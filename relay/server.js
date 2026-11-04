/*
 * server.js — Relay WebSocket per il pannello Flipper/ESP32-S2 (solo recon)
 * ------------------------------------------------------------------------
 * Ponte tra l'AGENTE (ESP32-S2, DEVICE_TOKEN) e il PANNELLO web (VIEWER_TOKEN).
 * I comandi dal browser all'agente passano da una WHITELIST (solo
 * scan/select/stations/monitor/stop): qualsiasi attacco e' scartato qui.
 * Stato solo in RAM (effimero). panel.html viene letto ad OGNI richiesta,
 * quindi un `git pull` aggiorna la pagina senza riavviare il servizio.
 *
 * Avvio:  DEVICE_TOKEN=... VIEWER_TOKEN=... PORT=8787 node server.js
 */

import http from 'node:http';
import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';
import { fileURLToPath } from 'node:url';
import { WebSocketServer } from 'ws';

const __dirname = path.dirname(fileURLToPath(import.meta.url));

const PORT          = parseInt(process.env.PORT || '8787', 10);
const DEVICE_TOKEN  = process.env.DEVICE_TOKEN  || '';
const VIEWER_TOKEN  = process.env.VIEWER_TOKEN  || '';
const PANEL_KEY     = process.env.PANEL_KEY     || '';   // chiave d'accesso al pannello (sul tag NFC)
const BASE_PATH     = process.env.BASE_PATH || '/flipper';
const WS_PATH       = BASE_PATH + '/ws';
const PAGE_FILE     = path.join(__dirname, 'panel.html');
const COOKIE_NAME   = 'fr_key';

if (!DEVICE_TOKEN || !VIEWER_TOKEN) {
  console.error('ERRORE: imposta DEVICE_TOKEN e VIEWER_TOKEN come variabili d\'ambiente.');
  process.exit(1);
}
if (!PANEL_KEY) {
  console.error('ERRORE: imposta PANEL_KEY (la chiave d\'accesso sul tag NFC). Generane una: openssl rand -hex 32');
  process.exit(1);
}

// confronto a tempo costante (evita timing attack sulla chiave)
function keyOk(given) {
  if (typeof given !== 'string' || given.length !== PANEL_KEY.length) return false;
  try { return crypto.timingSafeEqual(Buffer.from(given), Buffer.from(PANEL_KEY)); }
  catch { return false; }
}
function getCookie(req, name) {
  const h = req.headers.cookie || '';
  for (const part of h.split(';')) {
    const i = part.indexOf('=');
    if (i > -1 && part.slice(0, i).trim() === name) return decodeURIComponent(part.slice(i + 1).trim());
  }
  return null;
}

const ALLOWED_CMDS = new Set(['scan', 'select', 'stations', 'monitor', 'survey', 'stop']);
const snapshot = { status: null, aps: null, selected: null, stations: null, monitor: null };

// --- OUI vendor lookup (offline, registro IEEE) ---
let OUI = {};
try { OUI = JSON.parse(fs.readFileSync(path.join(__dirname, 'oui.json'), 'utf8')); console.log('OUI caricati:', Object.keys(OUI).length); }
catch { console.warn('oui.json non trovato: produttore non disponibile'); }
function vendorOf(mac) {
  if (!mac || mac.length < 8) return null;
  if (parseInt(mac.slice(0, 2), 16) & 0x02) return 'casuale';   // MAC randomizzato (privacy)
  return OUI[mac.slice(0, 8).replace(/:/g, '').toUpperCase()] || null;
}

let agentSocket = null;
const uiSockets = new Set();

function broadcastToUI(obj) {
  const msg = JSON.stringify(obj);
  for (const s of uiSockets) { try { s.send(msg); } catch {} }
}

// ---------------- HTTP: serve il pannello (letto ad ogni richiesta) ----------------
const server = http.createServer((req, res) => {
  const [url, qs] = (req.url || '').split('?');
  if (req.method === 'GET' && (url === BASE_PATH || url === BASE_PATH + '/')) {
    const keyInUrl = new URLSearchParams(qs || '').get('k');

    // 1) chiave nel link (dal tag NFC): valida -> posa un cookie e togli la chiave dall'URL
    if (keyInUrl != null) {
      if (!keyOk(keyInUrl)) { res.writeHead(403, { 'Content-Type': 'text/plain; charset=utf-8' }); res.end('Chiave non valida.'); return; }
      res.writeHead(302, {
        'Location': BASE_PATH,
        // cookie di sola trasmissione server->browser, 30 giorni, non leggibile da JS
        'Set-Cookie': `${COOKIE_NAME}=${encodeURIComponent(PANEL_KEY)}; Path=${BASE_PATH}; Max-Age=2592000; HttpOnly; Secure; SameSite=Lax`,
        'Cache-Control': 'no-store'
      });
      res.end();
      return;
    }

    // 2) niente chiave nell'URL: deve esserci il cookie valido (reload, ritorno nel browser)
    if (!keyOk(getCookie(req, COOKIE_NAME))) {
      res.writeHead(403, { 'Content-Type': 'text/html; charset=utf-8', 'Cache-Control': 'no-store' });
      res.end('<!doctype html><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">'
        + '<body style="font-family:-apple-system,sans-serif;background:#0a0d12;color:#e9eef4;display:grid;place-items:center;min-height:100vh;margin:0;text-align:center;padding:24px">'
        + '<div><div style="font-size:40px">🔒</div><h2>Accesso con chiave</h2>'
        + '<p style="color:#8294a8;max-width:320px">Avvicina il telefono al tag NFC del Flipper per aprire il pannello.</p></div>');
      return;
    }

    // 3) cookie ok: servi il pannello
    let html;
    try { html = fs.readFileSync(PAGE_FILE, 'utf8'); }
    catch { res.writeHead(500); res.end('panel.html mancante'); return; }
    html = html.replaceAll('%VIEWER_TOKEN%', VIEWER_TOKEN).replaceAll('%WS_PATH%', WS_PATH);
    res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8', 'Cache-Control': 'no-store' });
    res.end(html);
    return;
  }
  res.writeHead(404); res.end('not found');
});

// ---------------- WebSocket ----------------
const wss = new WebSocketServer({ noServer: true });

server.on('upgrade', (req, socket, head) => {
  const url = (req.url || '').split('?')[0];
  if (url !== WS_PATH) { socket.destroy(); return; }
  wss.handleUpgrade(req, socket, head, (ws) => wss.emit('connection', ws, req));
});

wss.on('connection', (ws) => {
  ws.role = null;
  let authTimer = setTimeout(() => { if (!ws.role) ws.close(); }, 5000);

  ws.on('message', (data) => {
    let msg;
    try { msg = JSON.parse(data.toString()); } catch { return; }

    if (!ws.role) {
      if (msg.role === 'agent' && msg.token === DEVICE_TOKEN) {
        clearTimeout(authTimer);
        ws.role = 'agent';
        agentSocket = ws;
        broadcastToUI({ type: 'agent', state: 'online', device: msg.device || null });
      } else if (msg.role === 'ui' && msg.token === VIEWER_TOKEN) {
        clearTimeout(authTimer);
        ws.role = 'ui';
        uiSockets.add(ws);
        ws.send(JSON.stringify({ type: 'agent', state: agentSocket ? 'online' : 'offline' }));
        for (const k of Object.keys(snapshot)) if (snapshot[k]) ws.send(JSON.stringify(snapshot[k]));
      } else {
        ws.close();
      }
      return;
    }

    if (ws.role === 'ui') {
      const cmd = msg && msg.cmd;
      if (!ALLOWED_CMDS.has(cmd)) { ws.send(JSON.stringify({ type: 'error', msg: 'comando non consentito: ' + cmd })); return; }
      if (!agentSocket) { ws.send(JSON.stringify({ type: 'error', msg: 'agente offline' })); return; }
      try { agentSocket.send(JSON.stringify(msg)); } catch {}
    } else if (ws.role === 'agent') {
      // arricchisci con il produttore (dal MAC) prima di inoltrare
      if (msg.type === 'aps' && Array.isArray(msg.aps)) for (const a of msg.aps) a.vendor = vendorOf(a.bssid);
      if (msg.type === 'stations' && Array.isArray(msg.stations)) for (const s of msg.stations) s.vendor = vendorOf(s.mac);
      if (msg.type && snapshot.hasOwnProperty(msg.type)) snapshot[msg.type] = msg;
      if (msg.type === 'status') snapshot.status = msg;
      broadcastToUI(msg);
    }
  });

  ws.on('close', () => {
    clearTimeout(authTimer);
    if (ws.role === 'ui') uiSockets.delete(ws);
    if (ws.role === 'agent' && agentSocket === ws) {
      agentSocket = null;
      for (const k of Object.keys(snapshot)) snapshot[k] = null;
      broadcastToUI({ type: 'agent', state: 'offline' });
    }
  });
});

server.listen(PORT, '127.0.0.1', () => {
  console.log(`flipper-relay in ascolto su 127.0.0.1:${PORT}`);
  console.log(`pannello: ${BASE_PATH}   websocket: ${WS_PATH}`);
});
