# Flipper Recon

Pannello web per comandare una scheda **ESP32-S2** in ricognizione Wi-Fi
(scan AP, station, select, monitor) da `https://flipper.dxveblud.dev`, in tempo reale.

Solo **ricognizione passiva**. Le funzioni d'attacco di Marauder (deauth,
handshake/PMKID, evil portal, beacon/probe flood) **non** sono esposte sul sito,
per scelta: restano su Marauder, da usare in locale sulla board.

```
[ESP32-S2: firmware agente]  --WSS-->  [nginx + relay sulla VM]  <--WSS--  [browser: /flipper]
      scan/station/monitor              127.0.0.1:8787 (systemd)           pannello (login)
```

## Funzioni del pannello
- **Scansione reti** con produttore (OUI), analisi canali, filtro, auto-scan ed export CSV.
- **📡 Radar**: tocca una rete e premi *Radar* → segnale in tempo reale di quella rete,
  con tendenza 🔥 più caldo / 🧊 più freddo, min/media/max, grafico e bip opzionale
  (più vicino = bip più fitti). Senza rete selezionata misura la rete a cui è connessa la board.
  La board fa uno scan mirato su un solo canale ogni ~0,5 s: **l'uplink resta su**.
- **Station / Monitor** sull'AP selezionato (monitor mode, uplink staccato ~6 s).

## Struttura
```
firmware/flipper_agent.ino   firmware agente (secret da compilare prima del flash)
relay/server.js              relay WebSocket (whitelist comandi; legge panel.html ad ogni richiesta)
relay/panel.html             il PANNELLO (il "sito") — modifica qui per cambiare la UI
relay/package.json
deploy/nginx-flipper.conf    sito nginx per flipper.dxveblud.dev
deploy/flipper-relay.service unit systemd (token da mettere sulla VM)
```

## Aggiornare il sito = `git push`
Il relay legge `relay/panel.html` ad **ogni richiesta**, e la VM fa `git pull`
da sola ogni minuto. Quindi per cambiare la grafica/funzioni del pannello:

```bash
# modifica relay/panel.html, poi:
git add relay/panel.html
git commit -m "ritocco pannello"
git push
```

Entro ~1 minuto il sito è aggiornato, **senza riavviare niente**.
(Se invece modifichi `relay/server.js`, serve un riavvio: `sudo systemctl restart flipper-relay`.)

## Setup sulla VM (una volta sola)
```bash
# 1. clona
cd ~ && git clone <URL_REPO> flipper-recon
cd flipper-recon/relay && npm install

# 2. servizio (metti i TOKEN veri nel file prima di avviare)
sudo cp ../deploy/flipper-relay.service /etc/systemd/system/
sudo nano /etc/systemd/system/flipper-relay.service
sudo systemctl daemon-reload && sudo systemctl enable --now flipper-relay

# 3. nginx (cert + login: vedi commenti in deploy/nginx-flipper.conf)
sudo cp ../deploy/nginx-flipper.conf /etc/nginx/sites-available/flipper
sudo ln -sf /etc/nginx/sites-available/flipper /etc/nginx/sites-enabled/flipper
sudo nginx -t && sudo systemctl reload nginx

# 4. auto-pull ogni minuto (push-to-deploy)
( crontab -l 2>/dev/null; echo "* * * * * git -C /home/ubuntu/flipper-recon pull -q" ) | crontab -
```

## Firmware (board)
Board: **ESP32S2 Dev Module**, core **esp32 ≥ 2.0** (serve `scanNetworks` con filtro canale/BSSID per il radar). Libreria: **WebSockets** (Markus Sattler).
Prima del flash compila in cima a `firmware/flipper_agent.ino`:
`WIFI_SSID`, `WIFI_PASS`, `DEVICE_TOKEN` (= quello del relay). `RELAY_HOST` è già `flipper.dxveblud.dev`.
Flash: tieni **BOOT** + tocca **RST**, poi carica (USB nativo). Opzione **USB CDC On Boot = Enabled** per avere i log.

## Note
- La board deve restare alimentata e in copertura della rete Wi-Fi configurata.
- Station/Monitor: la radio singola dell'S2 stacca l'uplink per ~6s e poi riconnette → i risultati arrivano a raffiche.
- **Accesso al pannello: solo con CHIAVE (tag NFC).** Niente piu' utente/password.
  Si entra solo aprendo `https://flipper.dxveblud.dev/flipper?k=<CHIAVE>`; il relay
  controlla la chiave (confronto a tempo costante), posa un cookie di 30 giorni e
  pulisce l'URL. Senza chiave: pagina "Accesso con chiave" (403).
  - **Imposta la chiave** sulla VM (nel service, non in git):
    `openssl rand -hex 32` -> mettila in `Environment=PANEL_KEY=...` del unit, poi
    `sudo systemctl daemon-reload && sudo systemctl restart flipper-relay`.
  - **Scrivi il tag NFC col Flipper Zero**: apri 125 kHz/NFC -> *NFC -> Add Manually ->
    NDEF* (oppure *Write* su un tag NTAG215 vuoto) e salva un record **URL**:
    `https://flipper.dxveblud.dev/flipper?k=<LA_TUA_CHIAVE>`. Avvicina il tag: iOS
    (iPhone 15 Pro, lettura NFC in background) mostra la notifica e apre il pannello gia' sbloccato.
  - La chiave e' come una password: chi ha il link entra. Se la perdi, cambiane il valore
    nel service, riavvia e riscrivi il tag.
- I token e le password Wi-Fi **non** stanno nel repo.
