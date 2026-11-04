/*
 * flipper_agent.ino  —  agente recon per ESP32-S2
 * ------------------------------------------------------------
 * Si collega al relay (sulla tua VM) via WebSocket sicuro e, SOLO su comando
 * che arriva dal sito, esegue funzioni di RICOGNIZIONE PASSIVA:
 *   - scan      : elenco access point vicini
 *   - select    : fissa un AP target (bssid + canale)
 *   - stations  : elenca i client (station) che dialogano col target
 *   - monitor   : conta il traffico sul canale del target per N secondi
 *   - stop       : annulla l'operazione in corso
 *
 * NON contiene deauth, beacon/probe flood, cattura handshake/PMKID, evil portal.
 * Quelle funzioni restano su Marauder, da usare solo in locale sulla board.
 *
 * Nota hardware: l'S2 ha una sola radio. Durante "stations"/"monitor" la board
 * entra in monitor mode e stacca l'uplink per la durata della finestra, poi si
 * riconnette e invia i risultati: per questo arrivano a raffiche di pochi sec.
 *
 * Librerie (Arduino IDE -> Gestore librerie):
 *   - "WebSockets" di Markus Sattler (arduinoWebSockets)
 * Board: "ESP32S2 Dev Module". Upload: tieni BOOT + tocca RST, scegli la porta.
 */

#include <WiFi.h>
#include <esp_wifi.h>
#include <WebSocketsClient.h>

// ======================= CONFIG — COMPILA QUESTI =======================
const char* WIFI_SSID    = "LA_TUA_RETE";
const char* WIFI_PASS    = "LA_TUA_PASSWORD_WIFI";

const char* RELAY_HOST   = "flipper.dxveblud.dev";  // dominio del relay
const uint16_t RELAY_PORT = 443;               // 443 = WSS dietro Caddy
const char* RELAY_PATH   = "/flipper/ws";      // path del WebSocket sul relay

// Token del dispositivo: identico qui e nel relay. Stringa lunga e casuale.
const char* DEVICE_TOKEN = "METTI_UN_DEVICE_TOKEN_LUNGO_E_CASUALE";

const uint32_t SNIFF_WINDOW_MS   = 6000;       // durata finestra monitor mode
const uint8_t  MAX_STATIONS      = 48;
// =======================================================================

WebSocketsClient ws;
String deviceMac;

// --- target selezionato ---
uint8_t targetBssid[6] = {0};
bool    hasTarget = false;
uint8_t targetChannel = 0;

// --- stato pendente (operazioni che richiedono monitor mode) ---
enum PendingOp { OP_NONE, OP_STATIONS, OP_MONITOR };
volatile PendingOp pendingOp = OP_NONE;
bool   sniffActive = false;
uint32_t sniffStart = 0;

// --- raccolta station (riempita dal callback in monitor mode) ---
struct Sta { uint8_t mac[6]; int8_t rssi; uint16_t pkts; };
Sta      staList[MAX_STATIONS];
uint8_t  staCount = 0;
volatile uint32_t pktTotal = 0;

String pendingSend = ""; // risultato da spedire quando il WS torna connesso

bool surveying = false;  // modalita site survey: RSSI della rete connessa in live
uint32_t lastSurvey = 0;

// ---------------- util ----------------
String macToStr(const uint8_t* m) {
  char b[18];
  snprintf(b, sizeof(b), "%02X:%02X:%02X:%02X:%02X:%02X", m[0],m[1],m[2],m[3],m[4],m[5]);
  return String(b);
}
bool macEq(const uint8_t* a, const uint8_t* b) { return memcmp(a,b,6)==0; }
bool isGroupAddr(const uint8_t* m) { return (m[0] & 0x01) != 0; } // multicast/broadcast
bool parseMac(const String& s, uint8_t* out) {
  int v[6];
  if (sscanf(s.c_str(), "%x:%x:%x:%x:%x:%x", &v[0],&v[1],&v[2],&v[3],&v[4],&v[5]) != 6) return false;
  for (int i=0;i<6;i++) out[i]=(uint8_t)v[i];
  return true;
}
String jsonEscape(const String& s) {
  String o; for (size_t i=0;i<s.length();i++){ char c=s[i];
    if(c=='"'||c=='\\'){o+='\\';o+=c;} else if(c=='\n')o+="\\n"; else if(c=='\r')o+="\\r"; else o+=c; }
  return o;
}
// estrattori JSON minimali (comandi semplici dal relay)
String jGetStr(const String& src, const char* key) {
  String pat = String("\"")+key+"\"";
  int k = src.indexOf(pat); if(k<0) return "";
  int c = src.indexOf(':', k); if(c<0) return "";
  int q1 = src.indexOf('"', c+1); if(q1<0) return "";
  int q2 = src.indexOf('"', q1+1); if(q2<0) return "";
  return src.substring(q1+1, q2);
}
long jGetInt(const String& src, const char* key, long def) {
  String pat = String("\"")+key+"\"";
  int k = src.indexOf(pat); if(k<0) return def;
  int c = src.indexOf(':', k); if(c<0) return def;
  int i=c+1; while(i<(int)src.length() && (src[i]==' ')) i++;
  int j=i; while(j<(int)src.length() && (isdigit(src[j])||src[j]=='-')) j++;
  if(j==i) return def;
  return src.substring(i,j).toInt();
}

const char* encType(wifi_auth_mode_t m){
  switch(m){
    case WIFI_AUTH_OPEN:return "open"; case WIFI_AUTH_WEP:return "wep";
    case WIFI_AUTH_WPA_PSK:return "wpa"; case WIFI_AUTH_WPA2_PSK:return "wpa2";
    case WIFI_AUTH_WPA_WPA2_PSK:return "wpa/wpa2"; case WIFI_AUTH_WPA3_PSK:return "wpa3";
    case WIFI_AUTH_WPA2_WPA3_PSK:return "wpa2/wpa3"; default:return "?";
  }
}

void wsSend(const String& s){ String t = s; ws.sendTXT(t); } // sendTXT vuole String& non-const

// ---------------- WiFi / relay ----------------
void ensureSta() {
  if (WiFi.status()==WL_CONNECTED) return;
  WiFi.mode(WIFI_STA);
  WiFi.begin(WIFI_SSID, WIFI_PASS);
  uint32_t t=millis();
  while (WiFi.status()!=WL_CONNECTED && millis()-t<20000) delay(250);
}

// ---------------- scan AP ----------------
void doScan() {
  wsSend("{\"type\":\"status\",\"state\":\"scanning\"}");
  int n = WiFi.scanNetworks(false, true); // sync, includi hidden
  String p = "{\"type\":\"aps\",\"count\":"+String(n<0?0:n)+",\"aps\":[";
  for (int i=0;i<n;i++){
    if(i) p+=",";
    p += "{\"idx\":"+String(i);
    p += ",\"ssid\":\""+jsonEscape(WiFi.SSID(i))+"\"";
    p += ",\"bssid\":\""+WiFi.BSSIDstr(i)+"\"";
    p += ",\"rssi\":"+String(WiFi.RSSI(i));
    p += ",\"ch\":"+String(WiFi.channel(i));
    p += ",\"enc\":\""+String(encType(WiFi.encryptionType(i)))+"\"}";
  }
  p += "]}";
  WiFi.scanDelete();
  wsSend(p);
}

// ---------------- callback monitor mode ----------------
void IRAM_ATTR sniffCb(void* buf, wifi_promiscuous_pkt_type_t type){
  const wifi_promiscuous_pkt_t* pkt = (wifi_promiscuous_pkt_t*)buf;
  const uint8_t* pl = pkt->payload;
  int8_t rssi = pkt->rx_ctrl.rssi;
  const uint8_t* a1 = pl+4;   // destinatario
  const uint8_t* a2 = pl+10;  // mittente
  const uint8_t* a3 = pl+16;  // bssid (nella maggior parte dei frame)

  pktTotal++;

  // ci interessano solo i frame legati al BSSID target
  bool rel = macEq(a1,targetBssid) || macEq(a2,targetBssid) || macEq(a3,targetBssid);
  if (!rel) return;

  // la "station" e' l'indirizzo coinvolto che NON e' l'AP e non e' broadcast
  const uint8_t* sta = nullptr;
  if (!macEq(a1,targetBssid) && !isGroupAddr(a1)) sta = a1;
  else if (!macEq(a2,targetBssid) && !isGroupAddr(a2)) sta = a2;
  if (!sta) return;

  for (uint8_t i=0;i<staCount;i++){
    if (macEq(staList[i].mac, sta)){ staList[i].pkts++; staList[i].rssi=rssi; return; }
  }
  if (staCount < MAX_STATIONS){
    memcpy(staList[staCount].mac, sta, 6);
    staList[staCount].rssi = rssi;
    staList[staCount].pkts = 1;
    staCount++;
  }
}

void startSniff(PendingOp op){
  if (!hasTarget || targetChannel==0){
    wsSend("{\"type\":\"error\",\"msg\":\"nessun AP selezionato\"}");
    return;
  }
  wsSend(op==OP_STATIONS
    ? "{\"type\":\"status\",\"state\":\"sniffing_stations\"}"
    : "{\"type\":\"status\",\"state\":\"monitoring\"}");
  delay(80); // lascia partire l'invio prima di staccare l'uplink

  staCount = 0; pktTotal = 0;
  WiFi.disconnect(false, false);
  esp_wifi_set_promiscuous(true);
  esp_wifi_set_promiscuous_rx_cb(&sniffCb);
  esp_wifi_set_channel(targetChannel, WIFI_SECOND_CHAN_NONE);
  sniffActive = true; sniffStart = millis(); pendingOp = op;
}

void finishSniff(){
  esp_wifi_set_promiscuous(false);
  sniffActive = false;
  PendingOp op = pendingOp; pendingOp = OP_NONE;
  ensureSta(); // ricollega: il WS si riaggancia da solo

  if (op==OP_STATIONS){
    String p = "{\"type\":\"stations\",\"bssid\":\""+macToStr(targetBssid)+"\",\"count\":"+String(staCount)+",\"stations\":[";
    for (uint8_t i=0;i<staCount;i++){
      if(i) p+=",";
      p += "{\"mac\":\""+macToStr(staList[i].mac)+"\",\"rssi\":"+String(staList[i].rssi)+",\"pkts\":"+String(staList[i].pkts)+"}";
    }
    p += "]}";
    // invia appena il WS torna su (gestito in loop con buffer)
    pendingSend = p;
  } else if (op==OP_MONITOR){
    pendingSend = "{\"type\":\"monitor\",\"bssid\":\""+macToStr(targetBssid)+"\",\"ch\":"+String(targetChannel)+",\"packets\":"+String(pktTotal)+",\"window_ms\":"+String(SNIFF_WINDOW_MS)+",\"stations_seen\":"+String(staCount)+"}";
  }
}

// ---------------- comandi ----------------
void handleCommand(const String& msg){
  String cmd = jGetStr(msg, "cmd");
  if (cmd=="scan"){ doScan(); }
  else if (cmd=="select"){
    String b = jGetStr(msg,"bssid");
    long ch = jGetInt(msg,"channel",0);
    uint8_t m[6];
    if (parseMac(b,m) && ch>0){
      memcpy(targetBssid,m,6); targetChannel=(uint8_t)ch; hasTarget=true;
      wsSend("{\"type\":\"selected\",\"bssid\":\""+b+"\",\"channel\":"+String(ch)+"}");
    } else {
      wsSend("{\"type\":\"error\",\"msg\":\"select non valido\"}");
    }
  }
  else if (cmd=="stations"){ startSniff(OP_STATIONS); }
  else if (cmd=="monitor"){ startSniff(OP_MONITOR); }
  else if (cmd=="survey"){
    surveying = true; lastSurvey = 0;                 // RSSI live della rete connessa
    wsSend("{\"type\":\"status\",\"state\":\"survey\"}");
  }
  else if (cmd=="stop"){
    surveying = false;
    if (sniffActive){ esp_wifi_set_promiscuous(false); sniffActive=false; pendingOp=OP_NONE; ensureSta(); }
    wsSend("{\"type\":\"status\",\"state\":\"idle\"}");
  }
  else {
    // qualsiasi altro comando (incl. eventuali attacchi) NON e' supportato dall'agente
    wsSend("{\"type\":\"error\",\"msg\":\"comando non consentito\"}");
  }
}

void onWsEvent(WStype_t type, uint8_t* payload, size_t len){
  switch(type){
    case WStype_CONNECTED:
      wsSend(String("{\"role\":\"agent\",\"token\":\"")+DEVICE_TOKEN+"\",\"device\":\""+deviceMac+"\"}");
      wsSend("{\"type\":\"status\",\"state\":\"ready\",\"device\":\""+deviceMac+"\"}");
      if (pendingSend.length()){ wsSend(pendingSend); pendingSend=""; }
      break;
    case WStype_TEXT: {
      String msg = String((char*)payload).substring(0,len);
      handleCommand(msg);
      break;
    }
    default: break;
  }
}

void setup(){
  Serial.begin(115200);
  delay(300);
  WiFi.mode(WIFI_STA);
  deviceMac = WiFi.macAddress();
  ensureSta();
  ws.beginSSL(RELAY_HOST, RELAY_PORT, RELAY_PATH);
  ws.onEvent(onWsEvent);
  ws.setReconnectInterval(4000);
}

void loop(){
  if (sniffActive){
    if (millis()-sniffStart >= SNIFF_WINDOW_MS) finishSniff();
    return; // in monitor mode non si gira il WS
  }
  ws.loop();
  // se c'e' un risultato in attesa e siamo connessi, spediscilo
  if (pendingSend.length() && WiFi.status()==WL_CONNECTED && ws.isConnected()){
    wsSend(pendingSend); pendingSend="";
  }
  // site survey: RSSI live della rete connessa, ogni ~700ms, uplink attivo
  if (surveying && WiFi.status()==WL_CONNECTED && ws.isConnected() && millis()-lastSurvey >= 700){
    lastSurvey = millis();
    wsSend("{\"type\":\"rssi\",\"rssi\":" + String(WiFi.RSSI()) + ",\"ssid\":\"" + jsonEscape(WiFi.SSID()) + "\"}");
  }
}
