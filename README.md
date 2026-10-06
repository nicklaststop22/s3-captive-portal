# s3 Captive Portal

A custom **ESP32-S3 captive-portal firmware** built as an honest WiFi
security teaching/demo device. The portal pages are clearly labeled
**"Evil Portal"** and state up front that the connection is **UNSECURED** —
this is **not** a clone of any real brand or service, and it is intended for
learning, demos, and testing on networks and devices you own.

> ⚠️ **Use responsibly.** Only run this on your own hardware and networks, or
> where you have explicit permission. You are responsible for complying with
> local laws and regulations.

## What it does

- **Two selectable captive-portal login pages**, flipped live with physical
  **UP/DOWN** GPIO buttons.
- **Admin dashboard at `/admin`** (HTTP basic-style login via
  `ADMIN_USER` / `ADMIN_PASS`):
  - View up to 25 captured credential pairs, with one-click clear.
  - **Passive channel scanner** (listen-only) across channels 1 / 6 / 11.
  - **Passive probe-request sniffer** — shows which SSIDs nearby devices are
    hunting for (MAC → SSID). Modern phones randomize probe MACs, so expect
    some noise mixed with real hits.
- **Status LED indicators** for current portal page / state.

## What it deliberately does NOT do

No **deauther / jammer**. Deauth frames hit shared RF spectrum and can knock
*any* nearby device offline — the FCC treats this as illegal intentional
interference even on a network you own. It is **not included and not a
toggle-away TODO**. Everything here is **receive-only** (scanning, sniffing);
nothing in this firmware ever transmits a frame that isn't a normal AP /
portal response.

## Hardware

- **Board:** ESP32-S3 (developed against an Adafruit Qualia / ESP32-S3 target)
- 2.4 GHz WiFi (SoftAP + captive DNS)
- Two momentary push buttons (UP / DOWN) for live page switching
- Optional status LEDs

## Repository layout

```
src/evil_portal_custom.cpp   Main firmware (Arduino / ESP32 core)
data/index.html              Captive-portal page served from flash (LittleFS/SPIFFS)
```

## Building & flashing

This is an Arduino/ESP32-core sketch. In broad strokes:

1. Install the **ESP32 Arduino core** (or use PlatformIO with the `espressif32`
   platform).
2. Open / add `src/evil_portal_custom.cpp` to your sketch.
3. Review the config block near the top of the source and set:
   - `AP_SSID` — the WiFi network name this broadcasts
   - `ADMIN_USER` / `ADMIN_PASS` — admin dashboard login
   - `LED_PIN_A` / `LED_PIN_B` — status LED wiring
   - `portalHTML_A` / `portalHTML_B` — the two login page designs/copy
4. Upload the sketch, and upload the `data/` folder to the device filesystem
   (LittleFS/SPIFFS) if your build serves `index.html` from flash.

## License

[MIT](LICENSE)
