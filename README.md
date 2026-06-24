# apsentry

Evil Twin / Rogue AP detection and wireless threat monitor. apsentry scans the
Wi-Fi environment, compares it against a trusted baseline, and raises scored
alerts for evil twins, rogue access points, MAC spoofing, encryption
downgrades, beacon floods, and signal anomalies. It ships with a live web
dashboard and a terminal mode.

Built for defenders: it detects and explains these attacks against networks you
own or operate. It does not perform them.

## What it detects

| Signature | Severity | What triggers it |
|-----------|----------|------------------|
| `evil_twin` | up to critical | Same SSID on a second BSSID, weighted by encryption mismatch, vendor mismatch, randomized MAC, and stronger signal |
| `rogue_trusted_ssid` | high–critical | A trusted SSID broadcast by a BSSID not in the baseline (impersonation) |
| `bssid_downgrade` | high | A trusted BSSID now advertising open/weaker security (spoofed AP) |
| `randomized_mac` | low–medium | A named AP using a locally-administered (randomized/spoofed) MAC |
| `weak_crypto` | medium | WEP or other deprecated ciphers |
| `beacon_flood` | medium–high | Many open SSIDs with randomized MACs appearing at once |
| `signal_anomaly` | low | A known AP whose signal jumps sharply between scans |
| `new_ap` | info | An AP not yet in the baseline (inventory) |

## Data sources

apsentry autodetects a backend by platform:

- Windows: `netsh wlan show networks mode=bssid`
- Linux: `nmcli device wifi list`
- macOS: the legacy `airport -s` scan
- `demo`: a synthetic environment that injects evil twins, open clones, rogue
  MACs, and beacon floods, so the engine and dashboard work without hardware
- `replay`: feed a JSON file exported from `/api/export`

Force a source with `--source`.

## Usage

```
python apsentry.py                 # web dashboard at http://127.0.0.1:8787
python apsentry.py scan            # one scan + analysis in the terminal
python apsentry.py monitor -i 10   # continuous terminal monitor

python apsentry.py --source demo --scenario eviltwin scan
python apsentry.py --source windows serve --port 8080
python apsentry.py --source demo serve            # try the UI with no Wi-Fi card
```

Run as a module instead of the shim: `python -m apsentry ...`.

### Baseline

An evil twin is an AP impersonating a network you trust, so detection is
strongest once apsentry knows your environment.

- In the dashboard: "Trust current as baseline" snapshots the visible APs, or
  trust/untrust individual rows.
- The baseline is stored as JSON (`--baseline path`, default
  `apsentry-baseline.json`) and reloaded on start.

With a baseline in place, a familiar SSID appearing on an unknown BSSID, or a
trusted AP suddenly advertising open security, is flagged as impersonation.

## Dashboard

```
python apsentry.py --source demo serve
```

The dashboard shows an environment risk score, severity breakdown, a live threat
feed with full reasoning and recommendations, channel activity, and a searchable
AP inventory with signal, security, vendor, and trust state. It polls the JSON
API (`/api/state`, `/api/scan`, `/api/baseline/*`, `/api/export`) every few
seconds.

## Deauthentication monitoring (optional)

`apsentry/detection/deauth.py` adds monitor-mode detection of 802.11
deauth/disassoc floods, which are both a denial-of-service and the setup phase
of many evil-twin attacks. It needs `scapy` and a wireless interface in monitor
mode (Linux):

```
pip install scapy
```

The module is import-safe without scapy; the rest of the tool is standard
library only.

## Architecture

```
apsentry/
  collectors/   per-platform Wi-Fi scan backends + demo/replay
  detection/    signatures, the aggregation engine, optional deauth monitor
  baseline.py   trusted-AP store (JSON)
  scoring.py    environment risk aggregation
  state.py      rolling inventory, signal history, alert log
  monitor.py    scan -> analyze -> score -> record loop
  server.py     dashboard HTTP server + JSON API
  ui/           dashboard (HTML/CSS/JS, no framework)
  cli.py        serve / scan / monitor
```

## Authorization

Use apsentry only to monitor networks you own or are authorized to defend.
Passive scanning is generally low-risk, but wireless monitoring and any
monitor-mode capture must comply with local law and your organization's policy.

## License

MIT
