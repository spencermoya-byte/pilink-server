# PiLink Server

The Raspberry Pi server for [PiLink](https://github.com/spencermoya-byte),
an iOS app that monitors and controls Raspberry Pi devices over a direct
TCP connection — no cloud relay.

**This repository is generated.** It mirrors the `pi-server/` directory of
the main PiLink repository at each release. Open issues and pull requests
against the main repository; changes made here are overwritten on the next
release.

## What the app installs

The PiLink app fetches these over SSH during device setup:

| File | Purpose |
|---|---|
| `pilink-server.py` | The TCP server the app talks to |
| `pilink-agent.py` | Self-healing agent that keeps the server alive |
| `requirements.txt` | Python dependencies |

## Manual install

```bash
mkdir -p ~/.pilink && cd ~/.pilink
curl -fsSLO https://raw.githubusercontent.com/spencermoya-byte/pilink-server/main/pilink-server.py
curl -fsSLO https://raw.githubusercontent.com/spencermoya-byte/pilink-server/main/pilink-agent.py
curl -fsSLO https://raw.githubusercontent.com/spencermoya-byte/pilink-server/main/requirements.txt
python3 -m venv venv && ./venv/bin/pip install -r requirements.txt
```

---
Published from release `manual`.
