# Argus Cloudflare Tunnel & Remote Access Guide

This guide details how to securely expose the local Argus ANPR microservice (running on edge hardware like Raspberry Pi 5) to the Janus cloud application via **Cloudflare Tunnel (`cloudflared`)** and **Cloudflare Access Service Tokens**, with defense-in-depth anti-spoofing API key protection.

---

## Architecture Overview

```
+-------------------------------------------------------+
|  Janus (Next.js on Cloudflare Workers / V8 Edge)      |
|  - Injects CF-Access-Client-Id & Secret headers       |
|  - Injects X-API-Key header                           |
+---------------------------+---------------------------+
                            | HTTPS
                            v
+-------------------------------------------------------+
|  Cloudflare Edge Network                              |
|  - Validates Access Policy (Service Token)            |
|  - Encrypts & routes to Cloudflare Tunnel             |
+---------------------------+---------------------------+
                            | WireGuard / QUIC Tunnel
                            v
+-------------------------------------------------------+
|  Edge Hardware (Raspberry Pi 5 / Hermes)              |
|  - cloudflared daemon receives tunnel connection      |
|  - Routes to 127.0.0.1:8000 (Argus FastAPI)           |
|  - Argus validates X-API-Key (anti-spoofing check)    |
|  - Local Hermes loopback remains zero-overhead bypass |
+-------------------------------------------------------+
```

---

## 1. Prerequisites

1. Cloudflare account with a configured domain (e.g. `gluvok.com`).
2. Cloudflare Zero Trust team domain.
3. Edge device running Linux (Raspberry Pi 5 running Raspberry Pi OS or Ubuntu).

---

## 2. Configuration & Setup

### Automated Setup Script

Argus includes an automated tunnel provisioner in `scripts/cloudflared/setup_tunnel.sh`:

```bash
# Set your tunnel credentials
export TUNNEL_NAME="argus-weighbridge-1"
export TUNNEL_HOSTNAME="anpr-1.gluvok.com"

# Execute setup
chmod +x scripts/cloudflared/setup_tunnel.sh
./scripts/cloudflared/setup_tunnel.sh
```

### Manual Configuration (`config.yml`)

The template is provided at `scripts/cloudflared/config.yml.template`:

```yaml
tunnel: <TUNNEL_UUID>
credentials-file: /etc/cloudflared/<TUNNEL_UUID>.json

ingress:
  - hostname: anpr-1.gluvok.com
    service: http://127.0.0.1:8000
    originRequest:
      connectTimeout: 30s
      keepAliveTimeout: 90s
      noTLSVerify: true
  - service: http_status:404
```

> **Important:** The `connectTimeout: 30s` and `keepAliveTimeout: 90s` directives prevent transient Cloudflare 524 Gateway Timeout errors during high-load multi-crop inference.

---

## 3. Defense-in-Depth Authentication

Argus implements layered authentication to protect against spoofing:

1. **Outer Layer: Cloudflare Zero Trust Access**
   - Create a Service Token in Cloudflare Zero Trust: `Access` -> `Service Auth` -> `Create Service Token`.
   - Protect `anpr-1.gluvok.com` with an Access Policy requiring this Service Token.
   - Cloudflare edge verifies `CF-Access-Client-Id` and `CF-Access-Client-Secret`.

2. **Inner Layer: Argus Anti-Spoofing API Key**
   - Set `ARGUS_API_KEY` on the edge device in `/etc/environment` or systemd service environment:
     ```bash
     ARGUS_API_KEY="your-secure-64-character-token"
     ```
   - Argus checks incoming requests:
     - Requests originating via Cloudflare (indicated by `CF-Connecting-IP`, `CF-RAY`, or `X-Forwarded-For`) are strictly required to supply a valid `X-API-Key`.
     - Direct local socket connections from `127.0.0.1` without proxy headers (e.g. local camera loops from Hermes) bypass authentication for maximum speed (<75ms).

---

## 4. Systemd Service Configuration

Ensure `cloudflared` starts automatically on boot alongside Argus:

```ini
# /etc/systemd/system/cloudflared.service
[Unit]
Description=Cloudflare Tunnel for Argus ANPR
After=network-online.target argus.service
Wants=network-online.target

[Service]
Type=notify
ExecStart=/usr/local/bin/cloudflared --config /etc/cloudflared/config.yml tunnel run
Restart=on-failure
RestartSec=5s
LimitNOFILE=65536

[Install]
WantedBy=multi-user.target
```

Enable and start:
```bash
sudo systemctl daemon-reload
sudo systemctl enable --now cloudflared
```

---

## 5. End-to-End Verification

Verify the endpoint remotely from any workstation:

```bash
curl -X POST "https://anpr-1.gluvok.com/recognize" \
  -H "CF-Access-Client-Id: <CLIENT_ID>" \
  -H "CF-Access-Client-Secret: <CLIENT_SECRET>" \
  -H "X-API-Key: <ARGUS_API_KEY>" \
  -F "file=@tests/1.jpg"
```

Expected response (`200 OK`):
```json
{
  "results": [
    {
      "plate": "RJ09GA0165",
      "vehicle_box": [10, 10, 50, 50],
      "execution_time_ms": 31.42
    }
  ],
  "execution_time_ms": 31.42
}
```
