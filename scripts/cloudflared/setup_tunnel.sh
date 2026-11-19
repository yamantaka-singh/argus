#!/usr/bin/env bash
set -e

# Cloudflare Tunnel setup utility for Linux / Raspberry Pi
if ! command -v cloudflared >/dev/null; then
  echo "Installing cloudflared for Linux ARM64..."
  curl -L --output cloudflared.deb https://github.com/cloudflare/cloudflared/releases/latest/download/cloudflared-linux-arm64.deb
  sudo dpkg -i cloudflared.deb
  rm cloudflared.deb
fi

echo "cloudflared installed successfully."
echo "Next steps:"
echo "1. cloudflared tunnel login"
echo "2. cloudflared tunnel create <tunnel-name>"
echo "3. Copy credentials file to /etc/cloudflared/<tunnel-id>.json"
echo "4. Render config.yml from template and run: sudo cloudflared service install"
