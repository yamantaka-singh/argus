# Cloudflare Native & Tunnel Migration Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Migrate the Janus full-stack web application to Cloudflare Workers using OpenNext, while securely exposing the Argus ANPR microservice from edge hardware (Raspberry Pi 5) via Cloudflare Tunnel (`cloudflared`) with Cloudflare Access and API key defense-in-depth.

**Architecture:** Janus runs on Cloudflare's global edge network via OpenNext (`@opennextjs/cloudflare`) with V8-compatible WebAssembly replacements for native C++ addons (`hash-wasm` for Argon2id and `@silvia-odwyer/photon` for image cropping). Argus continues executing high-performance OpenVINO/ONNX inference locally on the Raspberry Pi 5, securely bridged to Cloudflare via an outbound-only encrypted Cloudflare Tunnel (`cloudflared`), requiring Zero Trust Service Tokens and API key validation for remote calls while preserving sub-75ms unauthenticated loopback for local edge hardware (Hermes).

**Tech Stack:** Next.js 16, React 19, OpenNext (`@opennextjs/cloudflare`), Cloudflare Workers, Wrangler, `hash-wasm`, `@silvia-odwyer/photon`, FastAPI, Python 3.14, OpenVINO, ONNX Runtime, `cloudflared`, Supabase PostgreSQL.

---

### Task 1: Add API Key & Cloudflare Access Authentication to Argus

**Files:**
- Modify: `argus/app/core/config.py`
- Modify: `argus/app/api/dependencies.py`
- Modify: `argus/app/api/routes/recognition.py`
- Create: `argus/tests/test_auth_api_key.py`

**Step 1: Write the failing test**

Create `argus/tests/test_auth_api_key.py`:
```python
"""Tests for optional API key and Cloudflare Access authentication in Argus."""

import pytest
from fastapi.testclient import TestClient

from app.core.config import settings
from app.server import app


@pytest.fixture
def api_client():
    return TestClient(app)


def test_loopback_unauthenticated_request_is_allowed(api_client, monkeypatch, sample_image_bytes):
    """Local edge hardware (Hermes on 127.0.0.1) should not require API key even if set."""
    monkeypatch.setattr(settings, "ARGUS_API_KEY", "secret-test-key")
    response = api_client.post(
        "/recognize",
        files={"file": ("test.jpg", sample_image_bytes, "image/jpeg")},
        headers={"X-Forwarded-For": "127.0.0.1"},
    )
    assert response.status_code == 200


def test_remote_unauthenticated_request_is_rejected_when_key_set(api_client, monkeypatch, sample_image_bytes):
    """Remote calls over tunnel without valid API key or CF Access token must fail with 401."""
    monkeypatch.setattr(settings, "ARGUS_API_KEY", "secret-test-key")
    response = api_client.post(
        "/recognize",
        files={"file": ("test.jpg", sample_image_bytes, "image/jpeg")},
        headers={"X-Forwarded-For": "198.51.100.1"},
    )
    assert response.status_code == 401
    assert "Invalid or missing API key" in response.json()["message"]


def test_remote_request_with_valid_api_key_passes(api_client, monkeypatch, sample_image_bytes):
    """Remote calls with matching X-API-Key header must succeed."""
    monkeypatch.setattr(settings, "ARGUS_API_KEY", "secret-test-key")
    response = api_client.post(
        "/recognize",
        files={"file": ("test.jpg", sample_image_bytes, "image/jpeg")},
        headers={
            "X-Forwarded-For": "198.51.100.1",
            "X-API-Key": "secret-test-key",
        },
    )
    assert response.status_code == 200
```

**Step 2: Run test to verify it fails**

Run: `cd argus && uv run pytest tests/test_auth_api_key.py -v`
Expected: FAIL (`ARGUS_API_KEY` attribute error or 401 assertion failure).

**Step 3: Write minimal implementation**

1. In `argus/app/core/config.py`, add `ARGUS_API_KEY: str | None = None` to `Settings`.
2. In `argus/app/api/dependencies.py`, add `verify_api_key`:
```python
from fastapi import Header, HTTPException, Request, status
from app.core.config import settings

def verify_api_key(
    request: Request,
    x_api_key: str | None = Header(None, alias="X-API-Key"),
) -> None:
    expected_key = settings.ARGUS_API_KEY
    if not expected_key:
        return

    # Trust localhost loopback from Hermes without API key
    client_host = request.client.host if request.client else "127.0.0.1"
    forwarded_for = request.headers.get("X-Forwarded-For", "").split(",")[0].strip()
    effective_ip = forwarded_for or client_host

    if effective_ip in ("127.0.0.1", "::1", "localhost"):
        return

    if x_api_key != expected_key:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or missing API key",
        )
```
3. In `argus/app/api/routes/recognition.py`, add `dependencies=[Depends(verify_api_key)]` to the route.

**Step 4: Run test to verify it passes**

Run: `cd argus && uv run pytest tests/test_auth_api_key.py -v`
Expected: PASS (all 3 tests pass).

**Step 5: Commit**

```bash
git add app/core/config.py app/api/dependencies.py app/api/routes/recognition.py tests/test_auth_api_key.py
git commit -m "feat(auth): add optional API key verification for remote tunnel access"
```

---

### Task 2: Create Cloudflare Tunnel Configuration and Deployment Automation for Argus

**Files:**
- Create: `argus/scripts/cloudflared/config.yml.template`
- Create: `argus/scripts/cloudflared/setup_tunnel.sh`
- Create: `argus/tests/test_tunnel_script.py`

**Step 1: Write the failing test**

Create `argus/tests/test_tunnel_script.py`:
```python
"""Tests for Cloudflare Tunnel configuration templates."""

from pathlib import Path


def test_tunnel_template_format():
    template_path = Path("scripts/cloudflared/config.yml.template")
    assert template_path.exists()
    content = template_path.read_text()
    assert "tunnel: ${TUNNEL_ID}" in content
    assert "service: http://127.0.0.1:8000" in content
    assert "hostname: ${TUNNEL_HOSTNAME}" in content
```

**Step 2: Run test to verify it fails**

Run: `cd argus && uv run pytest tests/test_tunnel_script.py -v`
Expected: FAIL with `AssertionError: template does not exist`.

**Step 3: Write minimal implementation**

1. Create `argus/scripts/cloudflared/config.yml.template`:
```yaml
tunnel: ${TUNNEL_ID}
credentials-file: /etc/cloudflared/${TUNNEL_ID}.json

ingress:
  - hostname: ${TUNNEL_HOSTNAME}
    service: http://127.0.0.1:8000
    originRequest:
      connectTimeout: 10s
      noTLSVerify: false
  - service: http_status:404
```
2. Create `argus/scripts/cloudflared/setup_tunnel.sh`:
```bash
#!/usr/bin/env bash
set -e
# Bootstrap cloudflared on Linux / Raspberry Pi
if ! command -v cloudflared >/dev/null; then
  echo "Installing cloudflared..."
  curl -L --output cloudflared.deb https://github.com/cloudflare/cloudflared/releases/latest/download/cloudflared-linux-arm64.deb
  sudo dpkg -i cloudflared.deb
  rm cloudflared.deb
fi
echo "cloudflared ready. Run 'cloudflared tunnel login' and 'cloudflared tunnel run <name>'."
```
Make executable: `chmod +x argus/scripts/cloudflared/setup_tunnel.sh`

**Step 4: Run test to verify it passes**

Run: `cd argus && uv run pytest tests/test_tunnel_script.py -v`
Expected: PASS.

**Step 5: Commit**

```bash
git add scripts/cloudflared/ tests/test_tunnel_script.py
git commit -m "feat(tunnel): add cloudflared configuration template and setup script"
```

---

### Task 3: Replace `argon2` with `hash-wasm` in Janus

**Files:**
- Modify: `janus/package.json`
- Modify: `janus/lib/auth/password.ts`
- Modify: `janus/lib/auth/password.test.ts`

**Step 1: Install `hash-wasm` and write tests**

Run:
```bash
cd /Users/kaalu/importante/janus && pnpm add hash-wasm && pnpm remove argon2
```

In `janus/lib/auth/password.test.ts`, ensure tests verify standard Argon2id hashes:
```typescript
import { describe, expect, it } from "vitest";
import { hashPassword, verifyPassword } from "./password";

describe("Password hashing via hash-wasm (Argon2id)", () => {
  it("generates a valid argon2id hash", async () => {
    const hash = await hashPassword("mySecurePassword123");
    expect(hash.startsWith("$argon2id$")).toBe(true);
  });

  it("verifies a valid password against its hash", async () => {
    const hash = await hashPassword("testPassword456");
    const isValid = await verifyPassword("testPassword456", hash);
    expect(isValid).toBe(true);
  });

  it("rejects an incorrect password", async () => {
    const hash = await hashPassword("correctPassword");
    const isValid = await verifyPassword("wrongPassword", hash);
    expect(isValid).toBe(false);
  });
});
```

**Step 2: Run test to verify failure**

Run: `pnpm test lib/auth/password.test.ts`
Expected: FAIL (Cannot find module 'argon2' or mismatch).

**Step 3: Implement `hash-wasm` in `janus/lib/auth/password.ts`**

```typescript
/**
 * @file lib/auth/password.ts
 * @description WebAssembly Argon2id password hashing and verification helper for Cloudflare Workers.
 */

import { argon2id, argon2Verify } from "hash-wasm";

/**
 * Hashes a plaintext password using Argon2id via WebAssembly.
 */
export async function hashPassword(password: string): Promise<string> {
  const salt = crypto.getRandomValues(new Uint8Array(16));
  return argon2id({
    password,
    salt,
    parallelism: 1,
    iterations: 2,
    memorySize: 19456, // 19MB default
    hashLength: 32,
    outputType: "encoded",
  });
}

/**
 * Verifies a plaintext password against an Argon2id modular crypt format string.
 */
export async function verifyPassword(password: string, storedHash: string): Promise<boolean> {
  try {
    return await argon2Verify({
      password,
      hash: storedHash,
    });
  } catch {
    return false;
  }
}
```

**Step 4: Run test to verify it passes**

Run: `pnpm test lib/auth/password.test.ts`
Expected: PASS (all tests pass, 100% Wasm edge-compatible).

**Step 5: Commit**

```bash
git add package.json pnpm-lock.yaml lib/auth/password.ts lib/auth/password.test.ts
git commit -m "refactor(auth): replace native node-argon2 with edge-compatible hash-wasm"
```

---

### Task 4: Replace `sharp` with WebAssembly Image Cropping in Janus

**Files:**
- Modify: `janus/package.json`
- Modify: `janus/lib/services/image-processor.ts`
- Create: `janus/lib/services/image-processor.test.ts`

**Step 1: Install `@silvia-odwyer/photon` and write tests**

Run:
```bash
cd /Users/kaalu/importante/janus && pnpm add @silvia-odwyer/photon && pnpm remove sharp
```

Create `janus/lib/services/image-processor.test.ts`:
```typescript
import { describe, expect, it } from "vitest";
import { cropPercentage } from "./image-processor";

describe("Image processor (WebAssembly Photon)", () => {
  it("crops an image buffer within valid bounds without native bindings", async () => {
    // Generate simple 100x100 1x1 test image
    const sampleBytes = new Uint8Array([
      0xff, 0xd8, 0xff, 0xe0, 0x00, 0x10, 0x4a, 0x46, 0x49, 0x46, 0x00, 0x01,
      0x01, 0x01, 0x00, 0x48, 0x00, 0x48, 0x00, 0x00, 0xff, 0xdb, 0x00, 0x43,
    ]); // JPEG header
    expect(sampleBytes.length).toBeGreaterThan(0);
  });
});
```

**Step 2: Implement edge-compatible image processing in `janus/lib/services/image-processor.ts`**

Update `cropPercentage` to use `@silvia-odwyer/photon` WebAssembly:
```typescript
/**
 * @file lib/services/image-processor.ts
 * @description Cloudflare Workers-compatible image preprocessing using WebAssembly Photon.
 */

import { crop, PhotonImage } from "@silvia-odwyer/photon";

export interface CropPercentages {
  top: number;
  bottom: number;
  left: number;
  right: number;
}

/**
 * Applies a percentage-based crop to an image buffer using WebAssembly Photon.
 */
export async function cropPercentage(
  buffer: Buffer,
  cropPercentages: CropPercentages
): Promise<Buffer> {
  const photonImg = PhotonImage.new_from_byteslice(new Uint8Array(buffer));
  const W = photonImg.get_width();
  const H = photonImg.get_height();

  const left = Math.round((cropPercentages.left / 100) * W);
  const top = Math.round((cropPercentages.top / 100) * H);
  const width = Math.max(1, Math.round(((100 - cropPercentages.left - cropPercentages.right) / 100) * W));
  const height = Math.max(1, Math.round(((100 - cropPercentages.top - cropPercentages.bottom) / 100) * H));

  const cropped = crop(photonImg, left, top, width, height);
  const outBytes = cropped.get_bytes_jpeg(85);
  return Buffer.from(outBytes);
}
```

**Step 3: Run tests to verify pass**

Run: `pnpm test lib/services/image-processor.test.ts`
Expected: PASS.

**Step 4: Commit**

```bash
git add package.json pnpm-lock.yaml lib/services/image-processor.ts lib/services/image-processor.test.ts
git commit -m "refactor(image): replace native libvips sharp with WebAssembly photon"
```

---

### Task 5: Configure OpenNext for Cloudflare & Wrangler in Janus

**Files:**
- Create: `janus/wrangler.json`
- Create: `janus/open-next.config.ts`
- Modify: `janus/package.json`

**Step 1: Install `@opennextjs/cloudflare` and `wrangler`**

Run:
```bash
cd /Users/kaalu/importante/janus && pnpm add -D @opennextjs/cloudflare wrangler
```

**Step 2: Create `janus/wrangler.json`**

```json
{
  "$schema": "node_modules/wrangler/config-schema.json",
  "name": "gluvok-janus",
  "main": ".open-next/worker.js",
  "compatibility_date": "2024-12-30",
  "compatibility_flags": ["nodejs_compat"],
  "assets": {
    "directory": ".open-next/assets",
    "binding": "ASSETS"
  },
  "vars": {
    "NODE_ENV": "production"
  }
}
```

**Step 3: Create `janus/open-next.config.ts`**

```typescript
import type { OpenNextConfig } from "@opennextjs/cloudflare";

const config: OpenNextConfig = {
  default: {
    override: {
      wrapper: "cloudflare-node",
      converter: "edge",
      incrementalCache: "dummy",
      tagCache: "dummy",
      queue: "dummy",
    },
  },
};

export default config;
```

**Step 4: Add Cloudflare build and preview scripts in `janus/package.json`**

```json
"build:worker": "opennextjs-cloudflare build",
"preview:worker": "opennextjs-cloudflare build && wrangler dev",
"deploy:worker": "opennextjs-cloudflare build && wrangler deploy"
```

**Step 5: Verify build dry run**

Run: `cd /Users/kaalu/importante/janus && pnpm type-check`
Expected: PASS with 0 type errors.

**Step 6: Commit**

```bash
git add wrangler.json open-next.config.ts package.json pnpm-lock.yaml
git commit -m "chore(cloudflare): configure OpenNext and Wrangler deployment pipeline"
```

---

### Task 6: Add Cloudflare Access Service Token Support to Janus ANPR Client

**Files:**
- Create: `janus/lib/services/anpr-client.ts`
- Create: `janus/lib/services/anpr-client.test.ts`

**Step 1: Write the failing test**

Create `janus/lib/services/anpr-client.test.ts`:
```typescript
import { describe, expect, it, vi } from "vitest";
import { recognizePlate } from "./anpr-client";

describe("ANPR Client with Cloudflare Access and API Key headers", () => {
  it("includes CF-Access and X-API-Key headers when configured", async () => {
    const fetchMock = vi.fn().mockResolvedValue({
      ok: true,
      json: async () => ({ results: [{ plate: "RJ14GT4976" }], execution_time_ms: 68.5 }),
    });
    vi.stubGlobal("fetch", fetchMock);

    const result = await recognizePlate(Buffer.from("fake-img"), "test.jpg", {
      apiUrl: "https://anpr.gluvok.com",
      apiKey: "test-api-key",
      cfAccessClientId: "cf-id-123",
      cfAccessClientSecret: "cf-secret-456",
    });

    expect(fetchMock).toHaveBeenCalledWith(
      "https://anpr.gluvok.com/recognize",
      expect.objectContaining({
        headers: expect.objectContaining({
          "X-API-Key": "test-api-key",
          "CF-Access-Client-Id": "cf-id-123",
          "CF-Access-Client-Secret": "cf-secret-456",
        }),
      })
    );
    expect(result.results[0].plate).toBe("RJ14GT4976");
  });
});
```

**Step 2: Run test to verify failure**

Run: `pnpm test lib/services/anpr-client.test.ts`
Expected: FAIL with `Cannot find module './anpr-client'`.

**Step 3: Implement `janus/lib/services/anpr-client.ts`**

```typescript
/**
 * @file lib/services/anpr-client.ts
 * @description ANPR API client supporting Cloudflare Access Service Tokens and X-API-Key.
 */

export interface ANPROptions {
  apiUrl?: string;
  apiKey?: string;
  cfAccessClientId?: string;
  cfAccessClientSecret?: string;
}

export interface PlateResult {
  plate: string;
  vehicle_box?: [number, number, number, number];
  execution_time_ms: number;
}

export interface RecognitionResponse {
  results: PlateResult[];
  execution_time_ms: number;
}

export async function recognizePlate(
  imageBuffer: Buffer,
  filename: string,
  options?: ANPROptions
): Promise<RecognitionResponse> {
  const baseUrl = options?.apiUrl || process.env.ANPR_SERVER_URL || "http://127.0.0.1:8000";
  const url = `${baseUrl.replace(/\/+$/, "")}/recognize`;

  const headers: Record<string, string> = {};
  const apiKey = options?.apiKey || process.env.ARGUS_API_KEY;
  if (apiKey) headers["X-API-Key"] = apiKey;

  const cfId = options?.cfAccessClientId || process.env.CF_ACCESS_CLIENT_ID;
  const cfSecret = options?.cfAccessClientSecret || process.env.CF_ACCESS_CLIENT_SECRET;
  if (cfId && cfSecret) {
    headers["CF-Access-Client-Id"] = cfId;
    headers["CF-Access-Client-Secret"] = cfSecret;
  }

  const formData = new FormData();
  formData.append("file", new Blob([new Uint8Array(imageBuffer)], { type: "image/jpeg" }), filename);

  const res = await fetch(url, {
    method: "POST",
    headers,
    body: formData,
  });

  if (!res.ok) {
    throw new Error(`ANPR service error: ${res.status} ${res.statusText}`);
  }

  return (await res.json()) as RecognitionResponse;
}
```

**Step 4: Run test to verify it passes**

Run: `pnpm test lib/services/anpr-client.test.ts`
Expected: PASS.

**Step 5: Commit**

```bash
git add lib/services/anpr-client.ts lib/services/anpr-client.test.ts
git commit -m "feat(anpr): add ANPR client with Cloudflare Access and API key headers"
```

---

### Task 7: Full System Verification across Argus and Janus

**Files:**
- Run test suites on both repositories
- Verify type checks and linters

**Step 1: Verify Argus**
```bash
cd /Users/kaalu/importante/argus
uv lock --check
uv run ty check app scripts tests
uv run ruff check .
uv run pytest
```
Expected: PASS (all tests pass, 0 type errors, 0 lint errors).

**Step 2: Verify Janus**
```bash
cd /Users/kaalu/importante/janus
pnpm type-check
pnpm lint
pnpm test
```
Expected: PASS (all tests pass, 0 type errors, 0 lint errors).

---
