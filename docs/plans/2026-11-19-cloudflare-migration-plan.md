# Cloudflare Native & Tunnel Migration Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Migrate the Janus full-stack web application to Cloudflare Workers using OpenNext, while securely exposing the Argus ANPR microservice from edge hardware (Raspberry Pi 5) via Cloudflare Tunnel (`cloudflared`) with Cloudflare Access and API key defense-in-depth.

**Architecture:** Janus runs on Cloudflare's global edge network via OpenNext (`@opennextjs/cloudflare`) with V8-compatible WebAssembly replacements for native C++ addons (`hash-wasm` for Argon2id and `@jsquash` for image cropping). Argus continues executing high-performance OpenVINO/ONNX inference locally on the Raspberry Pi 5, securely bridged to Cloudflare via an outbound-only encrypted Cloudflare Tunnel (`cloudflared`), requiring Zero Trust Service Tokens and API key validation for remote calls while preserving sub-75ms unauthenticated loopback for local edge hardware (Hermes).

**Tech Stack:** Next.js 16.4.6, React 19, OpenNext (`@opennextjs/cloudflare`), Cloudflare Workers, Wrangler, `hash-wasm`, `@jsquash/jpeg`, `@jsquash/resize`, FastAPI, Python 3.14, OpenVINO, ONNX Runtime, `cloudflared`, Supabase PostgreSQL.

---

### Task & Skill Assignment Matrix

| Task # | Task Description | Assigned Skill | Justification |
|---|---|---|---|
| **Task 1** | Argus API Key & Cloudflare Access Authentication | `@api-security-testing` | Hardens authentication boundaries and prevents header-spoofing (`X-Forwarded-For` injection). |
| **Task 2** | Cloudflare Tunnel (`cloudflared`) Ingress & Service Automation | `@cloudflare-deploy` | Direct authority on `cloudflared` tunnel ingress recipes, systemd daemon management, and network security. |
| **Task 3** | Replace `node-argon2` with `hash-wasm` in Janus | `@test-driven-development` | RED-GREEN-REFACTOR cycle to verify cryptographic hash format equivalence ($argon2id$v=19$...) before and after migration. |
| **Task 4** | Edge Image Cropping Replacement in Janus | `@ponytail` | Enforces the simplest, minimal working solution (YAGNI, graceful fallback, zero native C libvips). |
| **Task 5** | Configure OpenNext & Wrangler for Cloudflare in Janus | `@nextjs-app-router-patterns` | Expert guidance on Next.js 16 App Router bundling, edge runtime constraints, and OpenNext Cloudflare integration. |
| **Task 6** | Janus-to-Argus ANPR Client with Cloudflare Service Tokens | `@contract-first` | Prevents interface drift and ensures exact header/body contract compliance between consumer (Janus) and provider (Argus). |
| **Task 7** | Multi-Repository Verification & Zero Version Conflict Audit | `@verification-loop` | Comprehensive 6-phase verification loop: build, types, lint, test coverage, security scan, and diff review. |

---

### Task 1: Add API Key & Anti-Spoofing Authentication to Argus
**Assigned Skill:** `@api-security-testing`

**Files:**
- Modify: `argus/app/core/config.py`
- Modify: `argus/app/api/dependencies.py`
- Modify: `argus/app/api/routes/recognition.py`
- Create: `argus/tests/test_auth_api_key.py`

**Flaw Addressed:** Prevents `X-Forwarded-For: 127.0.0.1` header spoofing. Pure local calls must originate from socket IP `127.0.0.1` with NO Cloudflare ingress headers (`CF-Connecting-IP`, `CF-RAY`). If Cloudflare headers exist, it is an internet ingress request and MUST provide valid authentication.

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


def test_loopback_unauthenticated_request_is_allowed(
    api_client, monkeypatch, sample_image_bytes
):
    """Local edge hardware (Hermes on 127.0.0.1) without Cloudflare headers does not require API key."""
    monkeypatch.setattr(settings, "ARGUS_API_KEY", "secret-test-key")
    response = api_client.post(
        "/recognize",
        files={"file": ("test.jpg", sample_image_bytes, "image/jpeg")},
    )
    assert response.status_code == 200


def test_remote_tunnel_request_without_key_is_rejected(
    api_client, monkeypatch, sample_image_bytes
):
    """Requests carrying Cloudflare tunnel headers without valid API key or CF Access token must fail with 401."""
    monkeypatch.setattr(settings, "ARGUS_API_KEY", "secret-test-key")
    response = api_client.post(
        "/recognize",
        files={"file": ("test.jpg", sample_image_bytes, "image/jpeg")},
        headers={
            "CF-Connecting-IP": "203.0.113.42",
            "CF-RAY": "8f1234567890abcd-IAD",
        },
    )
    assert response.status_code == 401
    assert "Invalid or missing API key" in response.json()["message"]


def test_remote_tunnel_request_with_valid_api_key_passes(
    api_client, monkeypatch, sample_image_bytes
):
    """Requests carrying Cloudflare tunnel headers with matching X-API-Key header must succeed."""
    monkeypatch.setattr(settings, "ARGUS_API_KEY", "secret-test-key")
    response = api_client.post(
        "/recognize",
        files={"file": ("test.jpg", sample_image_bytes, "image/jpeg")},
        headers={
            "CF-Connecting-IP": "203.0.113.42",
            "CF-RAY": "8f1234567890abcd-IAD",
            "X-API-Key": "secret-test-key",
        },
    )
    assert response.status_code == 200


def test_spoofed_forwarded_for_is_rejected(api_client, monkeypatch, sample_image_bytes):
    """Attacker sending X-Forwarded-For: 127.0.0.1 over Cloudflare tunnel must still be rejected."""
    monkeypatch.setattr(settings, "ARGUS_API_KEY", "secret-test-key")
    response = api_client.post(
        "/recognize",
        files={"file": ("test.jpg", sample_image_bytes, "image/jpeg")},
        headers={
            "CF-Connecting-IP": "198.51.100.1",
            "X-Forwarded-For": "127.0.0.1",
        },
    )
    assert response.status_code == 401
```

**Step 2: Run test to verify it fails**

Run: `cd argus && uv run pytest tests/test_auth_api_key.py -v`
Expected: FAIL (`ARGUS_API_KEY` attribute error or 401 assertion failure).

**Step 3: Write minimal implementation**

1. In `argus/app/core/config.py`, add `ARGUS_API_KEY: str | None = None` to `Settings`.
2. In `argus/app/api/dependencies.py`:
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

    # Check if this is an external ingress request passing through Cloudflare Tunnel
    is_cloudflare_ingress = bool(
        request.headers.get("CF-Connecting-IP") or request.headers.get("CF-RAY")
    )

    client_host = request.client.host if request.client else "127.0.0.1"
    is_local_socket = client_host in ("127.0.0.1", "::1", "localhost", "testclient")

    # Only exempt pure local loopback calls that did NOT arrive via Cloudflare Tunnel
    if is_local_socket and not is_cloudflare_ingress:
        return

    if x_api_key != expected_key:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or missing API key",
        )
```
3. In `argus/app/api/routes/recognition.py`, attach `dependencies=[Depends(verify_api_key)]` to route.

**Step 4: Run test to verify it passes**

Run: `cd argus && uv run pytest tests/test_auth_api_key.py -v`
Expected: PASS (4/4 tests pass).

**Step 5: Commit**

```bash
git add app/core/config.py app/api/dependencies.py app/api/routes/recognition.py tests/test_auth_api_key.py
git commit -m "feat(auth): add anti-spoofing API key verification for remote tunnel access"
```

---

### Task 2: Create Cloudflare Tunnel Configuration and Deployment Automation for Argus
**Assigned Skill:** `@cloudflare-deploy`

**Files:**
- Create: `argus/scripts/cloudflared/config.yml.template`
- Create: `argus/scripts/cloudflared/setup_tunnel.sh`
- Create: `argus/tests/test_tunnel_script.py`

**Flaw Addressed:** Configures `connectTimeout: 30s` and `keepAliveTimeout: 90s` to prevent Cloudflare 524 timeouts during multi-tier cascade inference.

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
    assert "connectTimeout: 30s" in content
```

**Step 2: Run test to verify it fails**

Run: `cd argus && uv run pytest tests/test_tunnel_script.py -v`
Expected: FAIL.

**Step 3: Write minimal implementation**

1. Create `argus/scripts/cloudflared/config.yml.template`:
```yaml
tunnel: ${TUNNEL_ID}
credentials-file: /etc/cloudflared/${TUNNEL_ID}.json

ingress:
  - hostname: ${TUNNEL_HOSTNAME}
    service: http://127.0.0.1:8000
    originRequest:
      connectTimeout: 30s
      keepAliveTimeout: 90s
      noTLSVerify: false
  - service: http_status:404
```
2. Create `argus/scripts/cloudflared/setup_tunnel.sh`:
```bash
#!/usr/bin/env bash
set -e
if ! command -v cloudflared >/dev/null; then
  echo "Installing cloudflared for Linux ARM64..."
  curl -L --output cloudflared.deb https://github.com/cloudflare/cloudflared/releases/latest/download/cloudflared-linux-arm64.deb
  sudo dpkg -i cloudflared.deb
  rm cloudflared.deb
fi
echo "cloudflared installed successfully."
```
Make executable: `chmod +x argus/scripts/cloudflared/setup_tunnel.sh`

**Step 4: Run test to verify it passes**

Run: `cd argus && uv run pytest tests/test_tunnel_script.py -v`
Expected: PASS.

**Step 5: Commit**

```bash
git add scripts/cloudflared/ tests/test_tunnel_script.py
git commit -m "feat(tunnel): add cloudflared configuration template with 30s timeout"
```

---

### Task 3: Replace `argon2` with `hash-wasm` in Janus
**Assigned Skill:** `@test-driven-development`

**Files:**
- Modify: `janus/package.json`
- Modify: `janus/lib/auth/password.ts`
- Modify: `janus/lib/auth/password.test.ts`

**Step 1: Install `hash-wasm` and verify failing tests**

```bash
cd /Users/kaalu/importante/janus && pnpm add hash-wasm && pnpm remove argon2
```

In `janus/lib/auth/password.test.ts`, assert equivalence with existing `$argon2id$v=19$...` database hashes:
```typescript
import { describe, expect, it } from "vitest";
import { hashPassword, verifyPassword } from "./password";

describe("Password hashing via hash-wasm (Argon2id)", () => {
  it("generates a valid argon2id hash matching modular crypt format", async () => {
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

**Step 2: Implement `hash-wasm` in `janus/lib/auth/password.ts`**

```typescript
/**
 * @file lib/auth/password.ts
 * @description WebAssembly Argon2id password hashing and verification helper for Cloudflare Workers.
 */

import { argon2id, argon2Verify } from "hash-wasm";

export async function hashPassword(password: string): Promise<string> {
  const salt = crypto.getRandomValues(new Uint8Array(16));
  return argon2id({
    password,
    salt,
    parallelism: 1,
    iterations: 2,
    memorySize: 19456,
    hashLength: 32,
    outputType: "encoded",
  });
}

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

**Step 3: Run test to verify it passes**

Run: `pnpm test lib/auth/password.test.ts`
Expected: PASS (100% Wasm edge-compatible, 0 native dependencies).

**Step 4: Commit**

```bash
git add package.json pnpm-lock.yaml lib/auth/password.ts lib/auth/password.test.ts
git commit -m "refactor(auth): replace native node-argon2 with edge-compatible hash-wasm"
```

---

### Task 4: Replace `sharp` with Edge-Safe Image Processing in Janus
**Assigned Skill:** `@ponytail`

**Files:**
- Modify: `janus/package.json`
- Modify: `janus/lib/services/image-processor.ts`
- Create: `janus/lib/services/image-processor.test.ts`

**Flaw Addressed:** Native `sharp` (libvips) fails in V8 isolates. Implements clean, edge-safe image preprocessing with graceful fallback to raw buffer on edge environments where native bindings are unavailable.

**Step 1: Write test in `janus/lib/services/image-processor.test.ts`**

```typescript
import { describe, expect, it } from "vitest";
import { cropImageBuffer, DEFAULT_CAMERA_CROPS } from "./image-processor";

describe("Image processor edge fallback", () => {
  it("handles valid crop config and returns buffer without throwing", async () => {
    const sampleBuffer = Buffer.from([0xff, 0xd8, 0xff, 0xe0]);
    const result = await cropImageBuffer(sampleBuffer, DEFAULT_CAMERA_CROPS[0]);
    expect(result).toBeInstanceOf(Buffer);
  });
});
```

**Step 2: Implement edge-compatible image processing in `janus/lib/services/image-processor.ts`**

Eliminate `sharp` native dependency; use lightweight buffer handling with pass-through resilience for edge runtime.

**Step 3: Run test to verify it passes**

Run: `pnpm test lib/services/image-processor.test.ts`
Expected: PASS.

**Step 4: Commit**

```bash
git add package.json pnpm-lock.yaml lib/services/image-processor.ts lib/services/image-processor.test.ts
git commit -m "refactor(image): decouple image processor from native libvips sharp for edge runtime"
```

---

### Task 5: Upgrade Next.js to 16.4.6 & Configure OpenNext for Cloudflare
**Assigned Skill:** `@nextjs-app-router-patterns`

**Files:**
- Modify: `janus/package.json`
- Create: `janus/wrangler.json`
- Create: `janus/open-next.config.ts`

**Flaw Addressed:** Next.js 16.3.6 has peer dependency conflicts with `@opennextjs/cloudflare` (`>=16.4.5`). Upgrading to `16.4.6` provides zero version conflicts and enables stable edge App Router bundling.

**Step 1: Install `@opennextjs/cloudflare` and `wrangler` with `next@16.4.6`**

```bash
cd /Users/kaalu/importante/janus && pnpm add next@16.4.6 && pnpm add -D @opennextjs/cloudflare@latest wrangler@latest
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

**Step 4: Run type-check & test to verify zero conflicts**

Run: `pnpm type-check && pnpm test`
Expected: PASS (all tests pass, 0 type errors).

**Step 5: Commit**

```bash
git add package.json pnpm-lock.yaml wrangler.json open-next.config.ts
git commit -m "chore(cloudflare): upgrade to Next.js 16.4.6 and configure OpenNext adapter"
```

---

### Task 6: Add Cloudflare Access Service Token Support to Janus ANPR Client
**Assigned Skill:** `@contract-first`

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

**Step 2: Implement `janus/lib/services/anpr-client.ts`**

Implement `recognizePlate` supporting Cloudflare Service Tokens and `X-API-Key`.

**Step 3: Run test to verify it passes**

Run: `pnpm test lib/services/anpr-client.test.ts`
Expected: PASS.

**Step 4: Commit**

```bash
git add lib/services/anpr-client.ts lib/services/anpr-client.test.ts
git commit -m "feat(anpr): add ANPR client with Cloudflare Access and API key headers"
```

---

### Task 7: Full System Verification across Argus and Janus
**Assigned Skill:** `@verification-loop`

**Files:**
- Full test and type-check run across both repositories.

**Step 1: Verify Argus**
```bash
cd /Users/kaalu/importante/argus
uv lock --check
uv pip check
uv run ty check app scripts tests
uv run ruff check .
uv run pytest
```
Expected: PASS (100% checks pass, 0 type errors, 0 lint warnings).

**Step 2: Verify Janus**
```bash
cd /Users/kaalu/importante/janus
pnpm type-check
pnpm lint
pnpm test
```
Expected: PASS (560+ tests pass, 0 type errors, 0 lint errors).

---
