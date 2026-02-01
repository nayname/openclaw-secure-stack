# User Quick Start

Operations guide for deploying and running OpenClaw Secure Stack.

## What You Get After Install

Running `./install.sh` starts three containers:

| Container | Role | Port |
|-----------|------|------|
| **proxy** | Reverse proxy — authenticates requests, sanitizes prompts, forwards to OpenClaw | `${PROXY_PORT:-8080}` on the host |
| **openclaw** | Unmodified OpenClaw instance (internal only, not exposed) | 3000 (internal) |
| **egress-dns** | CoreDNS sidecar — only resolves allowlisted domains, everything else returns NXDOMAIN | 172.28.0.10 (internal) |

All containers run read-only, as non-root, with dropped capabilities.

## Your API Token

The installer generates a random token and stores it in `.env` as `OPENCLAW_TOKEN`. To retrieve it:

```bash
grep OPENCLAW_TOKEN .env
```

Include it in every request:

```bash
curl -X POST http://localhost:8080/v1/chat/completions \
  -H "Authorization: Bearer YOUR_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"model": "gpt-4o-mini", "messages": [{"role": "user", "content": "Hello"}]}'
```

## Common Operations

### Stop / Start / Restart

```bash
docker compose down          # stop all containers
docker compose up -d         # start in background
docker compose restart       # restart all
docker compose restart proxy # restart just the proxy
```

### View Logs

```bash
docker compose logs -f          # all containers, follow
docker compose logs -f proxy    # proxy only
docker compose logs openclaw    # openclaw output
```

## Configuration Changes

### Changing LLM Provider or API Key

Edit `.env` and set the appropriate key:

```bash
# For OpenAI
OPENAI_API_KEY=sk-...

# For Anthropic
ANTHROPIC_API_KEY=sk-ant-...
```

Then restart:

```bash
docker compose restart
```

### Allowing New External Domains

Edit `config/egress-allowlist.conf` (one domain per line), then re-run the installer to regenerate the DNS zone:

```bash
echo "api.newprovider.com" >> config/egress-allowlist.conf
./install.sh
```

### Changing the Proxy Port

Edit `.env`:

```bash
PROXY_PORT=9090
```

Then restart:

```bash
docker compose down && docker compose up -d
```

## Reading the Audit Log

The proxy writes security events as JSON Lines to the audit log inside the container. To view:

```bash
docker compose exec proxy cat /var/log/audit/audit.jsonl
```

Each line is a JSON object with fields: `timestamp`, `event_type`, `source_ip`, `action`, `result`, `risk_level`, and `details`.

Event types include:
- `auth_success` / `auth_failure` — authentication attempts
- `prompt_injection` — detected prompt injection patterns
- `skill_scan` / `skill_quarantine` / `skill_override` — scanner events

## What Blocked Requests Look Like

| Scenario | HTTP Status | Meaning |
|----------|-------------|---------|
| Missing or invalid token | 401 | Authentication failed |
| Prompt injection detected (reject rule) | 400 | Request blocked by sanitizer |
| External domain not on allowlist | DNS failure (NXDOMAIN) | Egress blocked by CoreDNS |

## Re-running the Installer

Running `./install.sh` again is safe. It will:
- Regenerate the DNS zone file from the current allowlist
- Preserve your existing `.env` (prompts before overwriting)
- Rebuild and restart containers

## Troubleshooting

1. **Health check fails**: Run `curl http://localhost:8080/health` — if it times out, check `docker compose ps` for container status.
2. **401 on every request**: Verify your token matches `OPENCLAW_TOKEN` in `.env`. The `Authorization` header must be `Bearer <token>`.
3. **LLM calls fail**: Check that the correct API key is set in `.env` and the provider domain is in `config/egress-allowlist.conf`.
4. **Container won't start**: Run `docker compose logs` to see error output. Common cause: port conflict on `PROXY_PORT`.
5. **Skills blocked unexpectedly**: Check scanner findings with `uv run python -m src.scanner.cli scan <skill-path>`. Review `config/scanner-rules.json` for rule definitions.
