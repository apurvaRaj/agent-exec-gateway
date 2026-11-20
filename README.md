# Agent Execution Gateway

A gateway that lets AI agents run code through an API that is **authenticated, audited and sandboxed**. Agents never get a shell or database credentials. They get a scoped API key and a narrow set of endpoints, and every call is logged.

**Status:** early. API-key authentication, scopes and audit logging are done. Code execution is not built yet (see Roadmap).

## Why

Giving an LLM agent direct access to a server or database is risky: a prompt injection or a bad plan can run anything. A gateway puts one controlled door in front of execution:

- **Who** is calling: every request carries an API key tied to a named agent.
- **What** they may do: scopes limit each key to specific actions.
- **What happened**: an append-only audit log records every attempt, allowed or not.
- **Where** it runs: execution will happen in an isolated sandbox with time, memory and network limits.

## Quick start

```bash
pip install -e ".[dev]"
pytest

# create a key (printed once)
agw-keys create --name notebook-agent --scopes exec:run exec:read --expires-days 90

# run the server
uvicorn gateway.app:create_app --factory --port 8000

curl -H "Authorization: Bearer agw_..." localhost:8000/v1/whoami
```

Set `GATEWAY_DB_PATH` to choose where keys are stored (default `gateway.db`).

## API

| Method | Path | Auth | Purpose |
| --- | --- | --- | --- |
| GET | `/health` | none | Liveness check |
| GET | `/v1/whoami` | any valid key | Shows the calling key's name, prefix, scopes and expiry |

## Key management

```bash
agw-keys create --name <agent> --scopes <scope...> [--expires-days N]
agw-keys list            # never shows secrets
agw-keys revoke <prefix>
```

Scopes: `exec:run` (run code), `exec:read` (read results), `admin` (implies all).

## Design decisions

**Key format: `agw_<prefix>_<secret>`.**
The 8-character prefix is stored in plain text. It is used to look a key up in one indexed query and to name the key in logs and admin tools, without exposing the secret. The `agw_` tag makes leaked keys easy to spot with secret scanners.

**Only a hash is stored.**
The database holds a SHA-256 hash of the key, never the key itself. A stolen database cannot be used to call the API. A slow password hash (bcrypt, argon2) is not used on purpose: the secret is 256 bits of randomness, so the hash cannot be brute-forced, and a slow hash would add latency to every request.

**Constant-time comparison.**
Hashes are compared with `hmac.compare_digest`, so response timing does not reveal how much of a guess was right.

**One error for every failure.**
Missing, malformed, unknown, wrong, revoked and expired keys all get the same `401` body. Clients cannot probe which keys exist. The real reason goes to the audit log for operators.

**401 vs 403.**
`401` means "we don't know who you are". `403` means "we know who you are, but this key lacks the scope".

**Audit log as JSON lines.**
Every authentication success, failure and scope denial is logged with timestamp, key prefix, path, client address and reason. The secret is never logged (a test enforces this). JSON lines can be shipped to any log store.

**Revocation and expiry.**
Keys can be revoked instantly and can carry an expiry date. `last_used_at` shows which keys are stale and safe to remove.

## Threat model (current scope)

| Threat | Mitigation |
| --- | --- |
| Database leak exposes keys | Only hashes stored |
| Key guessing | 256-bit secrets |
| Timing attacks on comparison | Constant-time compare |
| Probing for valid keys | Identical 401 for every failure |
| Leaked key keeps working | Revocation, expiry, audit trail with last use |
| Over-privileged agent | Per-key scopes |

Not yet covered: rate limiting of failed attempts, TLS termination (expected at the reverse proxy), key rotation without downtime.

## Roadmap

1. Authentication with API keys, scopes and audit log (done)
2. Execution endpoint: run Python in an isolated container with CPU, memory, time and network limits
3. Read-only data access for executed code
4. Rate limiting per key
5. Execution results and logs retrievable by run ID

## Development

```bash
pip install -e ".[dev]"
pytest -q
```

## License

MIT
