# Security Policy

## Reporting a vulnerability

Please do not open a public issue for security problems. Use GitHub's
[private vulnerability reporting](https://github.com/nlevenov/soc-alert-prioritizer/security/advisories/new)
instead. I aim to acknowledge reports within 72 hours.

## Threat model

The tool processes log content, and log content is attacker-controlled: an
attacker who can make a sensor log something can put arbitrary text into
signatures, user names, URLs and host names. The design treats every alert
field as untrusted input.

| Threat | Mitigation |
|--------|------------|
| Stored XSS through log fields | Jinja2 autoescaping, `escapeHtml` in the dashboard, explicit escaping in the HTML report, strict CSP (`script-src 'self'`, no inline handlers) |
| CSV / formula injection in exports | Cells starting with `= + - @` are prefixed with `'` |
| Chat injection (`<!channel>`, disguised links) | Slack/Mattermost markup is escaped in webhook messages |
| Malformed or oversized input | IPs and ports are validated, text fields are length-bounded and stripped of control characters, request bodies capped at 10 MB, future timestamps clamped |
| SQL injection | Bound parameters everywhere, fixed column lists, `LIKE` wildcards escaped |
| Unauthorized access | API key (constant-time compare) or HMAC-signed `HttpOnly`, `SameSite=Strict` session cookie; weak keys refused; lockout after 10 failures in 5 minutes |
| CSRF | `SameSite=Strict` plus an `Origin` check on every state-changing request |
| DNS rebinding against a local instance | Without an API key the app only answers to `localhost` Host headers |
| Exposure on the network | `serve` refuses non-loopback binds without an API key; Docker publishes on 127.0.0.1 |
| Malicious model file (pickle code execution) | Models are signed (HMAC-SHA256 with `SOCPRIO_MODEL_KEY`) and verified before loading |
| Secret leakage | Secrets only via environment variables; the webhook URL is never logged |
| Clickjacking, MIME sniffing | `X-Frame-Options: DENY`, `frame-ancestors 'none'`, `nosniff` |
| Container escape / lateral movement | Non-root user, read-only root filesystem, all capabilities dropped, `no-new-privileges` |
| Vulnerable dependencies | `pip-audit` and `bandit` in CI, Dependabot updates |

## Deployment checklist

- Set `SOCPRIO_API_KEY` (32+ random characters) and `SOCPRIO_MODEL_KEY`.
- Terminate TLS in a reverse proxy (nginx, Traefik, Caddy), run with
  `--behind-proxy` and set `allowed_hosts` to the public host name.
- Keep `config/` and `feeds/` read-only for the service account.
- Rotate the API key to invalidate every analyst session.
