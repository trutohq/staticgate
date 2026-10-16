StaticGate - Static IP Reverse Proxy

Overview

- Standalone Go server to proxy requests through a droplet with a static IP.
- Auth via token in `Truto-StaticGate-Token` header.
- Target URL is provided via `Truto-Target-URL` header.
- Health endpoint: `GET /up` returns `{ "status": "up" }` without auth.

Environment Variables

- `STATICGATE_API_KEY`: the Bearer token to accept.
- `PORT` (default `80`): server port.
- `STATICGATE_BLOCK_MODE` (default `log`): `log` allows every target and only logs a `would block target` line for dials the guard would refuse. `enforce` refuses them with `403 {"error":"target not allowed"}`.
- `STATICGATE_BLOCK_PRIVATE_NETWORKS` (default `false`): set to `true` to also block private/internal ranges (see below). Applies in both modes.

Target Guard

The guard checks the resolved IP at dial time, so it covers redirects and DNS rebinding. A startup log line (`target guard`) shows the active mode.

- Always blocked (in `enforce` mode): loopback (`127/8`, `::1`), link-local (`169.254/16` incl. cloud metadata `169.254.169.254`, `fe80::/10`), unspecified (`0.0.0.0`, `::`), `0.0.0.0/8`, and IPv4-mapped forms of these. There is no legitimate use of these through a public-egress proxy: loopback is the gate itself (it listens on `:80`), and link-local is only cloud metadata.
- Blocked only when `STATICGATE_BLOCK_PRIVATE_NETWORKS=true`: RFC1918 (`10/8`, `172.16/12`, `192.168/16`), ULA `fc00::/7`, CGNAT `100.64/10`, `192.0.0.0/24`, `198.18/15`, `240/4`, multicast, NAT64 `64:ff9b::/96`. Off by default, because callers may legitimately reach hosts on a private network (on-prem over VPN, split-horizon DNS, VPC).

Rollout

1. Deploy the new binary. With no new env vars it changes nothing for callers: mode is `log`, private ranges are not blocked, nothing is refused.
2. Watch what would be blocked: `sudo journalctl -u staticgate | grep "would block"`.
3. If only loopback/metadata hits appear (or none), add `STATICGATE_BLOCK_MODE=enforce` to `/etc/staticgate/.env` and `sudo systemctl restart staticgate`.
4. Optional: set `STATICGATE_BLOCK_PRIVATE_NETWORKS=true` only after the logs show no customer targets a private range.

Build & Run

```bash
go build -o staticgate
STATICGATE_API_KEY=your-secret-key ./staticgate
```

Test

```bash
# Health
curl http://localhost:80/up

# Proxy request (replace TOKEN and URL)
curl -i \
  -H "Truto-StaticGate-Token: TOKEN" \
  -H "Truto-Target-URL: https://api.github.com/users/octocat" \
  http://localhost:80
```

Deployment

Use the provided deploy script for easy deployment:

```bash
./deploy.sh root <server_ip>
```

Systemd Service Management

```bash
# Service control
sudo systemctl start staticgate
sudo systemctl stop staticgate
sudo systemctl restart staticgate
sudo systemctl status staticgate
sudo systemctl enable staticgate
sudo systemctl disable staticgate

# View logs
sudo journalctl -u staticgate -f                    # Follow logs in real-time
sudo journalctl -u staticgate --lines=50            # Show last 50 log entries
sudo journalctl -u staticgate --since="1 hour ago"  # Show logs from last hour

# Service file location
/etc/systemd/system/staticgate.service
```

Common Commands

```bash
# Check if service is running
sudo systemctl is-active staticgate

# View service configuration
sudo systemctl cat staticgate

# Reload service after config changes
sudo systemctl daemon-reload
sudo systemctl restart staticgate

# Check service logs for errors
sudo journalctl -u staticgate --priority=err

# View live logs (follow in real-time)
sudo journalctl -u staticgate -f

# Test the service locally
curl http://localhost/up

# Test with authentication
curl -H "Truto-StaticGate-Token: YOUR_TOKEN" \
     -H "Truto-Target-URL: https://httpbin.org/get" \
     http://localhost
```

Environment Setup

Create a `.env` file for deployment:

```bash
echo "STATICGATE_API_KEY=your-secret-key-here" > .env
```

Notes

- Uses the standard Go transport settings, including `HTTP_PROXY`/`HTTPS_PROXY`/`NO_PROXY` from the environment; the only addition is the dial guard.
- Removes hop-by-hop headers; forwards all headers except `Truto-*` prefixed headers.
- Target guard: see "Target Guard" above. When enforced, blocked targets get `403 {"error":"target not allowed"}`.
- Logs requests in JSON with timing and status.
- Service runs on port 80 by default (requires root or CAP_NET_BIND_SERVICE capability).
- Environment file location: `/etc/staticgate/.env`
