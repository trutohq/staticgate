StaticGate - Static IP Reverse Proxy

Overview

- Standalone Go server to proxy requests through a droplet with a static IP.
- Auth via token in `Truto-StaticGate-Token` header.
- Target URL is provided via `Truto-Target-URL` header.
- Health endpoint: `GET /up` returns `{ "status": "up" }` without auth.

Environment Variables

- `STATICGATE_API_KEY`: the Bearer token to accept.
- `PORT` (default `80`): server port.

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

- Removes hop-by-hop headers; forwards all headers except `Truto-*` prefixed headers.
- Logs requests in JSON with timing and status.
- Service runs on port 80 by default (requires root or CAP_NET_BIND_SERVICE capability).
- Environment file location: `/etc/staticgate/.env`
