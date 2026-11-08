# Deploying to csc.decodificat.ro and cscweb.decodificat.ro

This guide puts the CSC demo on the decodificat VPS next to the existing decodificat stack. It covers the first deploy and the maintenance after it: updates, rollbacks, settings, logs and backups.

```
internet ──443──▶ Caddy  (decodificat stack, /opt/decodificat)
                    ├── csc.decodificat.ro    ──▶ csc-server:8080  ┐  compose project "csc-demo"
                    └── cscweb.decodificat.ro ──▶ csc-webapp:8000  ┘  /opt/csc-demo
                                                      │
              the web app calls https://csc.decodificat.ro ─┘  (back in through Caddy)
```

- Both containers join the existing Docker network `decodificat_default`. The decodificat Caddy already terminates HTTPS and reaches them by service name.
- No ports are published on the host. The decodificat compose files are not changed; only two site blocks are added to its Caddyfile.
- The two stacks are independent. Deploying one never restarts the other.

| File | Purpose |
|---|---|
| `Dockerfile` | Two images (`--target server`, `--target webapp`) on `python:3.14-slim`, running as a non-root user, with health checks |
| `compose.yaml` | The production stack: environment, the `csc_data` volume, log rotation, 512 MB memory limit per container |
| `.env.production.example` | Template for `/opt/csc-demo/.env` |
| `deploy/Caddyfile.csc` | Site blocks to append to `/opt/decodificat/Caddyfile` |
| `deploy/update.sh` | Delivers an update or a rollback |
| `constraints.txt` | Exact versions of every Python package in the images |

> **Read this first: accounts live in memory.** Each restart of `csc-server` deletes every account and every credential that users created: an update, a settings change, a crash, a reboot. Their key files stay in the volume but are no longer used. Only the files in the volume survive: the demo CA and alice's two credentials. Warn your users, or add a database before relying on the deployment.

---

## First deploy

### 0. Push the code

The VPS pulls from GitHub (`DevMilovici/CSC-Demo`). On your laptop, run the tests and push:

```bash
pip install -r requirements-dev.txt
python -m pytest -q tests && python tests/e2e_smoke.py
git add -A && git commit && git push origin main
```

### 1. DNS

In the Hostinger DNS zone for `decodificat.ro`, add two A records, the same way as for `analytics`:

| Type | Name | Points to |
|---|---|---|
| A | `csc` | VPS IP |
| A | `cscweb` | VPS IP |

Skip this if a wildcard `*` record already exists. Check from anywhere:

```bash
dig +short csc.decodificat.ro cscweb.decodificat.ro   # both print the VPS IP
```

### 2. Get the code on the VPS

```bash
ssh deploy@srv722182
sudo mkdir -p /opt/csc-demo && sudo chown deploy:deploy /opt/csc-demo
git clone https://github.com/DevMilovici/CSC-Demo.git /opt/csc-demo
```

**If the repository is private,** give the VPS a read-only deploy key and clone over SSH:

```bash
ssh-keygen -t ed25519 -f ~/.ssh/csc_demo_deploy -N "" -C "srv722182 csc-demo"
cat ~/.ssh/csc_demo_deploy.pub
# GitHub → CSC-Demo → Settings → Deploy keys → Add (leave "Allow write access" off)
cat >> ~/.ssh/config <<'EOF'
Host github-csc-demo
    HostName github.com
    IdentityFile ~/.ssh/csc_demo_deploy
    IdentitiesOnly yes
EOF
git clone git@github-csc-demo:DevMilovici/CSC-Demo.git /opt/csc-demo
```

### 3. Configure

```bash
cd /opt/csc-demo
cp .env.production.example .env && chmod 600 .env
openssl rand -base64 32          # paste as OAUTH_CLIENT_SECRET
nano .env
```

| Setting | What to put |
|---|---|
| `OAUTH_CLIENT_SECRET` | The random string from `openssl`. The server and the web app share it. |
| `SMTP_*` | Gmail: `smtp.gmail.com`, `587`, `starttls`, your address, and an **App Password** (not your normal password). `SMTP_FROM` should be the same address. |
| `DEMO_USER_EMAIL` | The inbox that receives alice's signing codes. |
| `DEMO_USER_PASSWORD` | alice's password. The repository default is public, so choose your own. |
| `WEBAPP_DEMO_LOGIN` | Leave empty: visitors create their own account. To make alice public instead, set `alice:<password>`; visitors can then make the server email `DEMO_USER_EMAIL`. |

Check the name of the network that the decodificat Caddy runs on:

```bash
docker network ls --filter name=decodificat
```

If the name isn't `decodificat_default`, set `PROXY_NETWORK=<name>` in `.env`.

### 4. Start the two containers

```bash
cd /opt/csc-demo
docker compose up -d --build --wait     # builds both images, waits until both are healthy
docker compose ps                       # csc-server and csc-webapp: "Up … (healthy)"
docker compose logs csc-server          # shows "Email delivery: smtp"
```

The first start creates the demo root CA and alice's credentials in the `csc-demo_csc_data` volume.

### 5. Route the domains in Caddy

Append the two site blocks to the decodificat Caddyfile, check it, and reload Caddy. A reload has no downtime for decodificat.ro.

```bash
cd /opt/decodificat
cp Caddyfile Caddyfile.bak.$(date +%F)
cat /opt/csc-demo/deploy/Caddyfile.csc >> Caddyfile
docker compose exec caddy caddy validate --config /etc/caddy/Caddyfile --adapter caddyfile
docker compose exec caddy caddy reload --config /etc/caddy/Caddyfile --adapter caddyfile
```

- **Appending with `>>` matters.** It keeps the same file, so the container's bind mount sees the change. If you edit the Caddyfile with an editor that replaces the file and Caddy keeps serving the old version, run `docker compose up -d --force-recreate caddy`. That interrupts decodificat.ro for a few seconds.
- **The VPS Caddyfile is a local edit of the decodificat repository.** It was already one, with the real domains. `git pull` in `/opt/decodificat` keeps working as long as the upstream Caddyfile doesn't change. If it ever does, the pull stops with a conflict on that file; keep your version.

Caddy obtains the Let's Encrypt certificates on the first request, which takes 10 to 30 seconds.

### 6. Check it works

```bash
curl -s -X POST https://csc.decodificat.ro/csc/v2/info -H 'Content-Type: application/json' -d '{}' | head -c 300; echo
curl -sI https://cscweb.decodificat.ro | head -1        # HTTP/2 200
```

Then in a browser:

1. Open https://cscweb.decodificat.ro. The CSC server field shows `https://csc.decodificat.ro` and is read-only.
2. Click **Create one**, sign up with a real address, and open the confirmation email.
3. **Connect** → **Request a new credential** → approve on the provider's page → sign the sample contract.

`docker compose logs csc-server` shows one `[email] … sent to …` line per email.

---

## Maintenance

All commands run on the VPS in `/opt/csc-demo` unless stated otherwise.

### Delivering an update

On the laptop: change, test, commit, push to `main`. On the VPS:

```bash
cd /opt/csc-demo && ./deploy/update.sh
```

The script:

1. Fast-forwards to `origin/main` and prints the new commits.
2. Rebuilds both images. `--pull` also picks up security patches of `python:3.14-slim`.
3. Recreates the containers and waits up to 120 s until both are healthy.
4. Deletes the old images.

Expect a few seconds of downtime, and remember that user accounts are reset.

The script reports success only after both containers pass their health check. If one doesn't, it stops with an error. Look at `docker compose logs`, then fix forward or roll back.

### Rolling back

```bash
git log --oneline -10                  # pick the last good commit
./deploy/update.sh <commit>            # deploys exactly that commit
./deploy/update.sh                     # later: back to the latest main
```

### Changing a setting

Edit `.env`, then run `docker compose up -d --wait`. Compose recreates only the containers whose settings changed; nothing is rebuilt. Changing `OAUTH_CLIENT_SECRET` recreates both containers.

`CSC_DOMAIN` and `WEBAPP_DOMAIN` must also match `deploy/Caddyfile.csc` and the DNS records. Change all three together.

### Logs and status

```bash
docker compose ps                                  # state and health
docker compose logs -f --tail 100 csc-server       # or csc-webapp
docker stats --no-stream csc-demo-csc-server-1 csc-demo-csc-webapp-1
```

Logs rotate automatically: 3 files of 10 MB per container. The server logs startup, every email it sends, and errors. It doesn't log individual requests; for those, see the Caddy logs in `/opt/decodificat`.

### Backups

The only data worth keeping is the `csc-demo_csc_data` volume: the demo CA's private key and alice's keys. If the CA is lost, a new one is generated, and PDFs signed earlier no longer validate in the web app.

```bash
# back up (writes csc-data-YYYY-MM-DD.tgz in the current directory; it contains private keys, so keep it private)
docker run --rm -v csc-demo_csc_data:/data:ro -v "$PWD":/backup alpine \
  tar czf /backup/csc-data-$(date +%F).tgz -C /data .

# restore
docker compose stop csc-server
docker run --rm -v csc-demo_csc_data:/data -v "$PWD":/backup alpine \
  sh -c 'rm -rf /data/* && tar xzf /backup/csc-data-YYYY-MM-DD.tgz -C /data && chown -R 10001 /data'
docker compose up -d --wait
```

Accounts aren't backed up because they only exist in memory.

### Updating Python dependencies

The images install the exact versions in `constraints.txt`, so rebuilding next month produces the same image as today. To upgrade, on the laptop:

```bash
# 1. resolve the newest versions on Linux, exactly as the image will
docker run --rm -v "$PWD/requirements.txt:/r.txt:ro" python:3.14-slim sh -c \
  'pip install -q --root-user-action=ignore -r /r.txt && pip freeze --exclude pip' > /tmp/new.txt
# 2. replace everything below the two comment lines of constraints.txt with /tmp/new.txt, then review the diff
git diff constraints.txt
# 3. test with the same versions, then commit, push and run ./deploy/update.sh on the VPS
pip install -r requirements-dev.txt -c constraints.txt
python -m pytest -q tests && python tests/e2e_smoke.py
```

Do this every few months, or when a security advisory affects `cryptography`, `pyhanko`, `starlette` or `fastapi`.

### Housekeeping

- **Build cache:** `docker builder prune -f` now and then frees build cache. `update.sh` already deletes old images.
- **Orphaned key files:** credentials that users created become orphans after a restart, about 3 KB each. Right after a restart you can delete them with:
  ```bash
  docker compose exec csc-server sh -c "find /data -name 'cred-*' ! -name 'cred-alice-*' -delete"
  ```
- **Stopping the decodificat stack:** `docker compose down` in `/opt/decodificat` warns that `decodificat_default` still has active endpoints, and leaves the network in place. That's expected. After the decodificat stack comes back up, CSC works again with no action needed.

### Removing the deployment

1. Delete the two site blocks from `/opt/decodificat/Caddyfile` and reload Caddy (step 5).
2. In `/opt/csc-demo`, run `docker compose down -v --rmi all`. This also deletes the volume with the keys.
3. Remove the `csc` and `cscweb` DNS records.

---

## Troubleshooting

| Symptom | Cause and fix |
|---|---|
| `network decodificat_default declared as external, but could not be found` | Set `PROXY_NETWORK` in `.env` to the name shown by `docker network ls`. |
| Browser shows a 502 | Caddy can't reach the container. Check `docker compose ps` here, and `docker network inspect decodificat_default \| grep csc` should list both containers. |
| Certificate error or no HTTPS | DNS doesn't point to the VPS yet, or port 80 is blocked. Check `docker compose logs caddy` in `/opt/decodificat`. |
| Web app: *Cannot reach the CSC server at https://csc.decodificat.ro* | The container can't reach the VPS's own public IP (no hairpin NAT). Test with `docker compose exec csc-webapp python -c "import urllib.request as u; print(u.urlopen('https://csc.decodificat.ro/docs').status)"`. Fix: in `compose.yaml`, under `csc-webapp`, add `extra_hosts: ["csc.decodificat.ro:host-gateway"]`, then run `docker compose up -d`. |
| Sign-up says it can't send the email (HTTP 503) | Check SMTP: `docker compose logs csc-server` shows the SMTP error. For Gmail, use an App Password. If the provider blocks port 587, try `SMTP_PORT=465` with `SMTP_SECURITY=ssl`. |
| Provider page: *The redirect_uri is not registered* | `WEBAPP_DOMAIN` doesn't match the address the web app is actually reached at. |
| A user's credentials disappeared | The server restarted; accounts live in memory. See the warning at the top. |
| `auth/login` returns 429 for one account | 10 wrong passwords for that account in 10 minutes. It unlocks automatically after 10 minutes, or immediately when the server restarts. |
