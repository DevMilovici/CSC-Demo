#!/usr/bin/env bash
# Deliver an update on the VPS: pull, rebuild, restart, wait until healthy, clean up.
#   cd /opt/csc-demo && ./deploy/update.sh            # latest main
#   cd /opt/csc-demo && ./deploy/update.sh <commit>   # a specific commit (e.g. to roll back)
# Before deploying it backs up the database and keys (kept in the volume, newest 10), so a rollback
# across a database schema change can restore the data as it was. See DEPLOY.md.
set -euo pipefail
cd "$(dirname "$0")/.."

[ -f .env ] || { echo "Missing .env (copy .env.production.example)"; exit 1; }

before=$(git rev-parse --short HEAD)
git fetch --quiet origin
if [ $# -ge 1 ]; then
  git checkout --quiet "$1"
else
  git checkout --quiet main
  git merge --ff-only --quiet origin/main
fi
after=$(git rev-parse --short HEAD)
echo "Deploying $before -> $after"
git log --oneline "$before..$after" 2>/dev/null | sed 's/^/  /' || true

docker compose build --pull
if docker compose ps --status running --services | grep -qx csc-server; then
  docker compose exec -T csc-server python server/admin.py backup
fi
docker compose up -d --wait --wait-timeout 120
docker image prune -f >/dev/null
docker compose ps
echo "Deployed $after"
