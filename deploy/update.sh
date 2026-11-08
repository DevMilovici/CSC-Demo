#!/usr/bin/env bash
# Deliver an update on the VPS: pull, rebuild, restart, wait until healthy, clean up.
#   cd /opt/csc-demo && ./deploy/update.sh            # latest main
#   cd /opt/csc-demo && ./deploy/update.sh <commit>   # a specific commit (e.g. to roll back)
# Accounts and credentials created by users live in memory and are lost on every restart.
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
docker compose up -d --wait --wait-timeout 120
docker image prune -f >/dev/null
docker compose ps
echo "Deployed $after"
