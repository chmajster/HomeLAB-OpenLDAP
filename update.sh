#!/usr/bin/env bash
set -Eeuo pipefail
umask 027
APP_DIR=/opt/homelab-openldap-manager
ETC_DIR=/etc/homelab-openldap-manager
DATA_DIR=/var/lib/homelab-openldap-manager
STAMP="$(date -u +%Y%m%dT%H%M%SZ)"
ROLLBACK="/var/backups/homelab-openldap-manager/update-${STAMP}"
[[ ${EUID} -eq 0 ]] || { echo 'Run as root' >&2; exit 1; }
mkdir -p "$ROLLBACK"
cp -a "$ETC_DIR" "$ROLLBACK/etc"
cp -a "$DATA_DIR/app.db" "$ROLLBACK/app.db" 2>/dev/null || true
tar -C "$APP_DIR" --exclude=venv -czf "$ROLLBACK/app.tar.gz" .
rollback(){
  echo 'Update failed; rolling back' >&2
  systemctl stop homelab-openldap-manager || true
  rm -rf "$APP_DIR.rollback"
  mkdir -p "$APP_DIR.rollback"
  tar -C "$APP_DIR.rollback" -xzf "$ROLLBACK/app.tar.gz"
  find "$APP_DIR" -mindepth 1 -maxdepth 1 ! -name venv -exec rm -rf {} +
  cp -a "$APP_DIR.rollback"/. "$APP_DIR"/
  cp -a "$ROLLBACK/app.db" "$DATA_DIR/app.db" 2>/dev/null || true
  systemctl start homelab-openldap-manager || true
}
trap rollback ERR
if [[ -d "$APP_DIR/.git" ]]; then git -C "$APP_DIR" pull --ff-only; else echo 'Source installation is not a git checkout; run update.sh from a fresh release checkout.' >&2; exit 2; fi
"$APP_DIR/venv/bin/pip" install -r "$APP_DIR/requirements.txt"
set -a; . "$ETC_DIR/app.env"; set +a
PYTHONPATH="$APP_DIR" "$APP_DIR/venv/bin/alembic" -c "$APP_DIR/alembic.ini" upgrade head || PYTHONPATH="$APP_DIR" "$APP_DIR/venv/bin/python" -c 'from app.database import init_db; init_db()'
systemctl restart homelab-openldap-manager
sleep 2
curl --fail --silent "http://127.0.0.1:${WEB_PORT}/api/v1/health" >/dev/null
trap - ERR
echo 'Update completed successfully'
