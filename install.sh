#!/usr/bin/env bash
set -Eeuo pipefail
umask 027

APP_NAME="homelab-openldap-manager"
APP_USER="homelab-ldap"
APP_DIR="/opt/${APP_NAME}"
ETC_DIR="/etc/${APP_NAME}"
DATA_DIR="/var/lib/${APP_NAME}"
LOG_DIR="/var/log/${APP_NAME}"
BACKUP_DIR="/var/backups/${APP_NAME}"
NON_INTERACTIVE=false
CONFIG_FILE=""
LISTEN_ADDRESS="0.0.0.0"
WEB_PORT="8080"
ADMIN_USER=""
ADMIN_PASSWORD=""
LDAP_URL=""
LDAP_BASE_DN=""
LDAP_BIND_DN=""
LDAP_BIND_PASSWORD=""
LDAP_STARTTLS="false"
LDAP_VERIFY_TLS="true"
USERS_BASE_DN=""
GROUPS_BASE_DN=""
CONFIGURE_NGINX=true

log(){ printf '[ImOpenLDAP] %s\n' "$*"; }
die(){ printf '[ImOpenLDAP] ERROR: %s\n' "$*" >&2; exit 1; }
need_root(){ [[ ${EUID} -eq 0 ]] || die "Run install.sh as root"; }

while [[ $# -gt 0 ]]; do
  case "$1" in
    --non-interactive) NON_INTERACTIVE=true; shift ;;
    --config) CONFIG_FILE="$2"; shift 2 ;;
    --listen-address) LISTEN_ADDRESS="$2"; shift 2 ;;
    --web-port) WEB_PORT="$2"; shift 2 ;;
    --admin-user) ADMIN_USER="$2"; shift 2 ;;
    --admin-password) ADMIN_PASSWORD="$2"; shift 2 ;;
    --ldap-url) LDAP_URL="$2"; shift 2 ;;
    --ldap-base-dn) LDAP_BASE_DN="$2"; shift 2 ;;
    --ldap-bind-dn) LDAP_BIND_DN="$2"; shift 2 ;;
    --ldap-bind-password) LDAP_BIND_PASSWORD="$2"; shift 2 ;;
    --ldap-starttls) LDAP_STARTTLS="$2"; shift 2 ;;
    --ldap-verify-tls) LDAP_VERIFY_TLS="$2"; shift 2 ;;
    --users-base-dn) USERS_BASE_DN="$2"; shift 2 ;;
    --groups-base-dn) GROUPS_BASE_DN="$2"; shift 2 ;;
    --no-nginx) CONFIGURE_NGINX=false; shift ;;
    -h|--help) sed -n '1,120p' "$0"; exit 0 ;;
    *) die "Unknown option: $1" ;;
  esac
done

need_root
[[ -f /etc/os-release ]] || die "Unsupported operating system"
. /etc/os-release
case "${ID}:${VERSION_ID}" in
  ubuntu:24.04|ubuntu:26.04|debian:12|debian:13) ;;
  *) die "Supported: Ubuntu 24.04/26.04 and Debian 12/13. Detected ${ID} ${VERSION_ID}" ;;
esac

if [[ -n "$CONFIG_FILE" ]]; then
  [[ -r "$CONFIG_FILE" ]] || die "Cannot read config: $CONFIG_FILE"
  eval "$(python3 - "$CONFIG_FILE" <<'PY'
import json, shlex, sys
p=json.load(open(sys.argv[1], encoding='utf-8'))
vals={
'LISTEN_ADDRESS':p.get('web',{}).get('listen_address','0.0.0.0'),
'WEB_PORT':str(p.get('web',{}).get('port',8080)),
'ADMIN_USER':p.get('admin',{}).get('username',''),
'ADMIN_PASSWORD':p.get('admin',{}).get('password',''),
'LDAP_URL':p.get('ldap',{}).get('url',''),
'LDAP_BASE_DN':p.get('ldap',{}).get('base_dn',''),
'LDAP_BIND_DN':p.get('ldap',{}).get('bind_dn',''),
'LDAP_BIND_PASSWORD':p.get('ldap',{}).get('bind_password',''),
'LDAP_STARTTLS':str(p.get('ldap',{}).get('starttls',False)).lower(),
'LDAP_VERIFY_TLS':str(p.get('ldap',{}).get('verify_tls',True)).lower(),
'USERS_BASE_DN':p.get('ldap',{}).get('users_base_dn',''),
'GROUPS_BASE_DN':p.get('ldap',{}).get('groups_base_dn',''),
}
for k,v in vals.items(): print(f'{k}={shlex.quote(v)}')
PY
)"
fi

[[ "$WEB_PORT" =~ ^[0-9]+$ ]] && (( WEB_PORT >= 1 && WEB_PORT <= 65535 )) || die "Invalid web port"

if [[ "$NON_INTERACTIVE" == true ]]; then
  [[ -n "$ADMIN_USER" && -n "$ADMIN_PASSWORD" && -n "$LDAP_URL" && -n "$LDAP_BASE_DN" && -n "$LDAP_BIND_DN" && -n "$LDAP_BIND_PASSWORD" ]] || die "Silent installation requires admin and LDAP parameters"
fi

export DEBIAN_FRONTEND=noninteractive
apt-get update
apt-get install -y python3 python3-venv python3-pip build-essential libldap2-dev libsasl2-dev ldap-utils ca-certificates curl sudo git
if [[ "$CONFIGURE_NGINX" == true ]]; then apt-get install -y nginx; fi

id "$APP_USER" >/dev/null 2>&1 || useradd --system --home "$APP_DIR" --shell /usr/sbin/nologin "$APP_USER"
install -d -o root -g "$APP_USER" -m 0750 "$APP_DIR" "$ETC_DIR"
install -d -o "$APP_USER" -g "$APP_USER" -m 0750 "$DATA_DIR" "$LOG_DIR" "$BACKUP_DIR"

log "Installing application files"
tar --exclude='venv' --exclude='.venv' --exclude='.env' -cf - . | tar -C "$APP_DIR" -xf -
python3 -m venv "$APP_DIR/venv"
"$APP_DIR/venv/bin/pip" install --upgrade pip wheel
"$APP_DIR/venv/bin/pip" install -r "$APP_DIR/requirements.txt"
chown -R root:"$APP_USER" "$APP_DIR"
chmod -R g=rX,o= "$APP_DIR"

SECRET_KEY="$(python3 - <<'PY'
import secrets; print(secrets.token_hex(32))
PY
)"
ENCRYPTION_KEY="$("$APP_DIR/venv/bin/python" - <<'PY'
from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())
PY
)"
cat > "$ETC_DIR/app.env" <<EOF
APP_ENV=production
WEB_LISTEN_ADDRESS=${LISTEN_ADDRESS}
WEB_PORT=${WEB_PORT}
DATABASE_URL=sqlite:///${DATA_DIR}/app.db
SECRET_KEY=${SECRET_KEY}
ENCRYPTION_KEY=${ENCRYPTION_KEY}
SESSION_HTTPS_ONLY=false
ENABLE_DOCS=false
LOG_LEVEL=INFO
EOF
chown root:"$APP_USER" "$ETC_DIR/app.env"
chmod 0640 "$ETC_DIR/app.env"

install -o root -g root -m 0755 "$APP_DIR/scripts/homelab-openldap-backup" /usr/local/libexec/homelab-openldap-backup
install -o root -g root -m 0440 "$APP_DIR/scripts/homelab-openldap-backup.sudoers" /etc/sudoers.d/homelab-openldap-backup
visudo -cf /etc/sudoers.d/homelab-openldap-backup >/dev/null
install -o root -g root -m 0644 "$APP_DIR/systemd/homelab-openldap-manager.service" /etc/systemd/system/homelab-openldap-manager.service

COMMON_ENV=(
  APP_ENV=production
  DATABASE_URL="sqlite:///${DATA_DIR}/app.db"
  SECRET_KEY="$SECRET_KEY"
  ENCRYPTION_KEY="$ENCRYPTION_KEY"
  PYTHONPATH="$APP_DIR"
)
env "${COMMON_ENV[@]}" "$APP_DIR/venv/bin/alembic" -c "$APP_DIR/alembic.ini" upgrade head

if [[ "$NON_INTERACTIVE" == true ]]; then
  set +x
  env "${COMMON_ENV[@]}" \
    ADMIN_USER="$ADMIN_USER" ADMIN_PASSWORD="$ADMIN_PASSWORD" LDAP_URL="$LDAP_URL" LDAP_BASE_DN="$LDAP_BASE_DN" LDAP_BIND_DN="$LDAP_BIND_DN" LDAP_BIND_PASSWORD="$LDAP_BIND_PASSWORD" \
    LDAP_STARTTLS="$LDAP_STARTTLS" LDAP_VERIFY_TLS="$LDAP_VERIFY_TLS" USERS_BASE_DN="$USERS_BASE_DN" GROUPS_BASE_DN="$GROUPS_BASE_DN" \
    "$APP_DIR/venv/bin/python" "$APP_DIR/scripts/bootstrap.py"
fi

systemctl daemon-reload
systemctl enable --now homelab-openldap-manager.service

if [[ "$CONFIGURE_NGINX" == true ]]; then
  sed "s#127.0.0.1:8080#127.0.0.1:${WEB_PORT}#g" "$APP_DIR/nginx/homelab-openldap-manager.conf" > /etc/nginx/sites-available/homelab-openldap-manager.conf
  ln -sfn /etc/nginx/sites-available/homelab-openldap-manager.conf /etc/nginx/sites-enabled/homelab-openldap-manager.conf
  nginx -t
  systemctl reload nginx
fi

sleep 2
curl --fail --silent "http://127.0.0.1:${WEB_PORT}/api/v1/health" >/dev/null || die "Application healthcheck failed"
log "Installation completed: http://${LISTEN_ADDRESS}:${WEB_PORT}"
