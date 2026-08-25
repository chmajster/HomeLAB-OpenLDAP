#!/usr/bin/env bash
set -Eeuo pipefail
KEEP_CONFIG=false; KEEP_DATABASE=false; KEEP_BACKUPS=false; PURGE=false
while [[ $# -gt 0 ]]; do case "$1" in --keep-config) KEEP_CONFIG=true;; --keep-database) KEEP_DATABASE=true;; --keep-backups) KEEP_BACKUPS=true;; --purge) PURGE=true;; *) echo "Unknown option: $1" >&2; exit 2;; esac; shift; done
[[ ${EUID} -eq 0 ]] || { echo 'Run as root' >&2; exit 1; }
systemctl disable --now homelab-openldap-manager 2>/dev/null || true
rm -f /etc/systemd/system/homelab-openldap-manager.service /etc/sudoers.d/homelab-openldap-backup /usr/local/libexec/homelab-openldap-backup
rm -f /etc/nginx/sites-enabled/homelab-openldap-manager.conf /etc/nginx/sites-available/homelab-openldap-manager.conf
systemctl daemon-reload
systemctl reload nginx 2>/dev/null || true
rm -rf /opt/homelab-openldap-manager
$KEEP_CONFIG || rm -rf /etc/homelab-openldap-manager
$KEEP_DATABASE || rm -rf /var/lib/homelab-openldap-manager
$KEEP_BACKUPS || rm -rf /var/backups/homelab-openldap-manager
rm -rf /var/log/homelab-openldap-manager
if $PURGE; then userdel homelab-ldap 2>/dev/null || true; fi
echo 'HomeLAB OpenLDAP Manager removed'
