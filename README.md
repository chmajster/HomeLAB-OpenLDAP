# ImOpenLDAP

Nowoczesny panel administracyjny do zarządzania prawdziwym serwerem OpenLDAP w HomeLAB i małych/średnich środowiskach. Aplikacja nie zastępuje LDAP własną bazą danych: użytkownicy, grupy, OU i atrybuty są odczytywane oraz modyfikowane bezpośrednio przez `ldap3`.

## Status

Wersja: `0.1.0`

Główne komponenty:

- FastAPI + Uvicorn
- ldap3
- SQLAlchemy + Alembic
- SQLite domyślnie, PostgreSQL przez `DATABASE_URL`
- Jinja2 + Bootstrap 5
- systemd + nginx
- Docker Compose dla developmentu

## Architecture

```text
ImOpenLDAP/
├── app/
│   ├── ldap/
│   │   ├── connection.py
│   │   ├── services.py
│   │   └── backup.py
│   ├── api.py
│   ├── tools_api.py
│   ├── web.py
│   ├── models.py
│   ├── schemas.py
│   ├── security.py
│   ├── audit.py
│   └── main.py
├── templates/
├── static/
├── migrations/
├── scripts/
├── systemd/
├── nginx/
├── tests/
├── docs/
├── install.sh
├── update.sh
└── uninstall.sh
```

Endpointy FastAPI nie wykonują bezpośrednio operacji `ldap3`. Logika katalogowa znajduje się w warstwie `app/ldap/`.

## Requirements

Produkcja natywna:

- Ubuntu 24.04 / 26.04
- Debian 12 / 13
- Python 3
- systemd
- opcjonalnie nginx
- dostęp sieciowy do OpenLDAP
- konto bind z uprawnieniami wymaganymi przez wykonywane operacje

Obsługiwane połączenia LDAP:

- `ldap://host:389`
- LDAP + StartTLS
- `ldaps://host:636`
- walidacja CA włączona domyślnie w konfiguracji aplikacji

## Installation

```bash
git clone https://github.com/chmajster/ImOpenLDAP.git
cd ImOpenLDAP
sudo ./install.sh
```

Instalacja interaktywna uruchamia aplikację, a pierwsza konfiguracja odbywa się pod `/setup`.

Domyślnie aplikacja działa jako użytkownik systemowy:

```text
homelab-ldap
```

Nie działa jako root.

## Silent installation

```bash
sudo ./install.sh \
  --non-interactive \
  --listen-address 0.0.0.0 \
  --web-port 8080 \
  --admin-user admin \
  --admin-password 'ChangeThisToAStrongPassword' \
  --ldap-url ldap://10.0.0.20:389 \
  --ldap-base-dn dc=example,dc=local \
  --ldap-bind-dn cn=admin,dc=example,dc=local \
  --ldap-bind-password 'LDAPSecret' \
  --ldap-starttls false \
  --ldap-verify-tls true
```

Hasła przekazane instalatorowi nie są wypisywane na stdout.

### JSON configuration

`/root/configs/openldap.json`:

```json
{
  "web": {
    "listen_address": "0.0.0.0",
    "port": 8080
  },
  "admin": {
    "username": "admin",
    "password": "ChangeThisToAStrongPassword"
  },
  "ldap": {
    "url": "ldap://10.0.0.20:389",
    "base_dn": "dc=example,dc=local",
    "bind_dn": "cn=admin,dc=example,dc=local",
    "bind_password": "LDAPSecret",
    "users_base_dn": "ou=People,dc=example,dc=local",
    "groups_base_dn": "ou=Groups,dc=example,dc=local",
    "starttls": false,
    "verify_tls": true
  }
}
```

Uruchomienie:

```bash
sudo ./install.sh --non-interactive --config /root/configs/openldap.json
```

## Configuration

Konfiguracja runtime jest zapisywana w:

```text
/etc/homelab-openldap-manager/app.env
```

Plik ma ograniczone uprawnienia. Klucz szyfrujący jest przechowywany poza bazą SQL. Bind password zapisany w bazie jest szyfrowany przez Fernet.

Najważniejsze zmienne:

```text
DATABASE_URL=
SECRET_KEY=
ENCRYPTION_KEY=
WEB_LISTEN_ADDRESS=
WEB_PORT=
SESSION_HTTPS_ONLY=
ENABLE_DOCS=
UID_MIN=
UID_MAX=
GID_MIN=
GID_MAX=
```

## LDAP configuration

Nie ma twardego założenia `ou=People` ani `ou=Groups`. Można skonfigurować osobno:

```text
Base DN
Users Base DN
Groups Base DN
```

Projekt jest przygotowany pod wiele rekordów `LDAPServer`; UI 0.1.0 używa pierwszego aktywnego serwera.

## TLS configuration

`LDAPConnectionManager` obsługuje:

- LDAP
- LDAPS
- StartTLS
- walidację certyfikatu
- własny CA certificate
- timeout
- reconnect na poziomie kolejnych operacji
- clean disconnect

Wyłączenie walidacji TLS powinno być używane wyłącznie świadomie w środowisku testowym.

## UI

Dostępne sekcje obejmują:

- Dashboard
- LDAP Browser
- Users
- Groups
- Search
- Schema Browser
- Audit

Szczegóły użytkownika i grupy są osobnymi stronami, nie modalami.

## REST API

Bazowy prefix:

```text
/api/v1/
```

Podstawowe endpointy:

```text
GET    /api/v1/health
GET    /api/v1/version
GET    /api/v1/status
POST   /api/v1/ldap/test

GET    /api/v1/users
POST   /api/v1/users
GET    /api/v1/users/{username}
PUT    /api/v1/users/{username}
DELETE /api/v1/users/{username}
POST   /api/v1/users/{username}/password
POST   /api/v1/users/{username}/enable
POST   /api/v1/users/{username}/disable

GET    /api/v1/groups
POST   /api/v1/groups
GET    /api/v1/groups/{name}
PUT    /api/v1/groups/{name}
DELETE /api/v1/groups/{name}

GET    /api/v1/ous
POST   /api/v1/ous
POST   /api/v1/search
GET    /api/v1/schema
GET    /api/v1/audit

POST   /api/v1/ldif/preview
POST   /api/v1/ldif/import
GET    /api/v1/ldif/export

GET    /api/v1/backups
POST   /api/v1/backups
POST   /api/v1/backups/{filename}/validate
POST   /api/v1/backups/restore
DELETE /api/v1/backups/{filename}

GET    /api/v1/password-policy
GET    /api/v1/locked-accounts
POST   /api/v1/locked-accounts/unlock
GET    /api/v1/system
GET    /api/v1/logs/{kind}
```

## API tokens

Token ma prefix `hlldap_` i jest zwracany tylko podczas tworzenia. W bazie przechowywany jest wyłącznie SHA-256 tokenu.

Przykładowe permissions:

```text
ldap.read
ldap.users.read
ldap.users.write
ldap.groups.read
ldap.groups.write
ldap.schema.read
audit.read
```

Przykład:

```bash
curl -H 'Authorization: Bearer hlldap_...' \
  http://server:8080/api/v1/users
```

## Search

Zaawansowany endpoint wyszukiwania:

```bash
curl -X POST http://server:8080/api/v1/search \
  -H 'Authorization: Bearer hlldap_...' \
  -H 'Content-Type: application/json' \
  -d '{
    "base_dn": "dc=example,dc=local",
    "scope": "SUBTREE",
    "ldap_filter": "(&(objectClass=person)(uid=chris))",
    "attributes": ["uid", "cn", "mail"],
    "size_limit": 100,
    "time_limit": 10
  }'
```

Pola wyszukiwania generowane przez aplikację korzystają z LDAP filter escaping. Zaawansowany endpoint przyjmuje świadomie pełny filtr LDAP.

## LDIF

Obsługiwane operacje:

- preview/validation
- add
- modify
- delete
- modrdn/moddn
- export
- raport częściowego powodzenia

Import nie wykonuje operacji bez `confirm=true`.

## Backup

Backup lokalnego `slapd` realizowany jest przez ograniczony root-owned helper:

```text
/usr/local/libexec/homelab-openldap-backup
```

Helper przyjmuje wyłącznie wygenerowane nazwy plików i akcje:

```text
create
validate
restore
```

Nie używa `shell=True`.

Restore wymaga jawnego potwierdzenia:

```text
RESTORE <filename>
```

## Audit

Każda operacja zmieniająca katalog wykonywana przez API zapisuje m.in.:

```text
Operation ID
X-Request-ID
user
time
source IP
operation
DN
status
old/new value
```

Pola `password`, `userPassword`, `token`, `secret`, `bind_password` i `private_key` są redagowane jako `[REDACTED]`.

## Authentication and RBAC

Role panelu:

- Administrator
- Operator
- Read Only

Hasła panelu są hashowane Argon2id. Mutacje API wykonywane przez sesję webową wymagają `X-CSRF-Token`. Tokeny Bearer nie korzystają z cookie-session CSRF.

Login jest objęty limitem prób na adres źródłowy.

## Security

Wdrożone mechanizmy:

- Argon2id
- Fernet encryption for stored LDAP bind password
- API token hashing
- CSRF protection
- secure/HttpOnly/SameSite session cookie support
- login rate limiting
- CSP
- X-Frame-Options
- X-Content-Type-Options
- Referrer-Policy
- Permissions-Policy
- HSTS przy HTTPS-only sessions
- LDAP filter escaping
- RDN escaping
- brak `shell=True`
- ograniczony sudo helper
- Operation ID / Request ID
- redakcja sekretów w audycie
- systemd hardening

Dla produkcji ustaw `SESSION_HTTPS_ONLY=true` i terminuj HTTPS w nginx/reverse proxy.

## Healthcheck

```bash
curl http://127.0.0.1:8080/api/v1/health
```

Przykład:

```json
{
  "status": "healthy",
  "application": "ok",
  "database": "ok",
  "ldap": "ok"
}
```

Przy niedostępnym LDAP aplikacja zwraca `degraded`, a nie ukrywa problemu.

## OpenAPI

Development:

```text
/docs
/redoc
```

W production dokumentacja jest domyślnie wyłączona przez `ENABLE_DOCS=false`.

## Update

```bash
sudo ./update.sh
```

Proces obejmuje:

1. backup konfiguracji,
2. backup bazy,
3. backup bieżącego kodu,
4. aktualizację,
5. dependencies,
6. migrations,
7. restart,
8. healthcheck,
9. rollback przy błędzie.

## Uninstall

```bash
sudo ./uninstall.sh --keep-config --keep-database --keep-backups
```

Pełne czyszczenie:

```bash
sudo ./uninstall.sh --purge
```

## Development

```bash
docker compose up --build
```

OpenLDAP development:

```text
LDAP URL: ldap://openldap:389
Base DN: dc=example,dc=local
Bind DN: cn=admin,dc=example,dc=local
```

Dane w `docker-compose.yml` są wyłącznie development defaults i nie powinny być używane w produkcji.

## Testing

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
ruff check .
pytest --cov=app
bandit -r app -x tests -s B324
pip-audit -r requirements.txt
```

Testy są podzielone na:

```text
tests/unit/
tests/integration/
tests/security/
```

## CI

GitHub Actions:

```text
.github/workflows/lint.yml
.github/workflows/test.yml
.github/workflows/security.yml
```

## Troubleshooting

Status usługi:

```bash
systemctl status homelab-openldap-manager
```

Logi:

```bash
journalctl -u homelab-openldap-manager -n 200 --no-pager
```

Test LDAP bez panelu:

```bash
ldapsearch -x -H ldap://10.0.0.20:389 \
  -D 'cn=admin,dc=example,dc=local' \
  -W \
  -b 'dc=example,dc=local' \
  '(objectClass=*)' dn
```

W błędach API użyj `X-Request-ID` do korelacji z logami i wpisami audytu.
