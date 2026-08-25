# Contributing

1. Create a feature branch from `main`.
2. Never commit `.env`, LDAP credentials, private keys or database files.
3. Run `ruff check .`, `pytest` and `bandit -r app`.
4. Keep LDAP operations in `app/ldap/`; API routes must call services.
5. Add tests for escaping, permissions and failure paths when changing LDAP code.
6. Open a pull request describing behavior, security impact and test evidence.
