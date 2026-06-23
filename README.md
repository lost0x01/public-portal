# Public Portal

A generic, brand-neutral internal operations portal for small teams. It provides a lightweight FastAPI/Jinja/SQLite web app for:

- authenticated internal dashboard
- request intake
- task tracking
- document library for shared files
- simple cost tracking
- publication/deliverable tracking
- JSON and CSV exports

This repository intentionally contains no organization-specific branding, private data, customer names, or live secrets.

## Quick start

```bash
uv sync --group dev
cp .env.example .env
uv run python app.py
```

Open http://127.0.0.1:8008 and sign in with the bootstrap admin configured in `.env`.

Default development credentials are intentionally generic and should be changed before any shared deployment.

## Configuration

Environment variables:

- `PORTAL_HOST` default `127.0.0.1`
- `PORTAL_PORT` default `8008`
- `PORTAL_SECRET_KEY` signed session secret; change for every deployment
- `PORTAL_ALLOWED_CIDRS` comma-separated app-layer allowlist
- `PORTAL_TRUST_X_FORWARDED_FOR` set to `true` only behind a trusted reverse proxy
- `PORTAL_ADMIN_USERNAME` bootstrap username
- `PORTAL_ADMIN_PASSWORD` bootstrap password
- `PORTAL_ADMIN_DISPLAY_NAME` bootstrap display name
- `PORTAL_DATA_DIR` storage directory, default `./data`
- `PORTAL_DOCUMENTS_DIR` document library directory, default `./data/documents`

## Security notes

This app is designed for private/internal use. App-layer CIDR allowlisting is defense in depth, not a replacement for a VPN, firewall, private network, SSO, or reverse-proxy access controls.

Before real use:

1. Change `PORTAL_SECRET_KEY`.
2. Change bootstrap admin credentials.
3. Restrict `PORTAL_ALLOWED_CIDRS` to your actual internal/VPN ranges.
4. Put the app behind network controls.
5. Back up `PORTAL_DATA_DIR` if the data matters.

## Development

Run tests:

```bash
uv run pytest -q
```

Run the app:

```bash
uv run python app.py
```

## License

MIT
