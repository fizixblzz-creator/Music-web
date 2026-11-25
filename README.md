# Music Website (Render Web Service)

Serves the page and calls your VPS API. The API key stays on the server (never in the browser).

## Render settings
- Language: Node
- Build Command: `npm install`
- Start Command: `node server.js`
- Instance: Free

## Environment variables
| Key | Value |
|---|---|
| `API_URL` | VPS API address, e.g. `https://xxxx.trycloudflare.com` |
| `API_KEY` | Same key as in `~/music-api/.env` on the VPS |
| `SITE_PASSWORD` | Password to open the website (recommended) |
