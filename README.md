# MELCloud Integration

Self‑hosted web app to view and control your Mitsubishi heat pump via the MELCloud service. This guide is written for beginners and focuses on getting you running quickly on your own machine or home server.

## Start Here (Fastest Way)

- Choose your setup below. Both let you pick the web port first, then start the app.

### Option A: Docker (simple and durable)

1) Install Docker and Docker Compose.
2) Download the project:
```
git clone https://github.com/simonwoollams/MELCloud_Integration.git
cd MELCloud_Integration
```
3) Pick a port (default 8000). To change it, edit `docker-compose.yml` and replace `8000:8000` with your port, for example `9000:8000`.
4) Start the app:
```
docker-compose up -d
```
5) Open the site:
```
http://localhost:8000   # or your chosen port
```

Your data (database, logs, backups) is stored in local folders so updates won’t lose anything.

### Option B: No Docker (simple script)

1) Install Python 3.8 or newer.
2) Download the project:
```
git clone https://github.com/simonwoollams/MELCloud_Integration.git
cd MELCloud_Integration
```
3) Choose a port. Open `start.py` and change the `PORT` value if you want something other than 8000.
4) Run the starter:
```
python start.py
```
5) Open the site:
```
http://localhost:8000   # or your chosen port
```

## First‑Time Setup In The App

- Create your admin account when prompted.
- Go to Settings and enter your MELCloud email and password so the app can read your devices.
- Optional: turn on background auto‑fetch so data updates automatically.

That’s it — you should now see device status, history and controls.

## Everyday Use

- Dashboard shows live status and quick actions.
- Schedules let you automate temperature or mode changes.
- Energy and History pages show past usage and summaries.


## Changing The Port Later

- Docker: edit `docker-compose.yml` and change the left side of `HOST:8000`, e.g. `9000:8000`, then run `docker-compose up -d` again.
- No Docker: edit `PORT` in `start.py` and rerun `python start.py`.

## Troubleshooting (Quick Fixes)

- Can’t open the site: make sure nothing else uses your chosen port, or pick another (e.g., 8080 or 9000).
- Blank/old data: open Settings and click Refresh, or enable Auto‑Fetch.
- Login issues: use the “Forgot password” flow if available, or delete the `instance/melcloud.db` file only if you’re ok starting fresh.
- Docker rebuild after updates:
```
docker-compose down
docker-compose up -d --build
```

## What You Get

- Real‑time monitoring: temperatures, modes, Wi‑Fi signal
- History and energy summaries
- Responsive, mobile‑friendly dashboard
- Schedules and manual controls (e.g., hot‑water boost)

## Where Things Live (for reference)

- App: `app.py` (no need to edit for basic use)
- Settings, dashboard, pages: under `templates/` and `static/`
- Data folders (Docker): see `docker-compose.yml` volumes (persist across updates)
- Local database (no‑Docker): `instance/melcloud.db`

## Safety Notes

- No default users — you create the first admin on first run.
- If exposing to the internet, run behind HTTPS (a reverse proxy like Nginx/Traefik) and set a strong `SECRET_KEY` environment variable.

## Need Help?

- Open a GitHub issue with what you tried and what happened.
- Include your platform (Windows/Mac/Linux), your chosen port, and whether you used Docker or the `start.py` option.

## License

MIT — see `LICENSE`.
