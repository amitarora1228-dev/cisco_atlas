# DartHawk

DartHawk is a local Flask web tool for analyzing Cisco DART ZIP bundles.

## Requirements

- Python 3.10+
- pip
- Internet access for first-time package install

Dependencies are listed in [requirements.txt](requirements.txt).

## Run on macOS

1. Open Terminal and go to the project folder:

```bash
cd /path/to/DartHawk
```

2. Create a virtual environment:

```bash
python3 -m venv .venv
```

3. Activate the virtual environment:

```bash
source .venv/bin/activate
```

4. Install dependencies:

```bash
python -m pip install -r requirements.txt
```

5. Run the tool:

```bash
python darthawk.py
```

6. The app opens in your browser automatically. If needed, open the URL shown in terminal.

## Run on Windows (PowerShell)

1. Open PowerShell and go to the project folder:

```powershell
cd C:\path\to\DartHawk
```

2. Create a virtual environment:

```powershell
py -m venv .venv
```

3. Activate the virtual environment:

```powershell
.\.venv\Scripts\Activate.ps1
```

4. Install dependencies:

```powershell
py -m pip install -r requirements.txt
```

5. Run the tool:

```powershell
py darthawk.py
```

6. The app opens in your browser automatically. If needed, open the URL shown in terminal.

## Optional startup environment variables

- `DARTHAWK_HOST` (default: `127.0.0.1`)
- `DARTHAWK_PORT` (preferred starting port, auto-fallback if busy)
- `DARTHAWK_OPEN_BROWSER` (`1` to open browser, `0` to disable)

Examples:

```bash
DARTHAWK_PORT=5050 python darthawk.py
```

```powershell
$env:DARTHAWK_PORT="5050"; py darthawk.py
```

## Deploy (Production)

This repo now includes deployment-ready files:

- `Procfile` for PaaS platforms (Render, Railway, Heroku-like)
- `Dockerfile` + `.dockerignore` for container deployment
- `gunicorn` in `requirements.txt`

### Option 1: PaaS (Render/Railway style)

1. Push this repo to GitHub.
2. Create a new Web Service from the repo.
3. Use these settings:

- Build command:

```bash
pip install -r requirements.txt
```

- Start command:

```bash
gunicorn --bind 0.0.0.0:$PORT --workers 2 --threads 4 --timeout 120 darthawk:app
```

### Option 2: Docker

Build and run locally:

```bash
docker build -t darthawk .
docker run --rm -p 5000:5000 darthawk
```

Then open `http://127.0.0.1:5000`.
