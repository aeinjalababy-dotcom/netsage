# NetSage — AI-Powered Network Traffic Analyzer

A polished, runnable local web prototype inspired by the supplied NetSage presentations. It demonstrates a traffic-monitoring dashboard, anomaly scoring, explainable event details, severity/risk prioritization, an event analyzer, and CSV export.

## Run on Windows
1. Install Python 3.10 or newer from https://www.python.org/downloads/ (select **Add Python to PATH** during setup).
2. Extract this ZIP to a normal writable folder.
3. Double-click `run_windows.bat`. It starts the app. No third-party Python packages are required.
4. Open **http://127.0.0.1:5000** in your browser.
5. Keep the terminal window open while using the dashboard. Press `Ctrl+C` in the terminal to stop the server.

If the batch file does not work, open PowerShell in this folder and run:
```powershell
python app.py
```
Then open http://127.0.0.1:5000.

## Run on Linux / macOS
```bash
./run_linux_mac.sh
```
Then open http://127.0.0.1:5000.

## Features
- Dashboard summary metrics, live-style traffic chart and severity distribution.
- Periodic demo traffic events while monitoring is active.
- Pause/resume monitoring and inject a demo anomaly.
- Search and filter events; open a record for risk score, reasons, threat context and suggested action.
- Event analyzer form for custom packet count, destination port and transfer size.
- Download event history as CSV.
- Responsive layout for desktop and smaller screens.

## Important implementation notes
- The server uses only Python standard-library modules, so no pip install or internet connection is needed after Python is installed.
- **This project runs in demo simulation mode by default.** The supplied presentations describe a proposed architecture and expected outputs, not a finished trained model or measured results. This implementation is a working educational prototype using transparent heuristic scoring and simulated traffic.
- It does **not** capture real network packets, call a live threat-intelligence API, or run SHAP/LIME. No real-world maliciousness should be inferred from demo IPs or scores.
- The web server binds to `127.0.0.1` so it is accessible only from the same computer by default.
- A live-capture or production deployment should be added and validated separately, with explicit authorization, suitable permissions, privacy safeguards, a real trained detector, and verified threat-intelligence sources.

## Project structure
```
netsage_project/
├── app.py
├── requirements.txt
├── run_windows.bat
├── run_linux_mac.sh
├── README.md
├── templates/
│   └── index.html
└── static/
    ├── app.js
    └── style.css
```
