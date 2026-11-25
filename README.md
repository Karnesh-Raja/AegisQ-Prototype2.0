# AegisQ Round 2 prototype

AegisQ has two ways to run:

- **GitHub Pages:** the root `index.html` is a self-contained, browser-only build with the discovery scanner, simplified CBOM-style inventory, dashboard charts, Mosca-style risk assessment, shared X/Y/Z simulator, PQC advisor, roadmap, reports, and the offline Aegis Guide.
- **Local Flask app:** `python app.py` runs the Flask version at `http://127.0.0.1:5000` and provides the server-assisted ZIP scanner and downloadable PDF.

Both versions use synthetic MediVault data. Neither performs enterprise-wide or binary scanning, and neither claims CycloneDX compliance. The Aegis Guide uses built-in explanations and navigation rules; it is not a general-purpose cloud AI.

## Publish the browser-only build on GitHub Pages

1. Create a repository on GitHub and upload the files in this project ZIP to the repository’s top level. Keep `index.html`, `.nojekyll`, and the `static` folder together.
2. In the repository, open **Settings → Pages**.
3. Under **Build and deployment**, choose **Deploy from a branch**, select `main` and `/(root)`, then save.
4. Wait for GitHub to publish the site. The Pages URL will appear on that Settings page.

The root `index.html` runs in the visitor’s browser, including its ZIP inspection and local guide. GitHub Pages does not run the Flask server or Python API routes, so the Flask-only PDF endpoint is available when running the local Flask version or deploying it to a Python-capable host. GitHub’s documentation confirms that Pages publishes static files and does not support Python server-side applications: [Creating a GitHub Pages site](https://docs.github.com/en/pages/getting-started-with-github-pages/creating-a-github-pages-site).

## Milestone 1 — Check Python

Open **PowerShell** (Windows Start menu → type PowerShell). Enter:

```powershell
python --version
```

Expected: `Python 3.10` or newer. If that command fails, install Python 3.12 from python.org and select **Add Python to PATH**, then reopen PowerShell. This workspace has a bundled Python 3.12, though it may not be available from your regular PowerShell.

## Milestone 2 — Install the app packages

In PowerShell, go to this project folder (replace the example path if yours differs):

```powershell
cd "$HOME\.codex\.chatgpt-projects\g-p-6b06fbc6f1d8819194e222b93a96ba26"
py -3 -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
pip install -r requirements.txt
```

Expected: Flask and ReportLab finish installing. If `py` is not recognized, install Python and enable its launcher. If PowerShell blocks activation, run `Set-ExecutionPolicy -Scope Process Bypass` in that same window, then activate again. If package download fails, check your internet connection and retry.

## Milestone 3 — Start AegisQ

Keep the same PowerShell window and enter:

```powershell
python app.py
```

Expected: `Running on http://127.0.0.1:5000`. Open that address in your browser. Use **Run MediVault demo scan** to populate the dashboard. The server listens only on your own laptop.

To stop it, return to PowerShell and press **Ctrl+C**.

## Milestone 4 — Try a ZIP scan

Select **Scan a ZIP** and choose a ZIP containing readable `.py`, `.js`, `.java`, `.yaml`, `.json`, `.toml`, `.ini`, `.xml`, `.txt`, `.conf`, or similar supported source/config files. The scanner limits uploads to 10 MB and 500 ZIP entries, skips unsupported file types, rejects unsafe paths, and never executes uploaded content. It reads matching text in memory; it does not extract files to disk.

## Milestone 5 — Explore and export

Open **Crypto Inventory** to review line-linked evidence. Open **Threat Simulator** and move the sliders to explore the scenario model. Open **PQC Advisor** for purpose-aware recommendations and the migration roadmap. Use **Download assessment** to save the current findings as a PDF.

Use the floating **Ask me** robot for local page help. Click a term or select page text, then open the helper to see an explanation. You can also type questions such as `What is TLS?`, `open the simulator`, or `run the demo scan`. It uses built-in explanations and navigation rules, not an online generative AI service.

## What the risk number means

The 0–100 score is a prototype priority label using algorithm family, text-match confidence, filename-based component criticality, and the Mosca-style X+Y vs Z planning window. Data lifetime, migration time, and criticality are filename-based demo estimates that should be confirmed with owners. It is not a prediction of when a quantum computer will be available. A TLS or X.509 reference alone cannot establish the negotiated cipher suite or certificate key. Recommendations are planning prompts that require compatibility review.

## Local testing

With the virtual environment activated, run:

```powershell
python -m unittest discover -s tests -v
```

Expected: all checks pass. The tests cover the local demo scan, scenario endpoint, report response, and ZIP path safety.
