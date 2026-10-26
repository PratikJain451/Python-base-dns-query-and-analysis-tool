# DNS Query and Analysis Tool (Python Flask)

A complete, responsive, full-stack network diagnostic and analysis website built using **Python 3**, **Flask**, **dnspython**, **SQLite**, **Matplotlib**, and **Scapy**. Designed for Computer Science Engineering college projects, network laboratory demonstrations, and cybersecurity analysis.

---

## 🌟 Key Features

1. **DNS Record Resolution**:
   - Resolves standard RFC 1035 resource record sets:
     - **A**: Host IPv4 32-bit address
     - **AAAA**: Host IPv6 128-bit address
     - **CNAME**: Canonical name or alias target
     - **MX**: Mail exchange host with numeric preference/priority
   - High-precision latency measurement in milliseconds using Python's `time.perf_counter()`.
   - Clear semantic distinction between `SUCCESS`, `NO_ANSWER (NODATA)`, `NXDOMAIN`, `TIMEOUT`, and network `ERROR`.

2. **Multiple-Domain Comparison**:
   - Compares up to 10 domains side-by-side.
   - Computes minimum, maximum, and average response times.
   - Automatically determines the fastest and slowest domain with relative latency ratings.
   - Generates a horizontal comparison chart rendered on the server.

3. **Persistent SQLite Query Telemetry**:
   - Saves all query metrics, answers, resolvers, timestamps, and error messages to `instance/dns_analysis.db`.
   - Indexed columns for rapid search, filtering by record type and status, and chronological or latency sorting.
   - Pagination controls and a safe modal-confirmed database truncation feature.

4. **Server-Side Python Visual Analytics (Matplotlib)**:
   - All charts are compiled in Python using `matplotlib.use('Agg')` and saved to `static/generated/`:
     - **Bar Chart**: Response latency across domain queries.
     - **Line Graph**: Consecutive latency trend over time with mean benchmark line.
     - **Donut Chart**: Proportional query success vs. failure rates.
     - **Distribution Bar**: Query count broken down by record type (A, AAAA, CNAME, MX).
   - Generates clean empty-state placeholders when the database is empty; no broken image icons.

5. **Wireshark Packet Dissection (PCAP & PCAPNG)**:
   - Dedicated Wireshark analysis suite.
   - Detailed tutorial on capturing DNS traffic on Windows interfaces.
   - Curated display filter cheat sheet (`dns`, `dns.flags.response == 0`, `dns.flags.rcode != 0`, etc.).
   - Upload PCAP/PCAPNG capture files for packet-by-packet dissection (Source/Dest IP and Ports, DNS Tx ID, Query Name, QType, Flags, RCODE, Answers).
   - Built-in one-click **Sample PCAP generator** to test packet analysis immediately without external tools.
   - Explanations of encrypted DNS protocols (**DoH** and **DoT**) and packet sniffing limitations.

6. **CSV and JSON Data Export**:
   - Export full query history via RFC-compliant CSV and structured JSON endpoints (`/export/csv`, `/export/json`).

7. **Zero Complex Frontend Frameworks**:
   - Pure Flask + Jinja2 server-rendered templates.
   - Styled with Bootstrap 5 CSS and a custom cybersecurity dark-navy/cyan theme.
   - Fully operational without client-side JavaScript for all core query workflows.

---

## 📁 Project Directory Structure

```text
dns-query-analysis/
├── app.py                     # Main Flask application and HTTP route handlers
├── dns_service.py             # DNS resolution, timing, validation, and multi-domain benchmark logic
├── database.py                # SQLite database management, parameterized queries, and indexing
├── graph_service.py           # Matplotlib headless backend chart generation
├── packet_analyzer.py         # PCAP/PCAPNG packet capture parser with Scapy support
├── requirements.txt           # Project dependencies
├── README.md                  # Complete documentation and execution guide
├── templates/                 # Server-rendered Jinja2 templates
│   ├── base.html              # Shared responsive layout with navbar and footer
│   ├── index.html             # Main Dashboard with metrics and embedded charts
│   ├── dns_query.html         # DNS query form with record checkboxes
│   ├── results.html           # Query batch results table (POST-Redirect-GET)
│   ├── compare.html           # Multi-domain comparison tool
│   ├── history.html           # Query history with search, filters, and pagination
│   ├── query_details.html     # Single query detailed technical inspection
│   ├── graphs.html            # Visual analytics page with 4 Matplotlib charts
│   ├── wireshark.html         # Packet capture upload, tutorial, and dissection table
│   ├── about.html             # Comprehensive engineering project report
│   └── error.html             # User-friendly 404, 413, and 500 error page
├── static/
│   ├── css/
│   │   └── style.css          # Custom cybersecurity and networking styling
│   ├── images/
│   │   └── logo.png           # Application emblem logo
│   └── generated/             # Auto-generated Matplotlib chart images
├── uploads/                   # Temporary upload directory for PCAP files
└── instance/                  # SQLite database (dns_analysis.db)
```

---

## 🛠️ Technology Stack

- **Backend Language**: Python 3.9+ (Tested through Python 3.15)
- **Web Framework**: Flask 3.x
- **Template Engine**: Jinja2
- **DNS Resolution**: `dnspython`
- **Timing Engine**: Python `time.perf_counter()`
- **Database**: SQLite 3 (Standard Library `sqlite3`)
- **Visual Analytics**: `matplotlib` (Agg headless backend)
- **Packet Dissection**: `scapy` & Native Binary PCAP Streamer
- **Data Export**: Standard Library `csv` and `json`
- **Styling**: Bootstrap 5.3 + Bootstrap Icons + Custom CSS

---

## 🚀 Installation & Execution on Windows in VS Code

Follow these beginner-friendly step-by-step instructions:

### Step 1: Open the Project in VS Code
1. Launch **Visual Studio Code**.
2. Click **File &rarr; Open Folder...** and select this project directory (`N CN PROJECT` or `dns-query-analysis`).

### Step 2: Open the Integrated Terminal
- Press <kbd>Ctrl</kbd> + <kbd>`</kbd> (backtick) or select **Terminal &rarr; New Terminal** from the top menu.
- Ensure PowerShell or Command Prompt is selected.

### Step 3: Create a Python Virtual Environment
In the VS Code terminal, execute:
```powershell
py -m venv .venv
```
*(If `py` is not recognized, use `python -m venv .venv`)*

### Step 4: Activate the Virtual Environment
Activate the environment in PowerShell:
```powershell
.venv\Scripts\Activate.ps1
```

> **Note (PowerShell Execution Policy):**  
> If PowerShell displays an error stating that script execution is disabled on this system, you can bypass it safely for the current terminal session without altering global system policies:
> ```powershell
> Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
> .venv\Scripts\Activate.ps1
> ```
> Alternatively, switch the terminal to **Command Prompt (cmd)** and run:
> ```cmd
> .venv\Scripts\activate.bat
> ```

### Step 5: Install Dependencies
Install all required packages via pip:
```powershell
py -m pip install -r requirements.txt
```

### Step 6: Start the Flask Application
Run the Flask server:
```powershell
py app.py
```

You should see console output similar to:
```text
=================================================================
  DNS Query and Analysis Tool - Flask Server Starting
  Running locally at: http://127.0.0.1:5000
  Press Ctrl+C to stop the server.
=================================================================
 * Serving Flask app 'app'
 * Debug mode: on
 * Running on http://127.0.0.1:5000
```

### Step 7: Open the Application in Your Browser
Open your browser and navigate to:
[http://127.0.0.1:5000](http://127.0.0.1:5000)

---

## 🔍 Application Walkthrough & Testing Guide

| Page / Route | Functionality & Testing Instructions |
|---|---|
| **Dashboard (`/`)** | View real-time database query metrics, quick search input, latest query logs, and dynamically generated Matplotlib graphs. |
| **DNS Query (`/dns-query`)** | Enter a domain name (e.g. `google.com`), toggle record types (`A`, `AAAA`, `CNAME`, `MX`), select resolver (`Google 8.8.8.8`, `Cloudflare 1.1.1.1`), and execute the query. |
| **Results (`/results`)** | Review authoritative DNS answers, MX priority integers, round-trip latency (ms), and RFC status badges. Refreshing this page does not repeat queries (POST-Redirect-GET). |
| **Domain Compare (`/compare`)** | Paste multiple domains (e.g. `google.com`, `github.com`, `wikipedia.org`), select records, and benchmark latency min/max/average side by side with a comparative horizontal bar chart. |
| **History (`/history`)** | Search queries by domain or IP, filter by record type (A/AAAA/CNAME/MX) or status, sort by date/time, and navigate paginated records. |
| **Query Details (`/history/<id>`)** | Inspect the granular technical breakdown of an individual query record, including RFC protocol explanation and resolution sequence. |
| **Visual Charts (`/graphs`)** | View the 4 standalone high-resolution Matplotlib charts rendered by the Python backend. |
| **Wireshark Analysis (`/wireshark`)** | Follow the packet capture guide, copy display filters, and upload a `.pcap` file. Or click **"Download Sample PCAP"** to analyze pre-packaged DNS traffic with zero setup. |
| **Data Export (`/export/csv`, `/export/json`)** | Download structured telemetry reports with a single click. |
| **About Project (`/about`)** | Comprehensive academic project report covering problem statement, objectives, system architecture, advantages, limitations, and future scope. |

---

## 🔧 Troubleshooting Guide

### 1. `pip : The term 'pip' is not recognized`
Run pip using Python's module launcher:
```powershell
py -m pip install -r requirements.txt
```

### 2. Port 5000 Already in Use
If another application is running on port 5000:
- Stop the conflicting process or change the port in `app.py`:
  ```python
  app.run(host="127.0.0.1", port=5001, debug=True)
  ```
- Access the tool at `http://127.0.0.1:5001`.

### 3. DNS Query Timeouts
- If querying a domain times out, verify that your computer has an active Internet connection and that local antivirus/firewall software is not blocking UDP port 53.
- Try selecting a public upstream resolver like **Google Public DNS (8.8.8.8)** from the resolver dropdown.

### 4. Matplotlib Cache or GUI Warnings
- The tool uses `matplotlib.use("Agg")` at the top of `graph_service.py` to ensure headless, thread-safe server execution without GUI popups.

### 5. Wireshark PCAP File Formats
- Both standard `.pcap` (tcpdump) and `.pcapng` formats are accepted.
- For maximum speed and compatibility, saving captures as standard `Wireshark/tcpdump (*.pcap)` in Wireshark is recommended.

---

## 📜 License & Academic Attribution
Developed as an educational Computer Science Engineering project in Computer Networks (CN). Permitted for academic demonstrations, laboratory evaluations, and technical presentations.
