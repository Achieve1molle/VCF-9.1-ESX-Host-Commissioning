
# VCF9 ESXi Readiness (r6i3)

**VCF9-ESXi-Readiness-r6i3.ps1** is a Windows PowerShell 7+ **GUI** tool that preflights one or more **stand‑alone ESXi hosts** for VMware Cloud Foundation 9.x readiness. It validates core settings (NTP, services), inspects the presented **server certificate**, optionally runs **Broadcom Compatibility Guide (BCG)** checks for CPU/IO/SSD against simple JSON rule files, detects possible **vSAN residue**, and inventories **CDP/LLDP neighbors**—exporting everything to CSV and (optionally) Excel.

> Version: **r6i3** (UI restored; prereq panel, ESXi version picker, BCG normalize/regex, per‑vmnic neighbor capture, removed temp signing files)

---

## ✨ Features
- **WPF GUI** in PS7 (dark theme) with live log
- **Prerequisite checks**: PowerShell 7+, VMware PowerCLI, ImportExcel (optional), OpenSSH client (optional), offline **vSAN HCL** JSON presence
- **Target management**: add/remove rows, load/save CSV (Host/FQDN, Username, Password, Port)
- **ESXi target version picker** (9.0.1.0, 9.0.0.1, 8.0 U3/U2/U1, 8.0) used by BCG rules
- **Test Connection** per host (PowerCLI `Connect-VIServer`)
- **Readiness run** per host (parallel using `ThreadJob`):
  - NTP servers present and `ntpd` startup policy
  - Server certificate **CN/SAN match** to host/FQDN
  - Optional **vSAN residue** detection via `esxcli vsan storage list`
  - Optional **BCG checks**:
    - **CPU**: normalize model; match via `match` or optional `regex` rule → supported ESXi versions
    - **IO (NIC/HBA)**: match by model *or* PCI VID/DID; driver name + **min version** rule checked via installed VIBs
    - **SSD**: model match to supported ESXi versions
  - **Neighbors**: CDP/LLDP discovery for each **vmnic**, including attached vSwitch/DVSwitch and peer switch/port details
- **Outputs** per run:
  - `PerHostRows.csv`
  - `VCF9-ESXi-Readiness-<timestamp>.xlsx` with `HostRows` (+ `Neighbors` tab) when ImportExcel is installed
  - timestamped log file under an auto‑created run folder: `VCF9-Readiness-YYYYMMDD-HHMMSS/`
- **Cancel** running checks safely; **Open Log / Open Reports / Open Last Excel** convenience buttons

---

## 📦 Requirements
- **Windows** (WPF/WinForms UI)
- **PowerShell 7 or later**
- **VMware PowerCLI** module (installable from the UI)
- **ImportExcel** module *(optional, for Excel output; installable from the UI)*
- **OpenSSH client** (`ssh`, `scp`) *(optional)*
- Network access from your workstation to each ESXi host **TCP/443**

> Optional reference data files placed either beside the script or in your chosen run folder:
> - `bcg_cpu.json`, `bcg_io.json`, `bcg_ssd.json` *(enables BCG checks when **Enable Broadcom Compatibility Guide** is selected)*
> - `all.json` *(offline vSAN HCL indicator in the Prereqs panel; not required for a run)*

---

## 🚀 Quick start
1. **Clone** this repo and open **PowerShell 7**.
2. Run the script:
   ```powershell
   pwsh -File .\VCF9-ESXi-Readiness-r6i3.ps1
   ```
3. In **Prerequisites**, click **Install PowerCLI** (and **Install ImportExcel** if you want Excel output), then **Recheck**.
4. In **ESXi Targets**:
   - Click **Add Row**, enter **Host / FQDN**, **Username** (e.g., `root`), Password, and optionally **Port**.
   - Or **Load Targets** from a CSV (see format below).
   - Pick the **Target ESXi Version** you intend to validate against.
5. Click **Test Connection** to verify logon, then **Run Readiness**.
6. Use **Open Reports** to jump to the run folder for CSV/Excel, and **Open Log** for the detailed log.

---

## 📄 CSV input format (Load/Save Targets)
The grid Load/Save uses a simple schema:

| Column      | Required | Notes                                                |
|-------------|----------|------------------------------------------------------|
| `TargetHost`| ✅        | Hostname or FQDN or IP of the ESXi host             |
| `Username`  | ✅        | e.g., `root`                                         |
| `Password`  | ❌        | Optional; can be left blank to type in the UI       |
| `Port`      | ❌        | Defaults to `443` if missing                         |

Example:
```csv
TargetHost,Username,Password,Port
esx01.lab.local,root,MySecret!,443
esx02.lab.local,root,,443
```

---

## 📤 Outputs
- **CSV**: `PerHostRows.csv` — one row per check per host with columns: `Host`, `Check`, `Status`, `Detail`
- **Excel** *(if ImportExcel present)*: `VCF9-ESXi-Readiness-YYYYMMDD-HHMMSS.xlsx`
  - **HostRows**: all checks
  - **Neighbors**: only rows where `Check = Neighbor`
- **Log**: `Readiness-YYYYMMDD-HHMMSS.log`

**Statuses** include `Pass`, `Fail`, `Warn`, `Unknown`, and informational entries.

---

## 🧠 How the checks work
### NTP & Service Policy
- Reads configured NTP servers and validates the `ntpd` service startup policy (expects **on/automatic**).

### Certificate (CN/SAN) match
- Opens an SSL stream to the host on **443**, reads `CN` and `SAN` entries and verifies that the entered **Host / FQDN** either matches the CN, is present in SAN, or is covered by a wildcard `*.domain` SAN.

### vSAN residue (optional)
- Executes `esxcli vsan storage list` and inspects output for typical leftover **in‑use/claimed/disk group** markers. If found, flags **Fail**.

### Broadcom Compatibility Guide (optional)
Provide any of the JSON files below to enable their respective checks. Files can live next to the script or in the selected run folder.

#### `bcg_cpu.json` (example)
```json
[
  { "match": "Xeon Gold 6330", "esxi": ["9.0.1.0", "9.0.0.1", "8.0 U3"] },
  { "regex": "^AMD EPYC\\s+74..", "match": "EPYC 74xx", "esxi": ["8.0 U3"] }
]
```
- The script **normalizes** CPU model strings (removes ®/™/"CPU" markers, trims SKU suffixes) before matching.
- A rule matches if the normalized CPU contains `match` **or** if the raw CPU string satisfies `regex`.

#### `bcg_io.json` (example)
```json
[
  {
    "class": "NIC",
    "match": "Broadcom 57414",
    "driver": { "name": "bnxtnet", "min": "216.0.50" },
    "esxi": ["9.0.1.0", "8.0 U3"]
  },
  {
    "class": "HBA",
    "vid": "1000", "did": "0073",
    "driver": { "name": "lsi_msgpt3", "min": "18.00.02" },
    "esxi": ["8.0 U2", "8.0 U3"]
  }
]
```
- NIC/HBA devices are matched by **model** (`match`) or by **PCI VID/DID**.
- Installed **driver name** and **version** are derived from VIB listings; version is compared using a numeric segment comparison.

#### `bcg_ssd.json` (example)
```json
[
  { "match": "Intel SSD D3-S4610", "esxi": ["8.0 U3"] },
  { "match": "Samsung PM1735", "esxi": ["9.0.0.1", "9.0.1.0"] }
]
```
- All devices where `IsSsd = true` are considered; model is matched using `match`.

> **Note**: These JSON files are **not** official BCG exports—use them as light‑weight mapping lists for your environment.

### Neighbors (CDP/LLDP)
- For each **vmnic**, the script queries network hints and records the attached **standard vSwitch or DVSwitch**, neighbor **switch name/ID**, and **port**/**port ID** when advertised.

---

## 🔐 Security & privacy
- Credentials you type are used only for the live session to `Connect-VIServer`. The script does **not** persist passwords unless **you** choose to save a targets CSV that includes them.
- Logs and reports contain hostnames and configuration findings; review before sharing outside your org.
- PowerCLI certificate validation is set to **Ignore** for connectivity, but the script’s **Certificate** check still reports CN/SAN mismatches to encourage proper host cert hygiene.

---

## 🧰 Troubleshooting
- **WPF assembly load failed** → Run on **Windows** with **PowerShell 7+**.
- **PowerCLI/ImportExcel not found** → Use the **Install** buttons in the Prereqs panel, or install from PSGallery.
- **Connect failure** → Verify TCP/443 reachability, credentials, and that host API is enabled.
- **Excel export failed** → Ensure **ImportExcel** is installed; otherwise use the CSV which is always produced.
- **BCG shows Unknown** → Provide the corresponding `bcg_*.json` file with a rule for your hardware; verify model/PCI IDs/driver names.

---

## 🗂️ Repository layout
```
/ (repo root)
├─ VCF9-ESXi-Readiness-r6i3.ps1
├─ bcg_cpu.json            (optional)
├─ bcg_io.json             (optional)
├─ bcg_ssd.json            (optional)
└─ all.json                (optional, offline vSAN HCL)
```

Run artifacts are written under: `VCF9-Readiness-YYYYMMDD-HHMMSS/`.

---

## 🤝 Contributing
PRs are welcome for:
- New/updated sample BCG rule entries
- Additional checks (e.g., syslog, lockdown mode, SSH policy)
- Usability tweaks to the UI

Please include a brief description and test output when contributing.

---

## 📜 License
> _Add your project license here (e.g., MIT, Apache-2.0)._

---

## 🙏 Acknowledgments
- Built with **PowerShell 7**, **WPF**, and **VMware PowerCLI**.
- Thanks to everyone sharing operational readiness best practices in the community.
