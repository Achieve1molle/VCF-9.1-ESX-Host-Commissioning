## VCF 9.1 ESX Host Validation and JSON Generator

PowerShell 7/WPF utility for validating, remediating, and documenting **VCF 9.1 ESX host readiness** before commissioning, with integrated bulk host commission JSON generation.

- **Current release:** v1.6
- **Script:** `VCF91-ESX-Validation-JSON-Generator-v1.6-VCF.PowerCLI.ps1`
- **Author:** Michael Molle
- **Required PowerCLI rollup:** `VCF.PowerCLI` (not `VMware.PowerCLI`)

## Highlights

- Processes **3–5 hosts in parallel** using isolated hidden PowerShell 7 workers; default is 4.
- Streams worker activity into the WPF log pane while also writing the run log.
- Masks ESXi passwords in the validation grid.
- Saves and restores host rows plus DNS, search-domain, and NTP settings in CSV.
- Warns that saved CSV files contain plaintext ESXi passwords.
- Installs all missing prerequisites in the active PowerShell 7 process.
- Creates, trusts, and uses a Current User self-signed code-signing certificate before STA relaunch.
- Uses guarded OSA/ESA residual-disk reclamation when cleanup is explicitly selected.
- Reboots each successfully processed host after SSH is disabled.

## Purpose

Use this tool to prepare standalone ESXi hosts for VCF 9.1 commissioning:

- Set and verify hostname, lowercase FQDN, DNS servers, domain, and search suffix.
- Validate forward and reverse DNS and host-to-DNS query reachability.
- Configure NTP, enable/start the NTP service, verify synchronization, and measure time drift.
- Validate or regenerate the ESXi certificate for the lowercase FQDN.
- Validate ESXi 9.1 or later.
- Enforce IPv6 disabled and report the reboot-required state.
- Validate raw vSAN disk eligibility without failing on the expected ESXi boot disk.
- Optionally remove residual OSA/ESA ownership and partition data from safe disks.
- Disable SSH and reboot each processed host.
- Export an Excel readiness report and generate VCF host commission JSON.

## Requirements

- Windows automation host with a WPF-capable interactive session.
- PowerShell 7 or later (`pwsh`).
- `VCF.PowerCLI`.
- `Posh-SSH`.
- `ImportExcel` for `.xlsx` reports; CSV fallback is used when unavailable.
- HTTPS/443 connectivity from the automation host to each ESXi host.
- SSH/TCP 22 connectivity while shell-level checks and remediation run.
- DNS and NTP connectivity from each ESXi host.
- Optional HTTPS/443 connectivity to SDDC Manager for Network Pool inventory and JSON generation.

### Prerequisite installation

Any prerequisite installation button checks and installs all missing modules in the current PowerShell 7 process:

```powershell
VCF.PowerCLI
ImportExcel
Posh-SSH
```

The script does not launch Windows PowerShell 5 and does not install `VMware.PowerCLI`.

## Launch

```powershell
pwsh -NoProfile -ExecutionPolicy Bypass -File .\VCF91-ESX-Validation-JSON-Generator-v1.6-VCF.PowerCLI.ps1
```

The script creates or reuses a Current User code-signing certificate, adds the certificate to Current User Trusted Publishers and Root, signs the script, and relaunches in PowerShell 7 STA mode when required.

## Validation CSV

Current CSV columns:

```csv
TargetHost,Username,Password,DnsServers,SearchDomains,NtpServers
pod01esx12.corp.example.com,root,ExamplePassword,192.0.2.10;192.0.2.11,corp.example.com,time1.example.com;time2.example.com
```

| Column | Description |
|---|---|
| `TargetHost` | ESXi host FQDN, normalized to lowercase. |
| `Username` | ESXi user; defaults to `root` when blank. |
| `Password` | Credential used by PowerCLI and SSH. |
| `DnsServers` | Desired DNS server list restored into the UI. |
| `SearchDomains` | Desired domain/search suffix restored into the UI. |
| `NtpServers` | Desired NTP server list restored into the UI. |

> **Security warning:** Save CSV writes ESXi passwords in plaintext. The UI displays a warning with the saved path. Restrict NTFS permissions and delete the CSV when no longer needed.

## UI workflow

1. Confirm PowerShell 7, VCF PowerCLI, ImportExcel, and Posh-SSH status.
2. Enter DNS servers, search domains, and NTP servers.
3. Add hosts manually or load a CSV.
4. Choose **3**, **4**, or **5** parallel nodes.
5. Leave **Apply remediation** selected for initial preparation.
6. Leave **Clean vSAN residue** cleared for new/raw hosts unless destructive cleanup is required.
7. Select **Run Readiness**.
8. Monitor detailed per-host activity in the live UI log.
9. Review the Results tab and generated Excel workbook.
10. Allow the hosts to reboot; rerun after reboot for final-state verification if desired.

## Validation and remediation behavior

### Hostname, DNS, and domain

The script sets the short hostname, lowercase FQDN, primary domain, DNS servers, and DNS search suffix. It uses PowerCLI first and ESXi shell commands as fallback or confirmation. Verification accepts functional DNS success when ESXi DNS-list parsing is blank.

### DNS

- The automation host verifies forward A and reverse PTR records.
- The PTR must match the lowercase host FQDN.
- Each ESXi host queries the configured DNS servers; at least one successful query is required.

### NTP and time drift

The script compares desired and current NTP servers, applies changes when necessary, enables the NTP service, and retries synchronization checks up to 10 times. The service is restarted after attempt 5 if no peer is selected or reachable. The report records signed and absolute UTC drift.

### Certificate

The certificate subject/SAN must contain the lowercase ESXi FQDN. With remediation enabled, the script runs:

```bash
/sbin/generate-certificates
```

The final reboot reloads management services and the certificate.

### IPv6

With remediation enabled, the script requests global IPv6 disable and reports `Remediated` because ESXi requires a reboot before all interfaces and management components reflect the final state.

### vSAN validation with cleanup cleared

The script runs `vdq -q -H`, with `vdq -q` as fallback, and queries `esxcli vsan storage list`.

The check passes when:

- One or more data disks report `Eligible for use by VSAN` or an eligible Storage Pool state.
- No non-empty vSAN ownership entry exists.

Expected ineligibility of the partitioned ESXi boot/system disk is ignored. Blank `esxcli vsan storage list` objects are not treated as ownership. Ownership requires a real device, vSAN UUID, disk-group value, mounted flag, host-use flag, or CMMDS flag.

### Guarded OSA/ESA cleanup

**Clean vSAN residue is destructive and must be selected explicitly.** After confirmation, the script:

1. Enumerates local disks.
2. Protects mounted VMFS extents, active coredump devices, and ESXi boot/system/OSData/locker devices.
3. Skips non-local and protected disks.
4. Attempts vSAN ownership removal through ESXCLI V2.
5. Clears the selected disk partition table using `HostStorageSystem.UpdateDiskPartitions()` with an empty partition specification.
6. Rescans HBAs and VMFS and refreshes storage.
7. Runs `vdq` to verify the post-clean state.

Locked or read-only disks are reported as failures; boot-option or out-of-band escalation remains an operator-controlled procedure.

### SSH and reboot

SSH is enabled only for required checks, then disabled. Each successfully processed host receives:

```powershell
Restart-VMHost -VMHost $vmh -Force -Confirm:$false
```

A management-disconnect warning immediately after the request is expected. The script sends the reboot request but does not wait for the host to return or perform a post-reboot validation pass.

## Parallel processing and live log

Each host runs in a separate hidden PowerShell 7 worker process. The main WPF process tails the shared log approximately every 250 milliseconds and displays connection attempts, remediation stages, validation results, SSH shutdown, reboot requests, and worker completion.

## Outputs

Each launch creates:

```text
VCF91-Validation-Json-Run-YYYYMMDD-HHMMSS
```

Typical files:

```text
ValidationJson-YYYYMMDD-HHMMSS.log
VCF91-ESX-Validation-YYYYMMDD-HHMMSS.xlsx
validation-targets.csv
example-validation-targets.csv
bulk-commission-hosts-YYYYMMDD-HHMMSS.json
```

The Excel workbook includes:

- **Hosts** — host-level summary.
- **Details** — one row per host/check with command output and evidence.

Status values are `Pass`, `Remediated`, `N/A`, and `Fail`.

## JSON Generator

The JSON Generator requests an SDDC Manager token and loads Network Pool inventory:

```text
POST /v1/tokens
GET  /v1/network-pools
```

The generated JSON contains host passwords in plaintext and must be protected accordingly.

## Troubleshooting

### New nodes show vSAN Fail

Use v1.6 or later. Earlier logic could mistake a blank `esxcli vsan storage list` object for ownership. In v1.6, eligible raw data disks pass and the expected partitioned ESXi boot disk is ignored.

### UI log appears idle

Use v1.4 or later. Parallel worker activity is streamed from the shared log into the WPF log pane while the run is active.

### IPv6 reports Remediated

The disable request was applied. Reboot is required before the final state is visible everywhere. Rerun readiness after reboot for confirmation.

### DNS inventory is blank but verification passes

ESXi output parsing did not return the server list, but a functional query from the host succeeded. The Details worksheet records this fallback.

### Reboot reports a warning

Management can drop before PowerCLI receives acknowledgement. Review the log and host management interface to confirm the reboot.

## Security notes

- Passwords are masked in the UI but held in memory during processing.
- Saved validation CSV and generated commission JSON contain plaintext passwords.
- Logs and reports can contain hostnames, IP addresses, DNS/NTP names, certificate data, and storage identifiers.
- Apply restrictive permissions to the run directory and remove secrets when no longer required.

## Release notes — v1.6

- Corrected blank ESXCLI vSAN result objects being interpreted as ownership.
- Requires actual non-empty ownership fields or true state flags.
- Counts eligible raw disks and ignores expected boot/system-device ineligibility.
- Retains live UI logging, 3–5-node parallel processing, PowerShell 7 prerequisite installation, code-signing certificate generation, password masking/warnings, guarded OSA/ESA cleanup, SSH shutdown, and per-host reboot.

## Disclaimer

Validate this workflow in a controlled environment before production use. Confirm host selection, remediation scope, reboot timing, and disk identity. Use vSAN cleanup only when every candidate disk is verified safe to erase.
