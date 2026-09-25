<#
.SYNOPSIS
  VCF 9.1 ESX Validation and JSON Generator v1.7.18 Shaded disabled password cells

.DESCRIPTION
  Production WPF tool for ESX readiness remediation/validation and bulk commission JSON generation.

.Author
  Michael Molle

  v1.7.18: password cells have a visible shaded disabled state in shared mode.
  v1.7.17: dedicated shared password box; entire host password column disabled
  and shaded in shared mode; professional dark blue action buttons.
  v1.7.15: explicit shared-password source above hosts, gray/disable other
  password cells, preflight credential consistency check without logging
  secrets, no repeat retries on rejected credentials, report bundle naming.
  v1.7.14: opt-in shared ESX password (one entered host), 600-second
  verified reboot timeout, NTP progress logging every three unsynchronized
  attempts. v1.7.13 fixes included: same-line vSAN UUID detection, DNS query
  without unsupported nc probe, preliminary DNS status, input rejection.
  IPv6 remediation and NTP synchronization/restart behavior unchanged.
  v1.7.12: host-side DNS TCP/53 and functional DNS queries, NTP name
  resolution and peer reach diagnostics, 20 NTP observations at 10-second
  intervals, one conditional service restart after three no-response samples.
  UDP netcat is not treated as proof of an NTP reply. IPv6 unchanged.
  v1.7.11: explicit storage intent and non-destructive external-storage vSAN
  classification; bounded NTP stabilization, drift threshold, certificate-name
  scope, plus v1.7.10 input, not-run, conditional-reboot and selected-peer gates.
  IPv6 function is unchanged from v1.7.9/v1.7.10.
  v1.7.9: pin A/PTR queries to configured DNS, verify host DNS list,
  defer IPv6 success to post-reboot, verify SSH cleanup, protect worker input,
  and omit passwords from saved CSV and diagnostic ZIP.
  v1.7.8: Open Run Folder launches Explorer on the current run directory,
  without requiring a report or an XLSX file association.
  v1.7.7: use ESX 9.1 global network IPv6 state with optional advanced-setting
  cross-check, report completion logging, and a themed host-run review dialog.
  v1.7.6: removes grid Refresh during CellEditEnding; password edits no longer
  trigger an invalid WPF edit transaction. Credential status updates at idle.
  v1.7.5: standalone-host reboot without maintenance-mode gating; preserve
  powered-on VM preflight, drain worker results, and export reports on errors.
  v1.7.4: removes the redundant reboot checkbox. Apply remediation alone
  selects the confirmed single-reboot and post-reboot validation workflow.
  v1.7.3: confirmed one-reboot remediation cycle, boot-time proof, bounded
  wait, and one validation-only post-reboot pass. No remediation/reboot retry.
  v1.7.2: validation-only default, explicit remediation and reboot gates, safe
  stop-queue behavior, IPv6 evidence consistency, clear button actions and progress.
  v1.7.1 maintenance fixes:
  - Preserves v1.7 IPv6 remediation and evidence logic.
  - Quotes paths when launching parallel workers and records worker stderr on failure.
  - Shows blank password cells until a real password is entered or loaded.
  - Requires a password for each target before running or generating commission JSON.
  v1.8.46 updates:
- Fixes blank ESXCLI vsan.storage.list result objects being mistaken for existing vSAN ownership.
- Requires an actual non-empty device, vSAN UUID, disk-group UUID/name, mounted, or used-by-host value before ownership is considered present.
- Logs eligible disk count, non-empty ownership entry count, and expected boot/system disk exclusions.
v1.8.45 updates:
- Corrects false vSAN failures on brand-new, unclaimed nodes when Clean vSAN residue is not selected.
- Treats raw disks reported as Eligible for use by VSAN / Reason: None as a pass, while ignoring expected ineligible ESXi boot/system devices.
- Still fails validation when existing vSAN ownership is returned or no eligible raw vSAN disk is detected.
v1.8.44 updates:
- Streams log entries written by parallel worker processes into the WPF log pane while validation is running.
- Adds worker start/completion progress messages and keeps the UI responsive during parallel processing.
v1.8.43 updates:
- Masks ESXi passwords and warns after saving plaintext passwords to CSV.
- Saves/loads DNS, domain, and NTP configuration with CSV targets.
- Runs 3-5 hosts concurrently in isolated hidden PowerShell 7 workers.
- Installs VCF.PowerCLI, ImportExcel, and Posh-SSH in-process under PowerShell 7.
- Creates/trusts a CurrentUser code-signing certificate and signs before STA relaunch.
- Uses guarded OSA/ESA disk reclamation with protected-device checks, ESXCLI V2, HostStorageSystem partition clearing, rescan, and vdq verification.
v1.8.41 updates:
  - Switched required PowerCLI rollup module to VCF.PowerCLI.
  - Updated prerequisite detection, import, error messaging, and install button command for VCF.PowerCLI.

  v40 included fixes:
  - Restores dark production UI layout/styling.
  - Separates Hostname/DNS/Domain Set from Hostname/DNS/Domain Verify.
  - DNS verify accepts functional DNS query success if ESX DNS-list parsing is blank.
  - Adds SSH retry wrapper for ESX shell commands.
  - Sets/verifies DNS, hostname/FQDN, domain/search suffix, NTP, NTP service, time drift, certificate lowercase FQDN, vSAN, ESX version.
  - Enforces IPv6 disabled when Apply remediation is checked and reports Remediated / pending reboot.
  - Disables SSH and sends final reboot request. Reboot acknowledgement warnings are expected when management drops.
#>
[CmdletBinding()]
param([switch]$NoRelaunch,[string]$WorkerInput,[string]$WorkerOutput)
function Ensure-SelfSignedScriptCertificate([string]$TargetPath){
 if(!$IsWindows -or !(Test-Path -LiteralPath $TargetPath)){return $false};try{
  $sig=Get-AuthenticodeSignature $TargetPath -ErrorAction SilentlyContinue;if($sig.Status -eq 'Valid'){return $true}
  $subject='CN=VCF91 ESX Validation Local Code Signing';$cert=Get-ChildItem Cert:\CurrentUser\My -CodeSigningCert -ErrorAction SilentlyContinue|Where-Object{$_.Subject -eq $subject -and $_.NotAfter -gt (Get-Date).AddDays(30)}|Sort-Object NotAfter -Descending|Select-Object -First 1
  if(!$cert){$cert=New-SelfSignedCertificate -Subject $subject -Type CodeSigningCert -CertStoreLocation Cert:\CurrentUser\My -KeyAlgorithm RSA -KeyLength 2048 -HashAlgorithm SHA256 -NotAfter (Get-Date).AddYears(3)}
  foreach($sn in 'TrustedPublisher','Root'){$st=[Security.Cryptography.X509Certificates.X509Store]::new($sn,'CurrentUser');try{$st.Open('ReadWrite');if(!($st.Certificates|Where-Object Thumbprint -eq $cert.Thumbprint)){$st.Add($cert)}}finally{$st.Close()}}
  $sig=Set-AuthenticodeSignature -FilePath $TargetPath -Certificate $cert -HashAlgorithm SHA256 -ErrorAction Stop;return $sig.Status -in 'Valid','UnknownError'
 }catch{Write-Warning "Self-signing failed: $($_.Exception.Message)";return $false}}
if(!$WorkerInput){$null=Ensure-SelfSignedScriptCertificate $PSCommandPath;$need=$PSVersionTable.PSVersion.Major-lt7 -or [Threading.Thread]::CurrentThread.ApartmentState-ne'STA';if($need-and!$NoRelaunch){$pwsh=(Get-Command pwsh.exe -ErrorAction SilentlyContinue).Source;if(!$pwsh){$pwsh=(Get-Command pwsh -ErrorAction SilentlyContinue).Source};if(!$pwsh){throw 'PowerShell 7 is required.'};&$pwsh -NoProfile -ExecutionPolicy Bypass -STA -File $PSCommandPath -NoRelaunch;exit $LASTEXITCODE};if($PSVersionTable.PSVersion.Major-lt7){throw 'PowerShell 7 or later is required.'}}
$ErrorActionPreference='Stop'
[Net.ServicePointManager]::SecurityProtocol=[Net.SecurityProtocolType]::Tls12
$script:PowerCliModule='VCF.PowerCLI'
try{if(Get-Module -ListAvailable -Name $script:PowerCliModule){Import-Module $script:PowerCliModule -ErrorAction Stop|Out-Null;Set-PowerCLIConfiguration -InvalidCertificateAction Ignore -Confirm:$false -Scope User|Out-Null}}catch{}
Add-Type -AssemblyName PresentationFramework,PresentationCore,WindowsBase,System.Xaml
if(!$WorkerInput){
 $script:RunDir=Join-Path (Get-Location) ("VCF91-Validation-Json-Run-"+(Get-Date -Format yyyyMMdd-HHmmss))
 New-Item -ItemType Directory -Path $script:RunDir -Force|Out-Null
 $script:LogFile=Join-Path $script:RunDir ("ValidationJson-"+(Get-Date -Format yyyyMMdd-HHmmss)+'.log')
 $script:DebugArtifactDir=Join-Path $script:RunDir 'Debug-Artifacts'
 New-Item -ItemType Directory -Path $script:DebugArtifactDir -Force|Out-Null
}
$script:DebugSequence=0
$script:IsRunning=$false;$script:StopRequested=$false;$script:LastReportPath=$null;$script:CurrentShellUser=$null;$script:CurrentShellPassword=$null
function DoEvents{if($WorkerInput){return};try{[System.Windows.Threading.Dispatcher]::CurrentDispatcher.Invoke([Action]{},[System.Windows.Threading.DispatcherPriority]::Background)}catch{}}
function Log([string]$m,[string]$l='INFO'){$line="$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss.fff') [$l] $m";Add-Content -Path $script:LogFile -Value $line;if($script:txtLog -and !$WorkerInput){$script:txtLog.AppendText($line+[Environment]::NewLine);$script:txtLog.ScrollToEnd();if($null-ne$script:UiLogSeen){$script:UiLogSeen++};DoEvents}}
function Save-DiagnosticArtifact([string]$Category,[string]$Operation,$Data){try{$script:DebugSequence++;$c=$Category-replace'[^A-Za-z0-9_-]','_';$o=$Operation-replace'[^A-Za-z0-9_-]','_';$p=Join-Path $script:DebugArtifactDir ('{0:d4}-{1}-{2}-{3}.json'-f$script:DebugSequence,(Get-Date -Format 'yyyyMMdd-HHmmss-fff'),$c,$o);$Data|ConvertTo-Json -Depth 30|Set-Content -LiteralPath $p -Encoding utf8BOM;Log "Diagnostic artifact saved: $p" DEBUG;return $p}catch{Log "Diagnostic artifact save failed: $($_.Exception.Message)" WARN;return $null}}
function Write-ExceptionDiagnostic($e,[string]$context){Save-DiagnosticArtifact EXCEPTION $context ([ordered]@{Context=$context;Message=$e.Exception.Message;Type=$e.Exception.GetType().FullName;Line=$e.InvocationInfo.ScriptLineNumber;Position=$e.InvocationInfo.PositionMessage;Stack=$e.ScriptStackTrace})}
function New-DiagnosticBundle{
 if($WorkerInput){return}
 # RunDir itself is the log bundle; Reports is kept within it. No separate ZIP.
 Log "Log bundle: $script:RunDir (Reports subfolder included; no ZIP created)" PASS
 return $script:RunDir
}

trap{try{$null=Write-ExceptionDiagnostic $_ 'GLOBAL-TRAP'}catch{};continue}

function HasMod($n){[bool](Get-Module -ListAvailable -Name $n)};function Imp($n){Import-Module $n -ErrorAction Stop}
function EnsureModule($n){if(HasMod $n){Imp $n|Out-Null;return $true};$old=$ProgressPreference;try{$ProgressPreference='SilentlyContinue';Install-PackageProvider NuGet -MinimumVersion 2.8.5.201 -Force -ErrorAction SilentlyContinue|Out-Null;Set-PSRepository PSGallery -InstallationPolicy Trusted -ErrorAction SilentlyContinue|Out-Null;Install-Module $n -Scope CurrentUser -Force -AllowClobber -SkipPublisherCheck -AcceptLicense -ErrorAction Stop;Imp $n|Out-Null;Log "$n installed/imported.";return $true}catch{Log "$n install failed: $($_.Exception.Message)" ERROR;return $false}finally{$ProgressPreference=$old}}
function EnsurePrerequisites{$ok=$true;foreach($n in 'VCF.PowerCLI','ImportExcel','Posh-SSH'){if(!(EnsureModule $n)){$ok=$false}};Prereq;if(!$ok){throw 'One or more prerequisites failed. Review the log.'}}
function Cred($u,$p){New-Object pscredential($u,(ConvertTo-SecureString $p -AsPlainText -Force))}
function SafeLower($v){if($null -eq $v){''}else{([string]$v).Trim().ToLowerInvariant()}}
function SplitList([string]$t){@($t -split '[,;\s]+'|Where-Object{$_ -and $_.Trim()}|ForEach-Object{$_.Trim()})}
function Norm($items){@($items|Where-Object{$_ -and ([string]$_).Trim()}|ForEach-Object{([string]$_).Trim().ToLowerInvariant()}|Sort-Object -Unique)}
function EqualList($a,$b){$x=@(Norm $a);$y=@(Norm $b);if($x.Count-ne$y.Count){return $false};foreach($i in $x){if($y -notcontains $i){return $false}};return $true}
function ContainsAll($desired,$actual){$d=@(Norm $desired);$a=@(Norm $actual);foreach($i in $d){if($a -notcontains $i){return $false}};return $true}
function Check($s,$d){[pscustomobject]@{Status=$s;Detail=$d}}
function PassLike($s){$s -match '^(Pass|Remediated|N/A)$'}
function CheckStop{if($script:StopRequested){throw 'Stop requested by operator.'}}
function SleepUi($sec){$e=(Get-Date).AddSeconds($sec);while((Get-Date)-lt$e){DoEvents;Start-Sleep -Milliseconds 250}}
function Q([string]$s){"'"+($s -replace "'","'\\''")+"'"}
function WaitTcp($h,$p,$sec){$e=(Get-Date).AddSeconds($sec);while((Get-Date)-lt$e){try{$c=New-Object Net.Sockets.TcpClient;$r=$c.BeginConnect($h,$p,$null,$null);if($r.AsyncWaitHandle.WaitOne(900,$false)){$c.EndConnect($r);$c.Close();return $true};$c.Close()}catch{};SleepUi 1};$false}
function VerCmp($a,$b){try{([version]$a).CompareTo([version]$b)}catch{[string]::Compare($a,$b,$true)}}
function EnsureToolSelfSignedCertificate{try{if($IsWindows -and (Get-Command New-SelfSignedCertificate -ErrorAction SilentlyContinue)){$sub='CN=VCF91-ESX-Validation-JSON-Generator';$cert=Get-ChildItem Cert:\CurrentUser\My -ErrorAction SilentlyContinue|Where-Object{$_.Subject -eq $sub}|Select-Object -First 1;if(!$cert){New-SelfSignedCertificate -Subject $sub -CertStoreLocation Cert:\CurrentUser\My -KeyLength 2048 -NotAfter (Get-Date).AddYears(3)|Out-Null;Log 'Generated local self-signed certificate for tool launch context.'}else{Log 'Local tool self-signed certificate already present.'}}}catch{Log "Local tool certificate generation warning: $($_.Exception.Message)" WARN}}
function TargetRows([bool]$ResolveSharedPassword=$true){
 try{$null=$gridValidation.CommitEdit();$null=$gridValidation.CommitEdit([System.Windows.Controls.DataGridEditingUnit]::Row,$true)}catch{}
 $shared=($ResolveSharedPassword -and [bool]$chkSharedPassword.IsChecked)
 if($shared -and [string]::IsNullOrEmpty($pwdShared.Password)){throw 'Enter the shared ESX password above the host list.'}
 $rows=@()
 foreach($x in @($script:Targets)){
  $h=([string]$x.TargetHost).Trim();if(!$h){continue}
  $u=if([string]::IsNullOrWhiteSpace([string]$x.Username)){'root'}else{([string]$x.Username).Trim()}
  $pass=if($shared){[string]$pwdShared.Password}else{[string]$x.Password}
  $rows+=[pscustomobject]@{TargetHost=(SafeLower $h);Username=$u;Password=$pass}
 }
 @($rows)
}
function Assert-SharedCredentialSnapshot($targets){
 if(![bool]$chkSharedPassword.IsChecked){return}
 if([string]::IsNullOrEmpty($pwdShared.Password)){throw 'Enter the shared ESX password above the host list.'}
 foreach($t in @($targets)){
  if(![string]::Equals([string]$t.Password,[string]$pwdShared.Password,[StringComparison]::Ordinal)){
   throw "Shared password was not applied to $($t.TargetHost); run canceled before any worker started."
  }
 }
 Log "Shared credential snapshot verified for $(@($targets).Count) targets; password values not logged."
}
function Assert-TargetNames($targets,$domainText){
 $domains=@(SplitList $domainText)
 if(!$domains.Count){throw 'Enter a search domain before validating target host names.'}
 $domain=([string]$domains[0]).TrimEnd('.').ToLowerInvariant()
 $label='^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$'
 if($domain -notmatch '\.' -or @($domain.Split('.')|Where-Object{$_ -notmatch $label}).Count){throw "Invalid primary search domain: $domain"}
 $seen=@{}
 foreach($t in @($targets)){
  $fqdn=([string]$t.TargetHost).Trim().ToLowerInvariant()
  $labels=@($fqdn.Split('.'))
  if(!$fqdn -or $fqdn.Length -gt 253 -or $labels.Count -lt 3 -or @($labels|Where-Object{$_ -notmatch $label}).Count){throw "Invalid host FQDN '$fqdn'."}
  $suffix='.'+$domain
  if(!$fqdn.EndsWith($suffix,[StringComparison]::OrdinalIgnoreCase) -or $fqdn.Substring(0,$fqdn.Length-$suffix.Length) -notmatch $label){throw "Host '$fqdn' does not match <host>.$domain. Check for a missing period or incorrect search domain."}
  if($seen.ContainsKey($fqdn)){throw "Duplicate target host: $fqdn"};$seen[$fqdn]=$true
 }
}
function Get-StorageIntent{if($cmbStorageIntent.SelectedItem){return [string]([System.Windows.Controls.ComboBoxItem]$cmbStorageIntent.SelectedItem).Tag};return ''}
function Assert-StorageIntent([string]$intent,[bool]$clean){
 if($intent -notin @('External','vSAN')){throw 'Select storage intent: External or vSAN.'}
 if($clean -and $intent -ne 'vSAN'){throw 'Clean vSAN residue is blocked for external-storage hosts.'}
}
function ValidateInputs{$m=@();if([string]::IsNullOrWhiteSpace($txtDns.Text)){$m+='DNS servers'};if([string]::IsNullOrWhiteSpace($txtNtp.Text)){$m+='NTP servers'};if([string]::IsNullOrWhiteSpace($txtDomains.Text)){$m+='Search domains'};if($m.Count){throw 'Populate required Desired ESX Configuration field(s): '+($m -join ', ')};if(@($script:Targets|Where-Object{![string]::IsNullOrWhiteSpace([string]$_.TargetHost)}).Count -eq 0){throw 'Add at least one host.'};if([bool]$chkSharedPassword.IsChecked -and [string]::IsNullOrEmpty($pwdShared.Password)){throw 'Enter the shared ESX password above the host list.'};Assert-TargetNames @(TargetRows) $txtDomains.Text;Assert-StorageIntent (Get-StorageIntent) ([bool]$chkClean.IsChecked);$maxDrift=0.0;if(![double]::TryParse(([string]$txtMaxDrift.Text).Trim(),[Globalization.NumberStyles]::Float,[Globalization.CultureInfo]::InvariantCulture,[ref]$maxDrift) -or $maxDrift -le 0 -or $maxDrift -gt 300){throw 'Max time drift must be a number greater than 0 and no greater than 300 seconds (use a period for decimals).'};$missing=@(TargetRows|Where-Object{[string]::IsNullOrWhiteSpace($_.Password)}|ForEach-Object{$_.TargetHost});if($missing.Count){throw "Enter an ESXi password for every target host before running: $($missing -join ', ')"}}
function Prereq{$lblPS.Text=$PSVersionTable.PSVersion.ToString();$lblPS.Foreground='LightGreen';$pcliFound=HasMod $script:PowerCliModule;$lblPCLI.Text=if($pcliFound){'Found'}else{'Missing'};$lblPCLI.Foreground=if($pcliFound){'LightGreen'}else{'Tomato'};$lblExcel.Text=if(HasMod ImportExcel){'Found'}else{'Missing'};$lblExcel.Foreground=if(HasMod ImportExcel){'LightGreen'}else{'Tomato'};$lblSsh.Text=if(HasMod Posh-SSH){'Found'}else{'Missing'};$lblSsh.Foreground=if(HasMod Posh-SSH){'LightGreen'}else{'Tomato'}}
function ConnectRetry($h,$u,$p){if(!(HasMod $script:PowerCliModule)){throw 'VCF.PowerCLI module is required. Use the Install VCF PowerCLI button or run: Install-Module -Name VCF.PowerCLI -Scope CurrentUser -Force -AllowClobber -SkipPublisherCheck'};Imp $script:PowerCliModule|Out-Null;try{Set-PowerCLIConfiguration -InvalidCertificateAction Ignore -Confirm:$false -Scope User|Out-Null}catch{};for($i=1;$i-le3;$i++){try{Log "[$h] Connect-VIServer attempt $i of 3...";return Connect-VIServer -Server $h -Credential (Cred $u $p) -Force -ErrorAction Stop}catch{Log "[$h] Connect failed attempt $i of 3: $($_.Exception.Message)" WARN;if($_.Exception.Message -match '(?i)incorrect user name or password|invalid login|invalid credentials|authentication failed'){throw};if($i-lt3){SleepUi 5}else{throw}}}}
function MgmtIp($vmh){try{$v=Get-VMHostNetworkAdapter -VMHost $vmh -VMKernel|Where-Object{$_.ManagementTrafficEnabled}|Select-Object -First 1;if($v.IP){return [string]$v.IP}}catch{};return $vmh.Name}
function EnableSsh($vmh){
 try{
  $svc=Get-VMHostService -VMHost $vmh -ErrorAction Stop|Where-Object{$_.Key -eq 'TSM-SSH'}|Select-Object -First 1
  if(!$svc){throw 'TSM-SSH service not returned.'}
  if($null -eq $script:SshWasRunning){$script:SshWasRunning=[bool]$svc.Running}
  if(!$svc.Running){
   Log "[$($vmh.Name)] Starting SSH service for readiness commands..." WARN
   Start-VMHostService -HostService $svc -Confirm:$false -ErrorAction Stop|Out-Null
   $script:SshStartedByTool=$true;SleepUi 6
  }
 }catch{Log "[$($vmh.Name)] SSH start warning: $($_.Exception.Message)" WARN}
}
function SshRun($h,$u,$p,$cmd,$to=120){if(!(HasMod Posh-SSH)){throw 'Posh-SSH module is required.'};Imp Posh-SSH|Out-Null;$s=$null;$old=$WarningPreference;try{if(!(WaitTcp $h 22 25)){throw 'TCP/22 not reachable.'};$WarningPreference='SilentlyContinue';$s=New-SSHSession -ComputerName $h -Credential (Cred $u $p) -AcceptKey -Force -ConnectionTimeout 15 -WarningAction SilentlyContinue -ErrorAction Stop;$r=Invoke-SSHCommand -SessionId $s.SessionId -Command $cmd -TimeOut $to -ErrorAction Stop;[pscustomobject]@{StdOut=(@($r.Output)-join"`n");StdErr=(@($r.Error)-join"`n");ExitStatus=$r.ExitStatus}}finally{$WarningPreference=$old;if($s){try{Remove-SSHSession -SessionId $s.SessionId|Out-Null}catch{}}}}
function Esx($vmh,$cmd,$to=120){SshRun (MgmtIp $vmh) $script:CurrentShellUser $script:CurrentShellPassword $cmd $to}
function EsxRetry($vmh,$cmd,$to=120,$tries=4){$last='';for($i=1;$i-le$tries;$i++){try{if($i-gt1){Log "[$($vmh.Name)] ESX shell retry $i of $tries..." WARN;EnableSsh $vmh;SleepUi 5};return Esx $vmh $cmd $to}catch{$last=$_.Exception.Message;Log "[$($vmh.Name)] ESX shell attempt $i failed: $last" WARN;if($i-lt$tries){SleepUi 8}}};throw $last}
function DisableSsh($vmh){
 if($script:SshWasRunning -eq $true){
  Log "[$($vmh.Name)] SSH was running before validation; original state preserved."
  return Check Pass 'SSH was running before validation; original state preserved.'
 }
 if($script:SshWasRunning -eq $null){
  Log "[$($vmh.Name)] SSH original state unknown; cleanup cannot be verified." WARN
  return Check Fail 'SSH original state unknown; inspect service and startup policy manually.'
 }
 try{
  $svc=Get-VMHostService -VMHost $vmh -ErrorAction Stop|Where-Object{$_.Key -eq 'TSM-SSH'}|Select-Object -First 1
  if(!$svc){throw 'TSM-SSH service not returned.'}
  if($svc.Running){Stop-VMHostService -HostService $svc -Confirm:$false -ErrorAction Stop|Out-Null}
  $verify=Get-VMHostService -VMHost $vmh -ErrorAction Stop|Where-Object{$_.Key -eq 'TSM-SSH'}|Select-Object -First 1
  if(!$verify){throw 'TSM-SSH service not returned during verification.'}
  if($verify.Running){throw 'TSM-SSH is still running after cleanup.'}
  Log "[$($vmh.Name)] SSH verified stopped; startup policy=$($verify.Policy)." PASS
  return Check Pass "SSH verified stopped; startup policy=$($verify.Policy); started by tool=$($script:SshStartedByTool)."
 }catch{
  Log "[$($vmh.Name)] SSH cleanup could not be verified: $($_.Exception.Message)" WARN
  return Check Fail "SSH cleanup unverified: $($_.Exception.Message). Inspect service and startup policy manually."
 }
}

function TestRebootPreflight($vmh,$h){
 try{
  # Standalone commissioning host: do not require maintenance mode.
  $powered=@(Get-VM -Location $vmh -ErrorAction Stop | Where-Object {$_.PowerState -eq 'PoweredOn'})
  if($powered.Count -gt 0){throw "Host has $($powered.Count) powered-on VM(s). No reboot will be requested."}
  Log "[$h] Reboot preflight passed: zero powered-on VMs. Maintenance mode not required." PASS
  return $true
 }catch{Log "[$h] Reboot preflight blocked: $($_.Exception.Message)" ERROR;return $false}
}
function InvokeSingleRebootAndWait($target,[int]$TimeoutSeconds=600){
 $h=SafeLower $target.TargetHost;$server=$null;$sent=$false;$before=$null
 try{
  if(!(WaitTcp $h 443 30)){throw 'Host HTTPS was not reachable for reboot preflight.'}
  $server=ConnectRetry $h $target.Username $target.Password
  $vmh=Get-VMHost -Server $server -ErrorAction Stop|Select-Object -First 1
  if(!$vmh){throw 'Host inventory was not returned for reboot.'}
  if(!(TestRebootPreflight $vmh $h)){throw 'Powered-on VM reboot preflight failed.'}
  $view=Get-View -Id $vmh.Id -ErrorAction Stop
  $before=$view.Runtime.BootTime
  if(!$before){throw 'Cannot obtain pre-reboot boot time; reboot verification would be unsafe.'}
  Log "[$h] Reboot phase: boot time before=$before; issuing ONE reboot request." WARN
  $sent=$true
  try{Restart-VMHost -VMHost $vmh -Force -Confirm:$false -ErrorAction Stop|Out-Null}
  catch{Log "[$h] Reboot request returned an error or lost acknowledgement: $($_.Exception.Message). Waiting for boot-time proof; no retry will be sent." WARN}
 }catch{
  $msg=$_.Exception.Message
  Log "[$h] Reboot phase blocked: $msg" ERROR
  return Check Fail $msg
 }finally{
  if($server){try{Disconnect-VIServer -Server $server -Force -Confirm:$false -ErrorAction SilentlyContinue|Out-Null}catch{}}
 }
 if(!$sent){return Check Fail 'Reboot was not requested.'}
 $deadline=(Get-Date).AddSeconds($TimeoutSeconds);$last='Host has not returned with a new boot time.'
 Log "[$h] Waiting up to $TimeoutSeconds seconds for verified reboot; post-reboot checks will run once only."
 while((Get-Date)-lt$deadline){
  Start-Sleep -Seconds 10
  $poll=$null
  try{
   $tcp=New-Object Net.Sockets.TcpClient
   try{$ar=$tcp.BeginConnect($h,443,$null,$null);if(!$ar.AsyncWaitHandle.WaitOne(2500,$false)){continue};$tcp.EndConnect($ar)}finally{$tcp.Close()}
   $poll=Connect-VIServer -Server $h -Credential (Cred $target.Username $target.Password) -Force -ErrorAction Stop
   $hostNow=Get-VMHost -Server $poll -ErrorAction Stop|Select-Object -First 1
   if(!$hostNow){throw 'Host API returned no VMHost.'}
   $bootNow=(Get-View -Id $hostNow.Id -ErrorAction Stop).Runtime.BootTime
   if($bootNow -and ([datetime]$bootNow -gt ([datetime]$before).AddSeconds(1))){
    Log "[$h] Reboot verified: boot time changed from $before to $bootNow." PASS
    return Check Pass "BootTimeBefore=$before; BootTimeAfter=$bootNow; RebootRequests=1"
   }
   $last="Management is reachable, but boot time has not advanced (current=$bootNow)."
  }catch{$last=$_.Exception.Message}
  finally{if($poll){try{Disconnect-VIServer -Server $poll -Force -Confirm:$false -ErrorAction SilentlyContinue|Out-Null}catch{}}}
 }
 Log "[$h] Reboot verification timed out: $last. No second reboot or remediation will be attempted." ERROR
 return Check Fail "Reboot not verified within $TimeoutSeconds seconds. Last observation: $last; RebootRequests=1"
}

function SetHostDns($vmh,$fqdn,$dnsTxt,$domTxt,$apply){$desiredDns=SplitList $dnsTxt;$domain=(SplitList $domTxt|Select-Object -First 1);$short=($fqdn -split '\.')[0];if(!$apply){return Check 'N/A' 'Apply remediation is disabled; hostname/DNS/domain set skipped.'};try{$existing=VerifyHostDns $vmh $fqdn $dnsTxt $domTxt $null;if($existing.Status -eq 'Pass'){return Check Pass "Hostname, domain, and DNS already match; no settings changed. $($existing.Detail)"};$script:MutationAttempted=$true;Log "[$fqdn] Setting hostname/FQDN/domain/DNS. Host=$short Domain=$domain DNS=$(($desiredDns -join ','))";$powerCliOk=$false;$powerCliMsg='';try{$net=Get-VMHostNetwork -VMHost $vmh -ErrorAction Stop;Set-VMHostNetwork -Network $net -HostName $short -DomainName $domain -DnsAddress $desiredDns -ErrorAction Stop|Out-Null;$powerCliOk=$true}catch{$powerCliMsg=$_.Exception.Message;Log "[$fqdn] PowerCLI DNS set warning: $powerCliMsg. Applying ESX shell set/confirmation." WARN};$add=($desiredDns|ForEach-Object{"esxcli network ip dns server add -s $(Q $_) >/dev/null 2>&1 || true"}) -join "`n";$cmd=@'
esxcli system hostname set --host=__SHORT__ --domain=__DOMAIN__ --fqdn=__FQDN__ || true
for s in $(esxcli network ip dns server list 2>/dev/null | awk '/^[0-9]/{print $1}'); do esxcli network ip dns server remove -s $s >/dev/null 2>&1 || true; done
__ADD__
esxcli network ip dns search add -d __DOMAIN__ >/dev/null 2>&1 || true
'@;$cmd=$cmd.Replace('__SHORT__',(Q $short)).Replace('__DOMAIN__',(Q $domain)).Replace('__FQDN__',(Q $fqdn)).Replace('__ADD__',$add);EsxRetry $vmh $cmd 120 4|Out-Null;SleepUi 3;return Check 'Remediated' "Set requested. PowerCLISet=$powerCliOk; PowerCLIMessage=$powerCliMsg; DesiredHost=$short; DesiredFQDN=$fqdn; DesiredDomain=$domain; DesiredDNS=$(($desiredDns-join ','))"}catch{return Check 'Fail' $_.Exception.Message}}
function VerifyHostDns($vmh,$fqdn,$dnsTxt,$domTxt,$dnsReach){$desiredDns=SplitList $dnsTxt;$domain=(SplitList $domTxt|Select-Object -First 1);$short=($fqdn -split '\.')[0];try{$cmd=@'
echo HOST=$(hostname -s)
echo FQDN=$(hostname -f)
echo DOMAIN=$(hostname -d)
echo DNS_BEGIN
esxcli network ip dns server list 2>&1; echo DNS_COMMAND_RC=$?
echo DNS_END
'@;$o=(EsxRetry $vmh $cmd 60 4).StdOut;$curHost=([regex]::Match($o,'(?m)^HOST=(.*)$')).Groups[1].Value.Trim();$curFqdn=([regex]::Match($o,'(?m)^FQDN=(.*)$')).Groups[1].Value.Trim();$curDom=([regex]::Match($o,'(?m)^DOMAIN=(.*)$')).Groups[1].Value.Trim();$block=([regex]::Match($o,'(?s)DNS_BEGIN\s*(.*?)\s*DNS_END')).Groups[1].Value;$dnsRc=([regex]::Match($block,'(?m)^DNS_COMMAND_RC=(\d+)')).Groups[1].Value;$curDns=@();if($dnsRc -eq '0'){foreach($m in [regex]::Matches($block,'(?<![\d.])(?:\d{1,3}\.){3}\d{1,3}(?![\d.])')){ $ipObj=$null;if([System.Net.IPAddress]::TryParse($m.Value,[ref]$ipObj) -and $ipObj.AddressFamily -eq [System.Net.Sockets.AddressFamily]::InterNetwork){$curDns+=,$m.Value}};$curDns=@($curDns|Select-Object -Unique)};$okHost=(SafeLower $curHost)-eq(SafeLower $short);$okDom=(SafeLower $curDom)-eq(SafeLower $domain);$okFqdn=([string]::IsNullOrWhiteSpace($curFqdn) -or (SafeLower $curFqdn)-eq(SafeLower $fqdn) -or $curFqdn -eq $curHost);$dnsListOk=($dnsRc -eq '0' -and $curDns.Count -gt 0 -and (ContainsAll $desiredDns $curDns) -and (ContainsAll $curDns $desiredDns));$dnsFunctionalOk=if($null -eq $dnsReach){'Not tested yet'}elseif($dnsReach.Status -eq 'Pass'){'Pass'}else{'Fail'};$st=if($okHost -and $okDom -and $okFqdn -and $dnsListOk){'Pass'}else{'Fail'};$note=if($dnsRc -ne '0' -or $curDns.Count -eq 0){'Configured DNS server list could not be verified; functional DNS success is a separate check.'}elseif(!$dnsListOk){'Configured DNS server list differs from requested list.'}else{''};return Check $st "Host=$curHost DesiredHost=$short; FQDN=$curFqdn DesiredFQDN=$fqdn; CurrentDNS=$(($curDns-join ',')); DesiredDNS=$(($desiredDns-join ',')); DNSListOk=$dnsListOk; DNSCommandRC=$dnsRc; DNSFunctionalOk=$dnsFunctionalOk; CurrentDomain=$curDom; DesiredDomain=$domain; $note"}catch{return Check 'Fail' $_.Exception.Message}}
function TestDnsResolution($fqdn,$dnsTxt){
 $servers=@(SplitList $dnsTxt)
 if($servers.Count -eq 0){return Check Fail 'No DNS server was selected for forward/reverse validation.'}
 $expected=([string]$fqdn).TrimEnd('.').ToLowerInvariant()
 $evidence=New-Object System.Collections.Generic.List[string]
 $allOk=$true
 foreach($dnsServer in $servers){
  try{
   $forward=@(Resolve-DnsName -Name $fqdn -Type A -Server $dnsServer -DnsOnly -NoHostsFile -ErrorAction Stop |
     Where-Object {$_.IPAddress} | ForEach-Object {[string]$_.IPAddress} | Select-Object -Unique)
   if($forward.Count -eq 0){$allOk=$false;$evidence.Add("Server=$dnsServer; A=none; Error=no A record");continue}
   foreach($ip in $forward){
    try{
     $names=@(Resolve-DnsName -Name $ip -Type PTR -Server $dnsServer -DnsOnly -NoHostsFile -ErrorAction Stop |
       Where-Object {$_.NameHost} | ForEach-Object {([string]$_.NameHost).TrimEnd('.').ToLowerInvariant()} | Select-Object -Unique)
     $match=($names.Count -gt 0 -and @($names | Where-Object {$_ -ne $expected}).Count -eq 0)
     if(!$match){$allOk=$false}
     $evidence.Add("Server=$dnsServer; A=$ip; PTR=$(if($names.Count){$names -join ','}else{'none'}); Match=$match")
    }catch{$allOk=$false;$evidence.Add("Server=$dnsServer; A=$ip; PTR=lookup failed; Error=$($_.Exception.Message)")}
   }
  }catch{$allOk=$false;$evidence.Add("Server=$dnsServer; A=lookup failed; Error=$($_.Exception.Message)")}
 }
 return Check $(if($allOk){'Pass'}else{'Fail'}) ($evidence -join ' | ')
}
function TestDnsReach($vmh,$dnsTxt,$fqdn){
 $servers=@(SplitList $dnsTxt)
 if(!$servers.Count){return Check Fail 'No DNS servers configured.'}
 $mgmt=$null
 try{$mgmt=Get-VMHostNetworkAdapter -VMHost $vmh -VMKernel -ErrorAction Stop|Where-Object{$_.ManagementTrafficEnabled}|Select-Object -First 1}catch{}
 $iface=if($mgmt){[string]$mgmt.Name}else{'Unknown'}
 $source=if($mgmt){[string]$mgmt.IP}else{'Unknown'}
 $evidence=@();$functional=$true
 foreach($server in $servers){
  $cmd="nslookup $(Q $fqdn) $(Q $server) 2>&1; echo DNS_QUERY_RC=`$?"
  try{
   $r=EsxRetry $vmh $cmd 35 2
   $out=[string]$r.StdOut
   $query=([regex]::Match($out,'(?m)^DNS_QUERY_RC=(\d+)\s*$')).Groups[1].Value
   if($query -ne '0'){$functional=$false}
   $evidence+="Server=$server; DNSQuery=$(if($query -eq '0'){'Answered'}else{'Failed'}); ManagementVMK=$iface; ManagementIP=$source; SourceBinding=NotGuaranteed; Raw=$out"
  }catch{$functional=$false;$evidence+="Server=$server; DNSQuery=Failed; ManagementVMK=$iface; ManagementIP=$source; SourceBinding=NotGuaranteed; Error=$($_.Exception.Message)"}
 }
 Check $(if($functional){'Pass'}else{'Fail'}) ($evidence -join ' | ')
}
function TestNtpNetwork($vmh,$ntpTxt,$syncDetail){
 $mgmt=$null
 try{$mgmt=Get-VMHostNetworkAdapter -VMHost $vmh -VMKernel -ErrorAction Stop|Where-Object{$_.ManagementTrafficEnabled}|Select-Object -First 1}catch{}
 $iface=if($mgmt){[string]$mgmt.Name}else{'Unknown'}
 $source=if($mgmt){[string]$mgmt.IP}else{'Unknown'}
 $peers=@(SplitList $ntpTxt);$items=@();$allNames=$true
 foreach($peer in $peers){
  try{
   $ip=$null
   if([Net.IPAddress]::TryParse($peer,[ref]$ip)){$items+="Server=$peer; HostDNS=N/A (IP); ManagementVMK=$iface; ManagementIP=$source; SourceBinding=NotGuaranteed";continue}
   $r=EsxRetry $vmh "nslookup $(Q $peer) 2>&1; echo NTP_NAME_RC=`$?" 35 2
   $o=[string]$r.StdOut;$rc=([regex]::Match($o,'(?m)^NTP_NAME_RC=(\d+)\s*$')).Groups[1].Value
   if($rc -ne '0'){$allNames=$false}
   $items+="Server=$peer; HostDNS=$(if($rc -eq '0'){'Answered'}else{'Failed'}); ManagementVMK=$iface; ManagementIP=$source; SourceBinding=NotGuaranteed; Raw=$o"
  }catch{$allNames=$false;$items+="Server=$peer; HostDNS=Failed; ManagementVMK=$iface; ManagementIP=$source; Error=$($_.Exception.Message)"}
 }
 $reachable=[regex]::IsMatch([string]$syncDetail,'(?m)^\s*[+* -]?\S+\s+\S+\s+\d+\s+\S+\s+\S+\s+\d+\s+[1-9]\d*\b')
 $status=if(!$allNames){'Fail'}elseif($reachable){'Pass'}else{'Pending'}
 Check $status "NTP UDP/123: $(if($reachable){'NTP peer replies observed (reach > 0)'}else{'No NTP peer reply proven; UDP/123 blocked, routing, server, or service issue possible (not confirmed)'}). UDP nc port probe is not proof of reply. $(($items -join ' | '))"
}
function RestartNtp($h){try{$svc=Get-VMHostService -VMHost $h|Where-Object{$_.Key -eq 'ntpd'}|Select-Object -First 1;if($svc){Set-VMHostService -HostService $svc -Policy On|Out-Null;try{Stop-VMHostService -HostService $svc -Confirm:$false -ErrorAction SilentlyContinue|Out-Null}catch{};SleepUi 3;Start-VMHostService -HostService $svc -Confirm:$false -ErrorAction SilentlyContinue|Out-Null;SleepUi 10;return $true}}catch{};try{EsxRetry $h '(/etc/init.d/ntpd restart || /etc/init.d/ntp restart || true)' 60 3|Out-Null;SleepUi 10;return $true}catch{return $false}}
function GetShellNtp($h){try{$cmd=@'
echo NTP_BEGIN
esxcli system ntp get 2>/dev/null | sed -n 's/.*Servers:[ ]*//p' | tr ',' '\n' | sed 's/^ *//;s/ *$//'
echo NTP_END
'@;$o=(EsxRetry $h $cmd 60 3).StdOut;$b=([regex]::Match($o,'(?s)NTP_BEGIN\s*(.*?)\s*NTP_END')).Groups[1].Value;@(Norm @($b -split '[\r\n]+'|Where-Object{$_.Trim()}))}catch{@()}}
function TestSetNtp($vmh,$ntpTxt,$apply){$desired=@(Norm (SplitList $ntpTxt));$changed=$false;$restarted=$false;try{$cur=@(Norm @(Get-VMHostNtpServer -VMHost $vmh -ErrorAction SilentlyContinue));if(!$cur){$cur=@(GetShellNtp $vmh)};$match=EqualList $desired $cur;if($apply -and !$match){$script:MutationAttempted=$true;Log "[$($vmh.Name)] Setting NTP servers to $(($desired-join','))";try{foreach($s in $cur){try{Remove-VMHostNtpServer -VMHost $vmh -NtpServer $s -Confirm:$false|Out-Null}catch{}};foreach($s in $desired){Add-VMHostNtpServer -VMHost $vmh -NtpServer $s -Confirm:$false|Out-Null}}catch{};$csv=$desired -join ',';EsxRetry $vmh "esxcli system ntp set -e true -s $(Q $csv) || true" 60 3|Out-Null;$restarted=RestartNtp $vmh;$changed=$true;$cur=@(Norm @(Get-VMHostNtpServer -VMHost $vmh -ErrorAction SilentlyContinue));if(!$cur){$cur=@(GetShellNtp $vmh)};$match=EqualList $desired $cur};$svc=$null;try{$svc=Get-VMHostService -VMHost $vmh|Where-Object{$_.Key -eq 'ntpd'}|Select-Object -First 1}catch{};$running=if($svc){[bool]$svc.Running}else{$false};if($apply -and $match -and !$running){$script:MutationAttempted=$true;$restarted=RestartNtp $vmh;$svc=Get-VMHostService -VMHost $vmh -ErrorAction Stop|Where-Object{$_.Key -eq 'ntpd'}|Select-Object -First 1;$running=if($svc){[bool]$svc.Running}else{$false}};$sync=$false;$detail='';$maxNtpAttempts=20;$noReplyCount=0;$additionalRestarts=0;for($i=1;$i -le $maxNtpAttempts;$i++){Log "[$($vmh.Name)] Checking NTP sync attempt $i of $maxNtpAttempts...";try{$detail=((EsxRetry $vmh "(ntpq -pn 2>/dev/null || /usr/lib/vmware/ntp/bin/ntpq -pn 2>/dev/null || true)" 30 3).StdOut).Trim();if($detail -match '(?m)^\*\S+\s+\S+\s+\d+\s+\S+\s+\S+\s+\d+\s+([1-9]\d*)\b'){$sync=$true;break};if($detail -match '(?m)^\s*[+* -]?\S+\s+\S+\s+\d+\s+\S+\s+\S+\s+\d+\s+[1-9]\d*\b'){$noReplyCount=0}else{$noReplyCount++}}catch{$detail=$_.Exception.Message};if(!$sync -and $apply -and $noReplyCount -ge 3 -and $additionalRestarts -eq 0 -and !$changed -and !$restarted){Log "[$($vmh.Name)] Three consecutive NTP observations with no peer reply; restarting service once." WARN;$script:MutationAttempted=$true;$additionalRestarts++;$restarted=RestartNtp $vmh;$noReplyCount=0};if(!$sync -and ($i % 3 -eq 0)){
 Log "[$($vmh.Name)] NTP syncing. Please be patient. Attempt $i of $maxNtpAttempts; waiting for a selected peer (*)." INFO
};if($i -lt $maxNtpAttempts){SleepUi 10}};$cfg=if($match -and $running){if($changed){'Remediated'}else{'Pass'}}else{'Fail'};[pscustomobject]@{Status=$cfg;Detail="CurrentNTP=$(($cur-join ',')); DesiredNTP=$(($desired-join ',')); ConfigMatch=$match; ServiceRunning=$running; Changed=$changed; ServiceRestarted=$restarted; AdditionalRestarts=$additionalRestarts";SyncStatus=if($sync){'Pass'}elseif($apply -and ($changed -or $restarted)){'Pending'}else{'Fail'};SyncDetail="SelectedPeer=$sync; ObservationIntervalSeconds=10; Attempts=$([Math]::Min($i,$maxNtpAttempts))/$maxNtpAttempts; $(if(!$sync){'No selected NTP peer (*); synchronization is not proven.'}); $detail"}}catch{[pscustomobject]@{Status='Fail';Detail=$_.Exception.Message;SyncStatus='Fail';SyncDetail='Skipped due to NTP config failure.'}}}
function TestTimeDrift($vmh){
 try{
  $before=[DateTimeOffset]::UtcNow
  $cmd=@'
echo ESX_EPOCH=$(date -u +%s)
echo ESX_UTC=$(date -u '+%Y-%m-%dT%H:%M:%SZ')
'@
  $out=(EsxRetry $vmh $cmd 30 3).StdOut
  $after=[DateTimeOffset]::UtcNow
  $epoch=([regex]::Match($out,'(?m)^ESX_EPOCH=(\d+)')).Groups[1].Value
  $hostText=([regex]::Match($out,'(?m)^ESX_UTC=(.*)$')).Groups[1].Value.Trim()
  if(!$epoch){throw "Unable to parse ESX time. Output=$out"}
  $mid=$before.AddTicks([long](($after-$before).Ticks/2))
  $hostUtc=[DateTimeOffset]::FromUnixTimeSeconds([int64]$epoch)
  $drift=[math]::Round(($hostUtc.UtcDateTime-$mid.UtcDateTime).TotalSeconds,2)
  $limit=[double]$script:MaxDriftSeconds
  if($limit -le 0){throw 'Time drift threshold is not configured.'}
  $elapsed=[math]::Round(($after-$before).TotalSeconds,2)
  $status=if([math]::Abs($drift) -le $limit -and $elapsed -le [math]::Max(2,$limit)){'Pass'}else{'Fail'}
  [pscustomobject]@{Status=$status;Detail="ScriptMidpointUTC=$($mid.UtcDateTime.ToString('yyyy-MM-ddTHH:mm:ss.fffZ')); HostTimeUTC=$($hostUtc.UtcDateTime.ToString('yyyy-MM-ddTHH:mm:ssZ')); HostReportedUTC=$hostText; DriftSeconds=$drift; AbsoluteDriftSeconds=$([math]::Abs($drift)); ThresholdSeconds=$limit; SampleRoundTripSeconds=$elapsed; MaxSampleRoundTripSeconds=$([math]::Max(2,$limit)); HostEpochResolutionSeconds=1";DriftSeconds=$drift}
 }catch{[pscustomobject]@{Status='Fail';Detail=$_.Exception.Message;DriftSeconds=$null}}
}
function CertCheck($fqdn){
 $tcp=$null;$ssl=$null
 try{
  $tcp=New-Object Net.Sockets.TcpClient($fqdn,443)
  # This callback deliberately accepts the presented certificate: this check tests FQDN only.
  $ssl=New-Object Net.Security.SslStream($tcp.GetStream(),$false,({$true}))
  $ssl.AuthenticateAsClient($fqdn)
  $cert=New-Object Security.Cryptography.X509Certificates.X509Certificate2($ssl.RemoteCertificate)
  $names=@($cert.GetNameInfo([Security.Cryptography.X509Certificates.X509NameType]::DnsName,$false))
  try{$san=$cert.Extensions|Where-Object{$_.Oid.FriendlyName -eq 'Subject Alternative Name'}|Select-Object -First 1;if($san){$names+=($san.Format($true)-split '[,\r\n]+'|ForEach-Object{($_ -replace 'DNS Name=','').Trim()})}}catch{}
  $fq=$fqdn.ToLowerInvariant();$ok=@($names|ForEach-Object{(SafeLower $_)}|Where-Object{$_ -eq $fq}).Count -gt 0
  Check $(if($ok){'Pass'}else{'Fail'}) "NameOnly=True; ChainTrust=NotChecked; ExpiryValidation=NotChecked; RequiredLowercaseFQDN=$fq; Subject=$($cert.Subject); Names=$(@($names|Where-Object{$_}) -join ','); Expires=$($cert.NotAfter)"
 }catch{Check Fail "Certificate name check failed: $($_.Exception.Message)"}
 finally{if($ssl){$ssl.Dispose()};if($tcp){$tcp.Dispose()}}
}
function GenCert($vmh,$fqdn){try{$certCmd=EsxRetry $vmh '/sbin/generate-certificates' 180 3;if($certCmd.ExitStatus -ne 0){throw "Certificate generation failed: RC=$($certCmd.ExitStatus); Error=$($certCmd.StdErr)"};Check Remediated "Ran /sbin/generate-certificates for lowercase FQDN $($fqdn.ToLowerInvariant()). Mandatory reboot will reload hostd/vpxa."}catch{Check Fail $_.Exception.Message}}
# ESX 9.1 may not expose /Net/IPv6Enabled as an advanced setting. The global
# network ip get IPv6Enabled field is authoritative; advanced evidence is optional.
function Get-IPv6State([string]$Evidence){
 $globalMatch=[regex]::Match($Evidence,'(?im)^\s*IPv6\s*Enabled\s*:\s*(true|false)\s*$')
 $intMatch=[regex]::Match($Evidence,'(?im)^\s*Int Value\s*:\s*([01])\s*$')
 $global=if($globalMatch.Success){$globalMatch.Groups[1].Value.ToLowerInvariant()}else{''}
 $int=if($intMatch.Success){$intMatch.Groups[1].Value}else{''}
 $conflict=($global -in @('true','false') -and $int -in @('0','1') -and (($global -eq 'true') -ne ($int -eq '1')))
 # An advanced value by itself is not enough to establish runtime IPv6 state.
 [pscustomobject]@{GlobalValue=$global;IntValue=$int;Known=($global -in @('true','false') -and !$conflict);Enabled=($global -eq 'true');Conflict=$conflict;AdvancedAvailable=($int -in @('0','1'))}
}
function IPv6($vmh,$apply){
 $h=[string]$vmh.Name
 try{
  $evidenceCmd=@'
echo IPV6_EVIDENCE_BEGIN
esxcli network ip get 2>&1
esxcli system settings advanced list -o /Net/IPv6Enabled 2>&1
esxcli network ip interface ipv6 address list 2>&1
echo IPV6_EVIDENCE_END
'@
  $before=(EsxRetry $vmh $evidenceCmd 60 3).StdOut
  $state=Get-IPv6State $before
  if(!$state.Known){
   $reason=if($state.Conflict){'Conflicting global and advanced IPv6 evidence'}else{'Unknown IPv6 baseline: esxcli network ip get did not return IPv6Enabled'}
   $artifact=Save-DiagnosticArtifact IPV6 "$h-before-unknown" ([ordered]@{Host=$h;State=$state;Evidence=$before;Reason=$reason})
   Log "[$h] $reason; no IPv6 remediation attempted. Artifact=$artifact" ERROR
   return Check Fail "$reason; Global=$($state.GlobalValue); Advanced=$($state.IntValue); Artifact=$artifact"
  }
  if(!$apply){
   $artifact=Save-DiagnosticArtifact IPV6 "$h-validation" ([ordered]@{Host=$h;State=$state;Evidence=$before})
   return Check $(if($state.Enabled){'Fail'}else{'Pass'}) "GlobalIPv6Enabled=$($state.GlobalValue); AdvancedInt=$(if($state.AdvancedAvailable){$state.IntValue}else{'Not available'}); Artifact=$artifact"
  }
  if(!$state.Enabled){
   Log "[$h] IPv6 already disabled in global network IP settings; no IPv6 changes needed." PASS
   return Check Pass "GlobalIPv6Enabled=false; AdvancedInt=$(if($state.AdvancedAvailable){$state.IntValue}else{'Not available'}); no IPv6 change requested."
  }
  Log "[$h] IPv6 enabled in global network IP settings; requesting disable. AdvancedInt=$(if($state.AdvancedAvailable){$state.IntValue}else{'Not available'})." WARN
  # Only set the advanced option when it was actually present in the baseline.
  if($state.AdvancedAvailable){
   $cmd=@'
set +e
O1=$(esxcli network ip set --ipv6-enabled=false 2>&1); R1=$?
O2=$(esxcli system settings advanced set -o /Net/IPv6Enabled -i 0 2>&1); R2=$?
echo "NETWORK_IP_SET_RC=$R1 OUTPUT=$O1"
echo "ADVANCED_SET_RC=$R2 OUTPUT=$O2"
exit 0
'@
  }else{
   $cmd=@'
set +e
O1=$(esxcli network ip set --ipv6-enabled=false 2>&1); R1=$?
echo "NETWORK_IP_SET_RC=$R1 OUTPUT=$O1"
echo "ADVANCED_SET_SKIPPED=not exposed on this ESX host"
exit 0
'@
  }
  $disableOut=(EsxRetry $vmh $cmd 60 3).StdOut
  $networkRc=([regex]::Match($disableOut,'(?im)^NETWORK_IP_SET_RC=(\d+)')).Groups[1].Value
  $advancedRc=([regex]::Match($disableOut,'(?im)^ADVANCED_SET_RC=(\d+)')).Groups[1].Value
  Start-Sleep 2
  $after=(EsxRetry $vmh $evidenceCmd 60 3).StdOut
  $afterState=Get-IPv6State $after
  $verified=($networkRc -eq '0' -and $afterState.Known -and !$afterState.Enabled -and (!$state.AdvancedAvailable -or $advancedRc -eq '0'))
  $artifact=Save-DiagnosticArtifact IPV6 "$h-remediation" ([ordered]@{Host=$h;Before=[ordered]@{State=$state;Evidence=$before};ESXCLI=[ordered]@{NetworkIpSetRC=$networkRc;AdvancedSetRC=$advancedRc;Output=$disableOut};After=[ordered]@{State=$afterState;VerifiedDisabled=$verified;Evidence=$after};RebootRequired=$true})
  if($networkRc -ne '0' -or ($state.AdvancedAvailable -and $advancedRc -ne '0') -or $afterState.Conflict){
   Log "[$h] IPv6 disable command failed or state conflicted. NetworkRC=$networkRc; AdvancedRC=$advancedRc; Artifact=$artifact" ERROR
   return Check Fail "IPv6 disable command failed or state conflicted. NetworkRC=$networkRc; AdvancedRC=$advancedRc; Artifact=$artifact"
  }
  if(!$verified){
   Log "[$h] IPv6 disable command accepted; live state still $($afterState.GlobalValue). Reboot and post-reboot validation required. Artifact=$artifact" WARN
   return Check Remediated "IPv6 disable command accepted; pending reboot verification. NetworkRC=$networkRc; GlobalBefore=$($state.GlobalValue); GlobalImmediate=$($afterState.GlobalValue); Artifact=$artifact"
  }
  Log "[$h] IPv6 global setting verified disabled; reboot required to apply. Artifact=$artifact" PASS
  return Check Remediated "Global IPv6 setting changed from true to false; NetworkRC=$networkRc; AdvancedIntAfter=$(if($afterState.AdvancedAvailable){$afterState.IntValue}else{'Not available'}); RebootRequired=True; Artifact=$artifact"
 }catch{$artifact=Write-ExceptionDiagnostic $_ "IPV6-$h";Log "[$h] IPv6 exception: $($_.Exception.Message); Artifact=$artifact" ERROR;return Check Fail "IPv6 exception: $($_.Exception.Message); Artifact=$artifact"}
}

function CanonicalBase([string]$n){$n-replace ':\d+$',''}
function Vsan($vmh,$clean,[string]$intent){
 try{
  Assert-StorageIntent $intent ([bool]$clean)
  if($intent -eq 'External' -and $clean){return Check Fail 'Destructive vSAN cleanup blocked for external-storage host.'}
  if($clean){return InvokeVsanCleanup $vmh}
  $vdqResult=EsxRetry $vmh 'vdq -q -H' 180 3
  $vdq=([string]$vdqResult.StdOut).Trim()
  if($vdqResult.ExitStatus -ne 0 -or !$vdq -or $vdq -notmatch 'DiskResults:'){
   return Check Fail "vSAN disk evidence unavailable or vdq failed; cannot classify storage. RC=$($vdqResult.ExitStatus); Output=$vdq"
  }
  $entries=@((Get-EsxCli -VMHost $vmh -V2 -ErrorAction Stop).vsan.storage.list.Invoke())
  $owned=@($entries|Where-Object{
   $vals=@($_.Device,$_.VSANUUID,$_.VSANDiskGroupUUID,$_.VSANDiskGroupName,$_.DisplayName)|ForEach-Object{([string]$_).Trim()}|Where-Object{$_}
   $flags=@($_.IsMounted,$_.Usedbythishost,$_.InCMMDS)|ForEach-Object{([string]$_).Trim()}|Where-Object{$_ -match '^(?i:true|yes|1)$'}
   $vals.Count -gt 0 -or $flags.Count -gt 0
  })
  $esa=EsxRetry $vmh 'esxcli vsan storagepool list 2>&1; echo VSAN_POOL_RC=$?' 60 3
  $poolOutput=([string]$esa.StdOut).Trim()
  $poolRc=([regex]::Match($poolOutput,'(?m)^VSAN_POOL_RC=(\d+)\s*$')).Groups[1].Value
  $poolBody=($poolOutput -replace '(?m)^VSAN_POOL_RC=\d+\s*$','').Trim();if($poolBody -match '^(?i:no (?:vsan )?storage pools?(?: (?:found|configured))?\.?)$'){$poolBody=''}
  if($poolRc -ne '0'){return Check Fail "vSAN ESA storage-pool query unavailable; cannot prove absence of ownership. RC=$poolRc; Output=$poolBody"}
  $eligible=([regex]::Matches($vdq,'(?im)^\s*State\s*:\s*Eligible for use by VSAN\s*$')).Count
  if(!$eligible){$eligible=([regex]::Matches($vdq,'(?im)^\s*StoragePoolState\s*:\s*Eligible for use by Storage Pool\s*$')).Count}
  $vdqUuid=[regex]::IsMatch($vdq,'(?im)^[^\S\r\n]*VSANUUID[^\S\r\n]*:[^\S\r\n]*[^\s\r\n]+')
  $vdqVsanReason=[regex]::IsMatch($vdq,'(?im)^\s*(?:Reason|StoragePoolReason)\s*:\s*.*(?:in.use by vsan|vsan partition|vsan metadata|vsan disk group)')
  $hasOwnership=($owned.Count -gt 0 -or $vdqUuid -or $vdqVsanReason -or $poolBody.Length -gt 0)
  $evidence="StorageIntent=$intent; EligibleRawDisks=$eligible; OwnershipEntries=$($owned.Count); VdqVsanUuid=$vdqUuid; VdqVsanReason=$vdqVsanReason; ESAStoragePoolOutput=$poolBody; vdq=$vdq"
  if($intent -eq 'External'){
   if($hasOwnership){return Check Fail "External-storage host has vSAN ownership or identifiable residue; manual review required. $evidence"}
   return Check 'N/A' "External storage selected; no vSAN ownership or identifiable residue detected. Disk eligibility is not applicable. Partitioned disks are not automatically treated as vSAN residue. $evidence"
  }
  if($hasOwnership){return Check Fail "Existing vSAN ownership or residue found; manual review required before commissioning. $evidence"}
  if($eligible -gt 0){return Check Pass "vSAN storage selected; raw eligible disk(s) found and no ownership detected. $evidence"}
  return Check Fail "vSAN storage selected but no eligible raw vSAN disks were found. $evidence"
 }catch{return Check Fail "vSAN evidence/validation error; cannot assume N/A: $($_.Exception.Message)"}
}
function InvokeVsanCleanup($vmh){
 # Legacy destructive cleanup intentionally disabled pending a separate audited disk-identification workflow.
 return Check Fail 'Automated vSAN disk cleanup is disabled in this revision. Use an independently approved storage runbook.'
}
function RunHost($t){$server=$null;$vmh=$null;$checksStarted=$false;$h=SafeLower $t.TargetHost;$details=@();$reboot=$false;try{Log "[$h] Connecting with PowerCLI...";if(!(WaitTcp $h 443 120)){throw 'TCP/443 not reachable after 120 seconds.'};$server=ConnectRetry $h $t.Username $t.Password;$vmh=Get-VMHost -Server $server|Select-Object -First 1;if(!$vmh){throw 'No VMHost object returned.'};$script:CurrentShellUser=$t.Username;$script:CurrentShellPassword=$t.Password;if($rebootAuthorized){if(!(TestRebootPreflight $vmh $h)){throw 'Reboot preflight failed. No remediation attempted.'};$script:PreflightPassed=$true};$checksStarted=$true;$script:SshWasRunning=$null;$script:SshStartedByTool=$false;EnableSsh $vmh;$dnsSet=SetHostDns $vmh $h $txtDns.Text $txtDomains.Text ([bool]$chkApply.IsChecked);Log "[$h] Hostname/DNS/Domain Set: $($dnsSet.Status)";$dnsfr=TestDnsResolution $h $txtDns.Text;Log "[$h] DNS Forward/Reverse: $($dnsfr.Status)";$dnsr=TestDnsReach $vmh $txtDns.Text $h;Log "[$h] DNS Reachability: $($dnsr.Status)";$dnsVerify=VerifyHostDns $vmh $h $txtDns.Text $txtDomains.Text $dnsr;Log "[$h] Hostname/DNS/Domain Verify: $($dnsVerify.Status)";$ntp=TestSetNtp $vmh $txtNtp.Text ([bool]$chkApply.IsChecked);Log "[$h] NTP Config: $($ntp.Status)";Log "[$h] NTP Sync: $($ntp.SyncStatus)";$ntpNet=TestNtpNetwork $vmh $txtNtp.Text $ntp.SyncDetail;Log "[$h] NTP Network Diagnostics: $($ntpNet.Status)";$td=TestTimeDrift $vmh;Log "[$h] Time Drift: $($td.Status) $($td.DriftSeconds) seconds";$vs=Vsan $vmh ([bool]$chkClean.IsChecked) $script:StorageIntent;Log "[$h] vSAN: $($vs.Status)";$certBefore=CertCheck $h;Log "[$h] Certificate Before Generation: $($certBefore.Status)";$certGen=if(([bool]$chkApply.IsChecked) -and $certBefore.Status -ne 'Pass'){$script:MutationAttempted=$true;GenCert $vmh $h}else{Check 'N/A' 'Certificate already matched lowercase FQDN or remediation disabled.'};$certSummary=if($certBefore.Status -eq 'Pass'){'Pass'}elseif($certGen.Status -eq 'Remediated'){'Remediated'}else{'Fail'};Log "[$h] Certificate Final: $certSummary";$ver=Check $(if((VerCmp $vmh.Version '9.1.0') -ge 0){'Pass'}else{'Fail'}) "Installed ESX version: $($vmh.Version); required: 9.1.0 or greater";$ip6=IPv6 $vmh ([bool]$chkApply.IsChecked);if(([bool]$chkApply.IsChecked) -and ($ip6.Status -eq 'Remediated' -or $ip6.Detail -match 'remediation\.json')){$script:MutationAttempted=$true};Log "[$h] IPv6: $($ip6.Status)";$rows=@(('Hostname/DNS/Domain Set',$dnsSet),('Hostname/DNS/Domain Verify',$dnsVerify),('DNS Forward/Reverse',$dnsfr),('DNS Reachability',$dnsr),('NTP Network Diagnostics',$ntpNet),('NTP Config',$ntp),('NTP Sync',[pscustomobject]@{Status=$ntp.SyncStatus;Detail=$ntp.SyncDetail}),('Time Drift',$td),('vSAN',$vs),('Certificate Name Before Generation (trust not checked)',$certBefore),('Certificate Generation',$certGen),('ESXVersion',$ver),('IPv6',$ip6));foreach($r in $rows){$details+=[pscustomobject]@{Host=$h;Check=$r[0];Status=$r[1].Status;Detail=$r[1].Detail}};$statusList=@($dnsSet.Status,$dnsVerify.Status,$dnsfr.Status,$dnsr.Status,$ntpNet.Status,$ntp.Status,$ntp.SyncStatus,$td.Status,$vs.Status,$certSummary,$ver.Status,$ip6.Status);$overall=if(@($statusList|Where-Object{!(PassLike $_)}).Count -eq 0){'Pass'}else{'Fail'};[pscustomobject]@{Summary=[pscustomobject]@{Host=$h;FQDN=$h;HostnameDNSDomainSet=$dnsSet.Status;HostnameDNSDomainVerify=$dnsVerify.Status;DNSForwardReverse=$dnsfr.Status;DNSReachability=$dnsr.Status;NTPNetwork=$ntpNet.Status;NTPConfig=$ntp.Status;NTPSync=$ntp.SyncStatus;TimeDrift=$td.Status;TimeDriftSeconds=$td.DriftSeconds;vSAN=$vs.Status;Certificate=$certSummary;ESXVersion=$ver.Status;IPv6=$ip6.Status;Overall=$overall};Details=$details}}catch{Log "[$h] Connect/run failed: $($_.Exception.Message)" ERROR;$unrun=if($checksStarted){'Fail'}else{'Not run'};if(!$checksStarted){$script:LastSshCheck=Check 'Not run' 'SSH was not started; connection/preflight failed before host checks.'};[pscustomobject]@{Summary=[pscustomobject]@{Host=$h;FQDN=$h;HostnameDNSDomainSet=$unrun;HostnameDNSDomainVerify=$unrun;DNSForwardReverse=$unrun;DNSReachability=$unrun;NTPNetwork=$unrun;NTPConfig=$unrun;NTPSync=$unrun;TimeDrift=$unrun;TimeDriftSeconds=$null;vSAN=$unrun;Certificate=$unrun;ESXVersion=$unrun;IPv6=$unrun;Overall='Fail'};Details=@([pscustomobject]@{Host=$h;Check='Connect/Run';Status='Fail';Detail=$_.Exception.Message})}}finally{try{if($vmh -and $checksStarted){$script:LastSshCheck=DisableSsh $vmh}}catch{};if($server){Disconnect-VIServer -Server $server -Force -Confirm:$false -ErrorAction SilentlyContinue|Out-Null}}}
function AttachSshCheck($result,$h){
 if(!$result -or !$result.Summary){return $result}
 $check=$script:LastSshCheck
 if(!$check){$check=Check Fail 'SSH cleanup result unavailable after host checks; inspect host manually.'}
 $result.Details=@($result.Details)+@([pscustomobject]@{Host=$h;Check='SSH cleanup';Status=$check.Status;Detail=$check.Detail})
 $result.Summary|Add-Member -NotePropertyName SSHCleanup -NotePropertyValue $check.Status -Force
 $result.Summary|Add-Member -NotePropertyName StorageIntent -NotePropertyValue $script:StorageIntent -Force
 $result.Summary|Add-Member -NotePropertyName TimeDriftThresholdSeconds -NotePropertyValue $script:MaxDriftSeconds -Force
 if($check.Status -ne 'Pass'){$result.Summary.Overall='Fail'}
 $script:LastSshCheck=$null
 return $result
}
function HtmlSafe($value){[System.Net.WebUtility]::HtmlEncode([string]$value)}
function ChartBar($name,$count,$total,$color){
 $width=if($total -gt 0){[math]::Round(100*$count/$total,1)}else{0}
 '<div class="bar"><span>'+(HtmlSafe $name)+'</span><div class="track"><div class="fill" style="width:'+$width.ToString([Globalization.CultureInfo]::InvariantCulture)+'%;background:'+$color+'"></div></div><b>'+$count+'</b></div>'
}
function CheckResultBar($name,$passed,$applicable,$na,$notRun){
 $width=if($applicable -gt 0){[math]::Round(100*$passed/$applicable,1)}else{0}
 $display=if($applicable -gt 0){"$passed / $applicable"}elseif($na -gt 0 -and $notRun -eq 0){'N/A'}else{'Not run'}
 $notes=@();if($na -gt 0){$notes+="$na N/A"};if($notRun -gt 0){$notes+="$notRun not run"}
 $extra=if($notes.Count -gt 0 -and $applicable -gt 0){' <small>('+(HtmlSafe ($notes -join ', '))+')</small>'}else{''}
 '<div class="bar"><span>'+(HtmlSafe $name)+'</span><div class="track"><div class="fill" style="width:'+$width.ToString([Globalization.CultureInfo]::InvariantCulture)+'%;background:#268454"></div></div><b>'+(HtmlSafe $display)+'</b>'+$extra+'</div>'
}
function ExportHtmlReport($sum,$det){
 $dir=Join-Path $script:RunDir 'Reports';New-Item -ItemType Directory -Path $dir -Force|Out-Null
 $path=Join-Path $dir ('VCF91-ESX-Validation-'+(Get-Date -Format yyyyMMdd-HHmmss)+'-executive.html')
 $hosts=@($sum);$pass=@($hosts|Where-Object{$_.Overall -eq 'Pass'}).Count;$fail=@($hosts|Where-Object{$_.Overall -eq 'Fail'}).Count;$other=$hosts.Count-$pass-$fail
 $b=[System.Text.StringBuilder]::new()
 [void]$b.AppendLine(@'
<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>VCF 9.1 ESX Validation Report</title><style>
*{box-sizing:border-box}body{margin:0;background:#eef2f7;color:#1c3047;font:14px Segoe UI,Arial,sans-serif}header{background:#183858;color:white;padding:32px 5vw;border-bottom:5px solid #39a1d5}header h1{margin:0}main{max-width:1400px;margin:auto;padding:25px}.cards{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:15px}.card,details{background:white;padding:18px;border-radius:8px;box-shadow:0 2px 9px #0001;margin:12px 0}.kpis{display:flex;flex-wrap:wrap;gap:10px}.kpis div{background:white;padding:15px;min-width:135px;border-top:4px solid #2776ac}.kpis b{font-size:27px;display:block}.section{border-left:5px solid #2776ac;background:white;padding:12px;margin-top:24px;font-weight:800;text-transform:uppercase}.bar{display:flex;align-items:center;gap:10px;margin:13px 0}.bar span{width:165px;flex:none}.track{height:19px;background:#e7edf3;border-radius:10px;overflow:hidden;flex:1}.fill{height:100%;border-radius:10px}.bar b{width:30px;text-align:right}.validation-results .bar b{width:68px;flex:0 0 68px;white-space:nowrap;text-align:right}.validation-results .track{min-width:0}.scroll{overflow:auto}table{width:100%;border-collapse:collapse;font-size:12px}th{background:#183858;color:white;text-align:left;padding:9px}td{padding:9px;border-bottom:1px solid #e2e8ee;vertical-align:top;overflow-wrap:anywhere}tr:nth-child(even) td{background:#f8fafc}summary{cursor:pointer;font-weight:800}small{color:#627080}@media(max-width:800px){.cards{grid-template-columns:1fr}}@media print{body{background:white}details{break-inside:avoid}}
</style></head><body><header><h1>VCF 9.1 ESX Host Validation</h1><p>Executive summary and individual host results</p></header><main>
'@)
 [void]$b.AppendLine('<p><small>Generated '+(HtmlSafe (Get-Date -Format 'yyyy-MM-dd HH:mm:ss zzz'))+'. Charts reflect final host status only. Earlier validation phases remain in host details.</small></p><div class="kpis">')
 foreach($v in @(@('Hosts',$hosts.Count),@('Pass',$pass),@('Fail',$fail),@('Not tested',$other))){[void]$b.AppendLine('<div><b>'+$v[1]+'</b>'+$v[0]+'</div>')}
 [void]$b.AppendLine('</div><div class="section">Executive summary charts</div><div class="cards"><div class="card"><h3>Host outcomes</h3>')
 foreach($v in @(@('Pass',$pass,'#268454'),@('Fail',$fail,'#c03d3d'),@('Not tested',$other,'#73849a'))){[void]$b.AppendLine((ChartBar $v[0] $v[1] $hosts.Count $v[2]))}
 [void]$b.AppendLine('</div><div class="card validation-results"><h3>Validation results</h3>')
 $checks=[ordered]@{HostnameDNSDomainVerify='Hostname / DNS';DNSForwardReverse='DNS forward/reverse';DNSReachability='DNS reachability';NTPNetwork='NTP network';NTPConfig='NTP configuration';NTPSync='NTP synchronization';TimeDrift='Time drift';vSAN='vSAN';Certificate='Certificate';ESXVersion='ESX version';IPv6='IPv6'}
 foreach($key in $checks.Keys){
 $passed=@($hosts|Where-Object{[string]$_.$key -eq 'Pass'}).Count
 $failed=@($hosts|Where-Object{[string]$_.$key -eq 'Fail'}).Count
 $na=@($hosts|Where-Object{[string]$_.$key -match '^(?i:N/A|NA|Not Applicable)$'}).Count
 $notRun=$hosts.Count-$passed-$failed-$na
 [void]$b.AppendLine((CheckResultBar $checks[$key] $passed ($passed+$failed) $na $notRun))
}
 [void]$b.AppendLine('<small>Green bars show passed checks out of applicable checks. N/A and not-run checks are shown separately.</small></div></div><div class="section">Host summary</div><div class="card scroll"><table><tr><th>Host</th><th>Overall</th><th>DNS</th><th>NTP</th><th>vSAN</th><th>Certificate</th><th>ESX version</th><th>IPv6</th></tr>')
 foreach($r in $hosts){[void]$b.AppendLine('<tr><td>'+(HtmlSafe $r.Host)+'</td><td>'+(HtmlSafe $r.Overall)+'</td><td>'+(HtmlSafe $r.HostnameDNSDomainVerify)+'</td><td>'+(HtmlSafe $r.NTPSync)+'</td><td>'+(HtmlSafe $r.vSAN)+'</td><td>'+(HtmlSafe $r.Certificate)+'</td><td>'+(HtmlSafe $r.ESXVersion)+'</td><td>'+(HtmlSafe $r.IPv6)+'</td></tr>')}
 [void]$b.AppendLine('</table></div><div class="section">Individual host results</div>')
 foreach($r in $hosts){$h=[string]$r.Host;[void]$b.AppendLine('<details><summary>'+(HtmlSafe $h)+' | '+(HtmlSafe $r.Overall)+'</summary><div class="scroll"><table><tr><th>Check / phase</th><th>Status</th><th>Evidence</th></tr>')
 foreach($d in @($det|Where-Object{$_.Host -eq $h})){[void]$b.AppendLine('<tr><td>'+(HtmlSafe $d.Check)+'</td><td>'+(HtmlSafe $d.Status)+'</td><td>'+(HtmlSafe $d.Detail)+'</td></tr>')}
 [void]$b.AppendLine('</table></div></details>')
 }
 [void]$b.AppendLine('</main></body></html>')
 [System.IO.File]::WriteAllText($path,$b.ToString(),[System.Text.UTF8Encoding]::new($false));Log "Executive HTML report: $path" PASS;return $path
}
function ExportReport($sum,$det){
 $base=Join-Path $script:RunDir ("VCF91-ESX-Validation-"+(Get-Date -Format yyyyMMdd-HHmmss))
 if(@($sum).Count -eq 0){throw 'No worker results were collected.'}
 if(HasMod ImportExcel){try{
  Import-Module ImportExcel -ErrorAction Stop|Out-Null
  $p="$base.xlsx"
  $sum|Export-Excel -Path $p -WorksheetName Hosts -AutoSize -ErrorAction Stop
  if(@($det).Count -gt 0){$det|Export-Excel -Path $p -WorksheetName Details -AutoSize -Append -ErrorAction Stop}
  $script:LastReportPath=$p;Log "Report saved: $p" PASS;return $p
 }catch{Log "Excel report failed; falling back to CSV: $($_.Exception.Message)" WARN}}
 $p="$base-hosts.csv";$sum|Export-Csv -NoTypeInformation -LiteralPath $p -ErrorAction Stop
 if(@($det).Count -gt 0){$det|Export-Csv -NoTypeInformation -LiteralPath "$base-details.csv" -ErrorAction Stop}
 $script:LastReportPath=$p;Log "CSV report saved: $p" PASS;return $p
}

function AddPoolName($n,$id=$null,$raw=$null){$n=([string]$n).Trim();if(!$n){return};foreach($i in @($cmbPool.Items)){if([string]$i.Content -eq $n){return}};$ci=New-Object System.Windows.Controls.ComboBoxItem;$ci.Content=$n;$ci.Tag=[pscustomobject]@{name=$n;id=$id;raw=$raw};[void]$cmbPool.Items.Add($ci)}
function InvokeJson($m,$u,$h=@{},$b=$null){$p=@{Method=$m;Uri=$u;Headers=$h;SkipCertificateCheck=$true;ErrorAction='Stop'};if($null-ne$b){$p.Body=($b|ConvertTo-Json -Depth 50);$p.ContentType='application/json'};$wr=Invoke-WebRequest @p;if($wr.Content){$wr.Content|ConvertFrom-Json}}
function ConnectPools{$fqdn=([string]$txtSddc.Text).Trim();$u=([string]$txtSddcUser.Text).Trim();$p=[string]$txtSddcPass.Password;if(!$fqdn -or !$u -or !$p){throw 'SDDC Manager FQDN, user, and password are required.'};$base=if($fqdn -match '^https?://'){$fqdn.TrimEnd('/')}else{"https://$fqdn"};$cmbPool.Items.Clear();$tok=InvokeJson POST "$base/v1/tokens" @{} @{username=$u;password=$p};$token=@($tok.accessToken,$tok.access_token,$tok.token,$tok.idToken,$tok.id_token)|Where-Object{$_}|Select-Object -First 1;if(!$token){throw 'Token response did not include a token.'};$np=InvokeJson GET "$base/v1/network-pools" @{Authorization="Bearer $token";Accept='application/json'};$items=@($np.elements);if(!$items){$items=@($np.networkPools)};if(!$items){$items=@($np.items)};foreach($pool in $items){$name=@($pool.name,$pool.networkPoolName,$pool.displayName)|Where-Object{$_}|Select-Object -First 1;$id=@($pool.id,$pool.networkPoolId,$pool.uuid)|Where-Object{$_}|Select-Object -First 1;if($name){AddPoolName $name $id $pool}};if($cmbPool.Items.Count){$cmbPool.SelectedIndex=0;Log "Loaded $($cmbPool.Items.Count) Network Pool name(s) from $base.";[System.Windows.MessageBox]::Show('Connected. Network Pool inventory loaded.','Connected')|Out-Null}else{throw 'No Network Pool names returned.'}}
function StorageCode($s){switch -Regex($s){'^vSAN OSA$'{'VSAN';break}'^vSAN Remote$'{'VSAN_REMOTE';break}'^vSAN ESA$'{'VSAN_ESA';break}'^vSAN Max$'{'VSAN_MAX';break}'^NFS$'{'NFS';break}'^VMFS on FC$'{'VMFS_FC';break}'^vVol$'{'VVOL';break}default{$s}}}
function GenJson{$targets=@(TargetRows);if(!$targets){throw 'No valid hosts.'};Assert-TargetNames $targets $txtDomains.Text;Assert-StorageIntent (Get-StorageIntent) $false;$missing=@($targets|Where-Object{[string]::IsNullOrWhiteSpace($_.Password)}|ForEach-Object{$_.TargetHost});if($missing.Count){throw "Enter an ESXi password for every target host before generating JSON: $($missing -join ', ')"};$np=if($cmbPool.SelectedItem -and $cmbPool.SelectedItem.Tag){[string]$cmbPool.SelectedItem.Tag.name}else{([string]$cmbPool.Text).Trim()};if(!$np){throw 'Select or type Network Pool Name.'};if(!$cmbStorage.SelectedItem){throw 'Select JSON storage type explicitly.'};$storage=([System.Windows.Controls.ComboBoxItem]$cmbStorage.SelectedItem).Content.ToString();$code=StorageCode $storage;$jsonIntent=if($code -match '^VSAN'){'vSAN'}else{'External'};if($jsonIntent -ne (Get-StorageIntent)){throw "JSON storage type '$storage' conflicts with selected host storage intent."};$hosts=@();foreach($t in $targets){$hosts += [ordered]@{fqdn=$t.TargetHost;username=$t.Username;storageType=$code;password=$t.Password;networkPoolName=$np;vvolStorageProtocolType=''}};$path=Join-Path $script:RunDir ("bulk-commission-hosts-"+(Get-Date -Format yyyyMMdd-HHmmss)+'.json');([ordered]@{hosts=$hosts})|ConvertTo-Json -Depth 50|Out-File $path -Encoding UTF8;Log "Bulk commission JSON generated: $path";try{Start-Process notepad.exe $path}catch{Invoke-Item $path}}

function InitializeUiLogTail{try{$script:UiLogSeen=@(Get-Content -LiteralPath $script:LogFile -ErrorAction SilentlyContinue).Count}catch{$script:UiLogSeen=0}}
function SyncUiLogTail{
 if($WorkerInput -or !$script:txtLog -or !(Test-Path -LiteralPath $script:LogFile)){return}
 try{
  $lines=@(Get-Content -LiteralPath $script:LogFile -ErrorAction Stop)
  if($script:UiLogSeen -gt $lines.Count){$script:UiLogSeen=0}
  if($lines.Count -gt $script:UiLogSeen){
   foreach($line in @($lines[$script:UiLogSeen..($lines.Count-1)])){$script:txtLog.AppendText([string]$line+[Environment]::NewLine)}
   $script:UiLogSeen=$lines.Count;$script:txtLog.ScrollToEnd();DoEvents
  }
 }catch{}
}
if($WorkerInput){
 try{
  $j=Import-Clixml -LiteralPath $WorkerInput -ErrorAction Stop
  if(!$j.ProtectedPassword){throw 'Protected worker password missing.'}
  $securePassword=ConvertTo-SecureString -String ([string]$j.ProtectedPassword) -ErrorAction Stop
  $j.Target|Add-Member -NotePropertyName Password -NotePropertyValue ([pscredential]::new([string]$j.Target.Username,$securePassword).GetNetworkCredential().Password) -Force
  $script:RunDir=$j.RunDir;$script:LogFile=$j.LogFile
  $script:DebugArtifactDir=Join-Path $script:RunDir 'Debug-Artifacts'
  $txtDns=[pscustomobject]@{Text=$j.Dns};$txtDomains=[pscustomobject]@{Text=$j.Domains}
  $txtNtp=[pscustomobject]@{Text=$j.Ntp}
  if($j.Clean){throw 'Automated vSAN cleanup is disabled in v1.7.11. Do not select Clean vSAN residue.'}
  if($j.Reboot -ne $j.Apply){throw 'Worker mode mismatch: reboot authorization must match Apply remediation.'}
  $chkApply=[pscustomobject]@{IsChecked=[bool]$j.Apply}
  $chkClean=[pscustomobject]@{IsChecked=[bool]$j.Clean}
  $rebootAuthorized=[bool]$j.Apply
   $script:PreflightPassed=$false;$script:MutationAttempted=$false;$script:MaxDriftSeconds=[double]$j.MaxDriftSeconds;$script:StorageIntent=[string]$j.StorageIntent
  Assert-StorageIntent $script:StorageIntent ([bool]$j.Clean)
  $h=SafeLower $j.Target.TargetHost
  Assert-TargetNames @($j.Target) $j.Domains
  if(!$j.Apply){
   Log "[$h] Validation-only phase: no reboot will be requested."
   $script:LastSshCheck=$null;$result=RunHost $j.Target;$result=AttachSshCheck $result $h
   $result.Summary|Add-Member -NotePropertyName Phase -NotePropertyValue 'Validation only' -Force
   $result.Summary|Add-Member -NotePropertyName RebootStatus -NotePropertyValue 'N/A' -Force
   $result.Summary|Add-Member -NotePropertyName PostRebootStatus -NotePropertyValue 'N/A' -Force
  }else{
   Log "[$h] Phase 1/3: applying remediation and recording pre-reboot results."
   $script:LastSshCheck=$null;$first=RunHost $j.Target;$first=AttachSshCheck $first $h
   $preOverall=$first.Summary.Overall
   $detail=@($first.Details|ForEach-Object{[pscustomobject]@{Host=$_.Host;Check="Pre-reboot / $($_.Check)";Status=$_.Status;Detail=$_.Detail}})
   $changes=@($first.Details|Where-Object{$_.Status -eq 'Remediated'}|ForEach-Object{$_.Check})
   if(!$script:PreflightPassed){$rebootResult=Check 'Not run' 'No reboot requested: connection or powered-on VM preflight did not pass.'}
   elseif(!$changes.Count -and !$script:MutationAttempted){$rebootResult=Check 'Not required' 'No host remediation was performed; no reboot requested.';Log "[$h] No changes; skipping reboot." PASS}
   else{Log "[$h] Remediation recorded or attempted ($($changes -join ', ')); issuing one reboot."; $rebootResult=InvokeSingleRebootAndWait $j.Target 600}
   $detail+=,[pscustomobject]@{Host=$h;Check='Reboot verification';Status=$rebootResult.Status;Detail=$rebootResult.Detail}
   if($rebootResult.Status -eq 'Not required'){
    $summary=$first.Summary
    $summary|Add-Member -NotePropertyName Phase -NotePropertyValue 'Remediation mode / no changes' -Force
    $summary|Add-Member -NotePropertyName PreRebootOverall -NotePropertyValue $preOverall -Force
    $summary|Add-Member -NotePropertyName RebootStatus -NotePropertyValue 'Not required' -Force
    $summary|Add-Member -NotePropertyName PostRebootStatus -NotePropertyValue 'Not required' -Force
    $result=[pscustomobject]@{Summary=$summary;Details=$detail}
   }elseif($rebootResult.Status -eq 'Pass'){
    Log "[$h] Phase 3/3: exactly one fresh validation-only pass; remediation and reboot are disabled."
    $chkApply.IsChecked=$false;$chkClean.IsChecked=$false;$rebootAuthorized=$false
    $script:LastSshCheck=$null;$script:PostRebootValidation=$true;try{$second=RunHost $j.Target;$second=AttachSshCheck $second $h}finally{$script:PostRebootValidation=$false}
    $detail+=@($second.Details|ForEach-Object{[pscustomobject]@{Host=$_.Host;Check="Post-reboot / $($_.Check)";Status=$_.Status;Detail=$_.Detail}})
    $summary=$second.Summary
    $summary|Add-Member -NotePropertyName Phase -NotePropertyValue 'Post-reboot final' -Force
    $summary|Add-Member -NotePropertyName PreRebootOverall -NotePropertyValue $preOverall -Force
    $summary|Add-Member -NotePropertyName RebootStatus -NotePropertyValue 'Verified' -Force
    $summary|Add-Member -NotePropertyName PostRebootStatus -NotePropertyValue $second.Summary.Overall -Force
    $result=[pscustomobject]@{Summary=$summary;Details=$detail}
    Log "[$h] Workflow complete. Post-reboot overall=$($summary.Overall). No further action will run."
   }else{
    $summary=$first.Summary
    $summary.Overall='Fail'
    $summary|Add-Member -NotePropertyName Phase -NotePropertyValue $(if($rebootResult.Status -eq 'Not run'){'Preflight blocked'}else{'Reboot not verified'}) -Force
    $summary|Add-Member -NotePropertyName PreRebootOverall -NotePropertyValue $preOverall -Force
    $summary|Add-Member -NotePropertyName RebootStatus -NotePropertyValue $(if($rebootResult.Status -eq 'Not run'){'Not run'}else{'Fail'}) -Force
    $summary|Add-Member -NotePropertyName PostRebootStatus -NotePropertyValue 'Not run' -Force
    $result=[pscustomobject]@{Summary=$summary;Details=$detail}
    Log "[$h] Workflow ended without post-reboot validation: $($rebootResult.Detail)" ERROR
   }
  }
  $result|Export-Clixml -LiteralPath $WorkerOutput -Depth 20 -ErrorAction Stop
  exit 0
 }catch{
  $errorText=$_.Exception.ToString()
  try{if($script:LogFile){Log "Worker orchestration error: $errorText" ERROR}}catch{}
  try{[pscustomobject]@{Error=$errorText}|Export-Clixml -LiteralPath $WorkerOutput -ErrorAction Stop}catch{}
  exit 1
 }
}
function WorkerFailure($h,$message){
 [pscustomobject]@{Summary=[pscustomobject]@{Host=$h;FQDN=$h;Overall='Fail';Phase='Worker failure';RebootStatus='Unknown';PostRebootStatus='Not run'};Details=@([pscustomobject]@{Host=$h;Check='Worker';Status='Fail';Detail=$message})}
}
function CompleteWorker($w){
 $h=[string]$w.T.TargetHost;$r=$null
 try{
  if(!(Test-Path -LiteralPath $w.O)){throw 'Worker produced no result file.'}
  $r=Import-Clixml -LiteralPath $w.O -ErrorAction Stop
  if(!$r -or !$r.Summary){throw $(if($r -and $r.Error){[string]$r.Error}else{'Worker result missing Summary.'})}
 }catch{
  $stderr=if(Test-Path -LiteralPath $w.StdErr){[string](Get-Content -LiteralPath $w.StdErr -Raw -ErrorAction SilentlyContinue)}else{''}
  $message="Worker result failure: $($_.Exception.Message); ExitCode=$($w.P.ExitCode); stderr=$stderr; stderr file=$($w.StdErr)"
  Log "[$h] $message" ERROR
  $r=WorkerFailure $h $message
 }finally{
  try{Remove-Item -LiteralPath $w.I -Force -ErrorAction SilentlyContinue}catch{}
  [void]$script:ActiveWorkers.Remove($w)
 }
 [void]$script:WorkerResults.Add($r)
 $script:CompletedCount++
 try{UpdateRunStatus}catch{Log "Progress warning: $($_.Exception.Message)" WARN}
 Log "[$h] Worker completed. Overall=$($r.Summary.Overall); active=$($script:ActiveWorkers.Count)."
}
function DrainWorkers{
 while($script:ActiveWorkers.Count -gt 0){
  foreach($w in @($script:ActiveWorkers.ToArray())){
   try{
    if(!$w -or !$w.P){throw 'Missing process handle.'}
    $w.P.Refresh()
    if($w.P.HasExited){CompleteWorker $w}
   }catch{
    Log "Collector warning: $($_.Exception.ToString())" ERROR
    if($w -and $w.P){try{$w.P.Refresh();if(!$w.P.HasExited){continue}}catch{continue}}
    if($w){[void]$script:ActiveWorkers.Remove($w);[void]$script:WorkerResults.Add((WorkerFailure $w.T.TargetHost $_.Exception.Message));$script:CompletedCount++}
   }
  }
  SyncUiLogTail;DoEvents
  if($script:ActiveWorkers.Count -gt 0){Start-Sleep -Milliseconds 350}
 }
}
function InvokeParallelHosts($targets,[int]$throttle){
 $throttle=[Math]::Max(3,[Math]::Min(5,$throttle))
 $script:CompletedCount=0;$script:TotalCount=@($targets).Count
 $script:WorkerResults=[Collections.ArrayList]::new()
 $script:ActiveWorkers=[Collections.ArrayList]::new()
 $queue=[Collections.Generic.Queue[object]]::new()
 foreach($target in $targets){$queue.Enqueue($target)}
 $script:QueuedWorkers=$queue.Count
 $pwsh=(Get-Process -Id $PID).Path
 InitializeUiLogTail
 try{
  while($queue.Count -gt 0 -or $script:ActiveWorkers.Count -gt 0){
   if($script:StopRequested -and $queue.Count -gt 0){
    while($queue.Count -gt 0){$t=$queue.Dequeue();[void]$script:WorkerResults.Add([pscustomobject]@{Summary=[pscustomobject]@{Host=$t.TargetHost;FQDN=$t.TargetHost;Overall='Skipped'};Details=@([pscustomobject]@{Host=$t.TargetHost;Check='Queue';Status='Skipped';Detail='Operator stopped queuing new hosts.'})});$script:CompletedCount++}
    $script:QueuedWorkers=0;UpdateRunStatus
   }
   while($queue.Count -gt 0 -and $script:ActiveWorkers.Count -lt $throttle -and !$script:StopRequested){
    $t=$queue.Dequeue();$script:QueuedWorkers=$queue.Count
    $id=[guid]::NewGuid().ToString('N');$i=Join-Path $script:RunDir "worker-$id-in.xml";$o=Join-Path $script:RunDir "worker-$id-out.xml"
    $stderr=Join-Path $script:RunDir "worker-$id-stderr.log";$stdout=Join-Path $script:RunDir "worker-$id-stdout.log"
    try{
     [pscustomobject]@{Target=[pscustomobject]@{TargetHost=$t.TargetHost;Username=$t.Username};StorageIntent=(Get-StorageIntent);MaxDriftSeconds=$txtMaxDrift.Text;ProtectedPassword=(ConvertTo-SecureString -String ([string]$t.Password) -AsPlainText -Force|ConvertFrom-SecureString);Dns=$txtDns.Text;Domains=$txtDomains.Text;Ntp=$txtNtp.Text;Apply=[bool]$chkApply.IsChecked;Clean=[bool]$chkClean.IsChecked;Reboot=[bool]$chkApply.IsChecked;RunDir=$script:RunDir;LogFile=$script:LogFile}|Export-Clixml -LiteralPath $i -Depth 10 -ErrorAction Stop
     $workerArgs=@('-NoProfile','-NonInteractive','-ExecutionPolicy','Bypass','-File',('"'+$PSCommandPath+'"'),'-WorkerInput',('"'+$i+'"'),'-WorkerOutput',('"'+$o+'"'))
     $p=Start-Process -FilePath $pwsh -ArgumentList $workerArgs -WindowStyle Hidden -PassThru -RedirectStandardError $stderr -RedirectStandardOutput $stdout -ErrorAction Stop
     if(!$p){throw 'Worker process handle not returned.'}
     [void]$script:ActiveWorkers.Add([pscustomobject]@{P=$p;T=$t;I=$i;O=$o;StdErr=$stderr;StdOut=$stdout})
     Log "[$($t.TargetHost)] Worker started. PID=$($p.Id); active=$($script:ActiveWorkers.Count)/$throttle"
    }catch{
     $message="Worker launch failed: $($_.Exception.ToString())";Log "[$($t.TargetHost)] $message" ERROR
     Remove-Item -LiteralPath $i -Force -ErrorAction SilentlyContinue
     [void]$script:WorkerResults.Add((WorkerFailure $t.TargetHost $message));$script:CompletedCount++
    }
    UpdateRunStatus;SyncUiLogTail
   }
   # Poll one cycle, not a blocking drain, so queued workers can launch as slots open.
   foreach($w in @($script:ActiveWorkers.ToArray())){
    try{$w.P.Refresh();if($w.P.HasExited){CompleteWorker $w}}catch{
     Log "Collector warning: $($_.Exception.ToString())" ERROR
     if($w -and $w.P){try{$w.P.Refresh();if(!$w.P.HasExited){continue}}catch{continue}}
     if($w){[void]$script:ActiveWorkers.Remove($w);[void]$script:WorkerResults.Add((WorkerFailure $w.T.TargetHost $_.Exception.Message));$script:CompletedCount++}
    }
   }
   SyncUiLogTail;DoEvents;Start-Sleep -Milliseconds 250
  }
 }catch{
  $script:StopRequested=$true
  Log "Collector exception: $($_.Exception.ToString()). Draining active workers." ERROR
  DrainWorkers
  while($queue.Count -gt 0){$t=$queue.Dequeue();[void]$script:WorkerResults.Add((WorkerFailure $t.TargetHost 'Not started: collector error.'));$script:CompletedCount++}
 }finally{
  $script:QueuedWorkers=0
  if($script:ActiveWorkers.Count -gt 0){DrainWorkers}
  SyncUiLogTail
 }
}

function Show-HostRunReview([object[]]$Targets,[bool]$Apply,[bool]$Cleanup){
 $x=@'
<Window xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation" xmlns:x="http://schemas.microsoft.com/winfx/2006/xaml" Title="Review Host Run" Width="760" Height="610" MinWidth="620" MinHeight="490" WindowStartupLocation="CenterOwner" ResizeMode="CanResizeWithGrip" Background="#071015" Foreground="#E6E6E6" FontFamily="Segoe UI" ShowInTaskbar="False">
<Grid Margin="18"><Grid.RowDefinitions><RowDefinition Height="Auto"/><RowDefinition Height="Auto"/><RowDefinition Height="*"/><RowDefinition Height="Auto"/><RowDefinition Height="Auto"/></Grid.RowDefinitions>
<Border x:Name="banner" Background="#10242D" BorderBrush="#F2C94C" BorderThickness="1" CornerRadius="5" Padding="15"><StackPanel><TextBlock x:Name="heading" FontSize="20" FontWeight="SemiBold" Foreground="#F2C94C"/><TextBlock x:Name="subtitle" Margin="0,6,0,0" Foreground="#B8CBD3" TextWrapping="Wrap"/></StackPanel></Border>
<Border Grid.Row="1" Background="#0D1B22" BorderBrush="#314A57" BorderThickness="1" CornerRadius="4" Margin="0,12,0,0" Padding="12"><StackPanel><TextBlock x:Name="mode" FontSize="15" FontWeight="SemiBold" Foreground="#76C7D8"/><TextBlock x:Name="summary" Margin="0,6,0,0" Foreground="#E6E6E6" TextWrapping="Wrap"/></StackPanel></Border>
<Grid Grid.Row="2" Margin="0,12,0,0"><Grid.RowDefinitions><RowDefinition Height="Auto"/><RowDefinition Height="*"/><RowDefinition Height="Auto"/><RowDefinition Height="*"/></Grid.RowDefinitions><TextBlock Text="TARGET HOSTS" Foreground="#76C7D8" FontWeight="SemiBold"/><TextBox x:Name="hosts" Grid.Row="1" Margin="0,5,0,10" IsReadOnly="True" VerticalScrollBarVisibility="Auto" Background="#071015" Foreground="#E6E6E6" BorderBrush="#314A57" Padding="9" FontFamily="Consolas"/><TextBlock Grid.Row="2" Text="OPERATIONAL SAFETY" Foreground="#F2C94C" FontWeight="SemiBold"/><TextBox x:Name="risk" Grid.Row="3" Margin="0,5,0,0" IsReadOnly="True" TextWrapping="Wrap" VerticalScrollBarVisibility="Auto" Background="#071015" Foreground="#E6E6E6" BorderBrush="#314A57" Padding="9"/></Grid>
<CheckBox x:Name="ack" Grid.Row="3" Content="I reviewed the target hosts, run mode, and operational impact." Foreground="#F2C94C" Margin="0,14,0,0" FontWeight="SemiBold"/>
<StackPanel Grid.Row="4" Orientation="Horizontal" HorizontalAlignment="Right" Margin="0,15,0,0"><Button x:Name="cancel" Content="Cancel" Width="110" Height="34" Margin="0,0,10,0" Background="#2B3740" Foreground="#F1F4F6" BorderBrush="#5F7482" IsCancel="True"/><Button x:Name="proceed" Content="Start run" Width="155" Height="34" Background="#2B3740" Foreground="#F1F4F6" BorderBrush="#F2C94C" FontWeight="SemiBold" IsDefault="True" IsEnabled="False"/></StackPanel>
</Grid></Window>
'@
 $dialog=[Windows.Markup.XamlReader]::Parse($x)
 if($w){$dialog.Owner=$w}
 $dialog.FindName('heading').Text=if($Apply){'Confirm host remediation'}else{'Review validation run'}
 $dialog.FindName('subtitle').Text=if($Apply){'One reboot only if remediation is performed; review eligible hosts.'}else{'Read-only host checks; temporary SSH service changes may occur.'}
 $dialog.FindName('mode').Text=if($Apply){'REMEDIATION'}else{'VALIDATION ONLY'}
 $dialog.FindName('summary').Text="Hosts: $(@($Targets).Count)    Reboot: $(if($Apply){'If changes occur: once per eligible host'}else{'No'})    vSAN cleanup: $(if($Cleanup){'YES - destructive'}else{'No'})"
 $dialog.FindName('summary').Text+='    Storage intent: '+(Get-StorageIntent)+'    Max drift: '+$txtMaxDrift.Text+'s    Shared password: '+[bool]$chkSharedPassword.IsChecked;$dialog.FindName('hosts').Text=(@($Targets|ForEach-Object{$_.TargetHost}) -join [Environment]::NewLine)
 $dialog.FindName('risk').Text=if($Apply){'Automated vSAN cleanup is disabled in this review build. Before any remediation or reboot, the tool checks for zero powered-on VMs. Standalone hosts do not require maintenance mode. An eligible host receives ONE reboot request only if remediation occurred, even if another pre-reboot check fails. The tool waits up to 10 minutes for a changed boot time, then performs ONE validation-only pass. It does not retry remediation or reboot. Disabling IPv6 may affect vMotion. Confirm change approval and the exact host list.'}else{'No host remediation, disk cleanup, or reboot is requested. SSH may be enabled temporarily for validation and disabled afterward.'}
 if($Cleanup){throw 'Automated vSAN cleanup is disabled in this review build.'}
 $ack=$dialog.FindName('ack');$proceed=$dialog.FindName('proceed')
 $ack.Add_Checked({$proceed.IsEnabled=$true});$ack.Add_Unchecked({$proceed.IsEnabled=$false})
 $proceed.Add_Click({$dialog.DialogResult=$true})
 $dialog.FindName('cancel').Add_Click({$dialog.DialogResult=$false})
 return ($dialog.ShowDialog() -eq $true)
}

$xaml=@'
<Window xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation" xmlns:x="http://schemas.microsoft.com/winfx/2006/xaml" Title="VCF 9.1 ESX Host Validation and JSON Generator" Height="850" Width="1400" MinWidth="1040" WindowStartupLocation="CenterScreen" Background="#050A0D" Foreground="#E6E6E6" FontFamily="Segoe UI"><Window.Resources><Style TargetType="Button"><Setter Property="Background" Value="#233849"/><Setter Property="Foreground" Value="#F4F8FB"/><Setter Property="BorderBrush" Value="#527089"/><Setter Property="BorderThickness" Value="1"/><Setter Property="Padding" Value="10,4"/><Setter Property="Margin" Value="4,3,4,3"/><Setter Property="Height" Value="30"/><Setter Property="Cursor" Value="Hand"/><Style.Triggers><Trigger Property="IsMouseOver" Value="True"><Setter Property="Background" Value="#31536C"/><Setter Property="BorderBrush" Value="#77ACD0"/></Trigger><Trigger Property="IsEnabled" Value="False"><Setter Property="Background" Value="#263039"/><Setter Property="Foreground" Value="#86939D"/><Setter Property="Cursor" Value="Arrow"/></Trigger></Style.Triggers></Style><Style TargetType="TextBlock"><Setter Property="Foreground" Value="#E6E6E6"/><Setter Property="Margin" Value="0,4,8,4"/></Style><Style TargetType="TextBox"><Setter Property="Background" Value="#050A0D"/><Setter Property="Foreground" Value="#E6E6E6"/><Setter Property="BorderBrush" Value="#607D8B"/><Setter Property="Padding" Value="4"/><Setter Property="CaretBrush" Value="#E6E6E6"/></Style><Style TargetType="PasswordBox"><Setter Property="Background" Value="#050A0D"/><Setter Property="Foreground" Value="#E6E6E6"/><Setter Property="BorderBrush" Value="#607D8B"/><Setter Property="Padding" Value="4"/><Setter Property="CaretBrush" Value="#E6E6E6"/></Style><Style TargetType="ComboBox"><Setter Property="Height" Value="24"/></Style><Style TargetType="GroupBox"><Setter Property="Foreground" Value="#E6E6E6"/><Setter Property="Background" Value="#0A1418"/><Setter Property="BorderBrush" Value="#D7DCE2"/><Setter Property="Margin" Value="6"/><Setter Property="Padding" Value="8"/></Style><Style x:Key="GridText" TargetType="TextBlock"><Setter Property="Foreground" Value="#E6E6E6"/><Setter Property="Background" Value="#050A0D"/><Setter Property="Padding" Value="4,1,4,1"/></Style><Style x:Key="GridEdit" TargetType="TextBox"><Setter Property="Foreground" Value="#E6E6E6"/><Setter Property="Background" Value="#050A0D"/><Setter Property="BorderBrush" Value="#0078D7"/></Style><Style TargetType="DataGridColumnHeader"><Setter Property="Background" Value="#D7DCE2"/><Setter Property="Foreground" Value="#111111"/><Setter Property="FontWeight" Value="SemiBold"/></Style><Style TargetType="DataGrid"><Setter Property="Background" Value="#050A0D"/><Setter Property="Foreground" Value="#E6E6E6"/><Setter Property="RowBackground" Value="#050A0D"/><Setter Property="AlternatingRowBackground" Value="#050A0D"/><Setter Property="GridLinesVisibility" Value="All"/><Setter Property="HorizontalGridLinesBrush" Value="#607D8B"/><Setter Property="VerticalGridLinesBrush" Value="#607D8B"/><Setter Property="BorderBrush" Value="#607D8B"/><Setter Property="HeadersVisibility" Value="Column"/><Setter Property="RowHeaderWidth" Value="0"/></Style><Style TargetType="DataGridRow"><Setter Property="Background" Value="#050A0D"/><Setter Property="Foreground" Value="#E6E6E6"/></Style><Style TargetType="TabControl"><Setter Property="Background" Value="#050A0D"/></Style><Style TargetType="TabItem"><Setter Property="Background" Value="#233849"/><Setter Property="Foreground" Value="#F4F8FB"/><Setter Property="BorderBrush" Value="#527089"/><Setter Property="Padding" Value="14,7"/><Setter Property="Margin" Value="0,0,5,0"/><Setter Property="Cursor" Value="Hand"/><Setter Property="Template"><Setter.Value><ControlTemplate TargetType="TabItem"><Border x:Name="TabBorder" Background="{TemplateBinding Background}" BorderBrush="{TemplateBinding BorderBrush}" BorderThickness="1,1,1,0" CornerRadius="4,4,0,0" Padding="{TemplateBinding Padding}"><ContentPresenter ContentSource="Header" HorizontalAlignment="Center" VerticalAlignment="Center"/></Border><ControlTemplate.Triggers><Trigger Property="IsMouseOver" Value="True"><Setter TargetName="TabBorder" Property="Background" Value="#31536C"/><Setter TargetName="TabBorder" Property="BorderBrush" Value="#77ACD0"/></Trigger><Trigger Property="IsSelected" Value="True"><Setter TargetName="TabBorder" Property="Background" Value="#155E75"/><Setter TargetName="TabBorder" Property="BorderBrush" Value="#48B4C8"/><Setter Property="Foreground" Value="#FFFFFF"/><Setter Property="FontWeight" Value="SemiBold"/><Setter Property="Panel.ZIndex" Value="1"/></Trigger><Trigger Property="IsEnabled" Value="False"><Setter TargetName="TabBorder" Property="Background" Value="#263039"/><Setter Property="Foreground" Value="#86939D"/></Trigger></ControlTemplate.Triggers></ControlTemplate></Setter.Value></Setter></Style></Window.Resources><Grid Margin="12" Background="#050A0D"><Grid.RowDefinitions><RowDefinition Height="Auto"/><RowDefinition Height="*"/><RowDefinition Height="180"/><RowDefinition Height="Auto"/></Grid.RowDefinitions><Grid Grid.Row="0"><Grid.ColumnDefinitions><ColumnDefinition Width="1*" MinWidth="440"/><ColumnDefinition Width="1.65*" MinWidth="560"/></Grid.ColumnDefinitions><GroupBox Header="Prerequisites" Grid.Column="0"><Grid><Grid.RowDefinitions><RowDefinition Height="42"/><RowDefinition Height="Auto"/></Grid.RowDefinitions><UniformGrid Columns="4"><StackPanel Orientation="Horizontal"><TextBlock Text="PowerShell:"/><TextBlock x:Name="lblPS"/></StackPanel><StackPanel Orientation="Horizontal"><TextBlock Text="VCF PowerCLI:"/><TextBlock x:Name="lblPCLI"/></StackPanel><StackPanel Orientation="Horizontal"><TextBlock Text="ImportExcel:"/><TextBlock x:Name="lblExcel"/></StackPanel><StackPanel Orientation="Horizontal"><TextBlock Text="Posh-SSH:"/><TextBlock x:Name="lblSsh"/></StackPanel></UniformGrid><StackPanel Grid.Row="1" Orientation="Horizontal"><Button x:Name="btnRecheck" Content="Recheck"/><Button x:Name="btnInstallPowerCLI" Content="Install VCF PowerCLI"/><Button x:Name="btnInstallExcel" Content="Install ImportExcel"/><Button x:Name="btnInstallSSH" Content="Install Posh-SSH"/></StackPanel></Grid></GroupBox><GroupBox Header="Desired ESX Configuration" Grid.Column="1"><Grid Margin="6"><Grid.ColumnDefinitions><ColumnDefinition Width="110"/><ColumnDefinition Width="2*"/><ColumnDefinition Width="24"/><ColumnDefinition Width="110"/><ColumnDefinition Width="1.15*"/></Grid.ColumnDefinitions><Grid.RowDefinitions><RowDefinition Height="32"/><RowDefinition Height="32"/><RowDefinition Height="30"/><RowDefinition Height="26"/><RowDefinition Height="30"/></Grid.RowDefinitions><TextBlock Text="DNS servers" VerticalAlignment="Center"/><TextBox x:Name="txtDns" Grid.Column="1" VerticalAlignment="Center"/><TextBlock Grid.Column="3" Text="Search domains" Margin="12,4,8,4" VerticalAlignment="Center"/><TextBox x:Name="txtDomains" Grid.Column="4" VerticalAlignment="Center"/><TextBlock Grid.Row="1" Text="NTP servers" VerticalAlignment="Center"/><TextBox x:Name="txtNtp" Grid.Row="1" Grid.Column="1" VerticalAlignment="Center"/><StackPanel Grid.Row="2" Grid.Column="1" Grid.ColumnSpan="4" Orientation="Horizontal" Margin="0,4,0,0"><CheckBox x:Name="chkApply" Content="Apply remediation" Foreground="#E6E6E6" IsChecked="False" Margin="0,0,24,0"/><CheckBox x:Name="chkClean" Content="Clean vSAN residue (disabled)" Foreground="#E6E6E6" IsEnabled="False" Margin="0,0,24,0"/></StackPanel><TextBlock x:Name="lblRunMode" Grid.Row="3" Grid.Column="1" Grid.ColumnSpan="4" Text="Validation only. No host remediation or reboot." Foreground="LightGreen"/><TextBlock Grid.Row="4" Text="Storage intent" VerticalAlignment="Center"/><ComboBox x:Name="cmbStorageIntent" Grid.Row="4" Grid.Column="1" Width="200" HorizontalAlignment="Left"><ComboBoxItem Tag="External">External storage</ComboBoxItem><ComboBoxItem Tag="vSAN">vSAN</ComboBoxItem></ComboBox><TextBlock Grid.Row="4" Grid.Column="3" Text="Max drift (s)" VerticalAlignment="Center"/><TextBox x:Name="txtMaxDrift" Grid.Row="4" Grid.Column="4" Text="5" Width="65" HorizontalAlignment="Left"/></Grid></GroupBox></Grid><TabControl Grid.Row="1" Margin="0,8,0,0"><TabItem Header="Validation"><Grid Margin="8" Background="#050A0D"><Grid.RowDefinitions><RowDefinition Height="Auto"/><RowDefinition Height="*"/><RowDefinition Height="24"/><RowDefinition Height="Auto"/></Grid.RowDefinitions><StackPanel Grid.Row="0" Orientation="Horizontal" Margin="5,3,0,8"><CheckBox x:Name="chkSharedPassword" Content="Use one password for all hosts" Foreground="#E6E6E6" VerticalAlignment="Center"/><TextBlock Text="Shared ESX password:" VerticalAlignment="Center" Margin="18,0,6,0"/><PasswordBox x:Name="pwdShared" Width="235" Height="27" IsEnabled="False" ToolTip="Enter the common password once here. Host password cells are disabled in shared mode."/></StackPanel><DataGrid Grid.Row="1" x:Name="gridValidation" AutoGenerateColumns="False" CanUserAddRows="False"><DataGrid.Columns><DataGridTextColumn Header="Host FQDN" Binding="{Binding TargetHost}" Width="2*" ElementStyle="{StaticResource GridText}" EditingElementStyle="{StaticResource GridEdit}"/><DataGridTextColumn Header="User Name" Binding="{Binding Username}" Width="*" ElementStyle="{StaticResource GridText}" EditingElementStyle="{StaticResource GridEdit}"/><DataGridTemplateColumn Header="Password" Width="*"><DataGridTemplateColumn.CellTemplate><DataTemplate><Border Padding="5,1" SnapsToDevicePixels="True"><Border.Style><Style TargetType="Border"><Setter Property="Background" Value="Transparent"/><Style.Triggers><DataTrigger Binding="{Binding IsChecked, ElementName=chkSharedPassword}" Value="True"><Setter Property="Background" Value="#425360"/></DataTrigger></Style.Triggers></Style></Border.Style><TextBlock VerticalAlignment="Center" Foreground="#E6E6E6"><TextBlock.Style><Style TargetType="TextBlock" BasedOn="{StaticResource GridText}"><Setter Property="Text" Value="********"/><Style.Triggers><DataTrigger Binding="{Binding Password}" Value=""><Setter Property="Text" Value=""/></DataTrigger><DataTrigger Binding="{Binding Password}" Value="{x:Null}"><Setter Property="Text" Value=""/></DataTrigger><DataTrigger Binding="{Binding IsChecked, ElementName=chkSharedPassword}" Value="True"><Setter Property="Text" Value="Disabled - shared password"/><Setter Property="Foreground" Value="#DCE8EE"/></DataTrigger></Style.Triggers></Style></TextBlock.Style></TextBlock></Border></DataTemplate></DataGridTemplateColumn.CellTemplate><DataGridTemplateColumn.CellEditingTemplate><DataTemplate><PasswordBox ToolTip="Enter password to set or replace the password for this host."/></DataTemplate></DataGridTemplateColumn.CellEditingTemplate></DataGridTemplateColumn></DataGrid.Columns></DataGrid><TextBlock x:Name="lblCredentials" Grid.Row="2" Text="No host passwords entered." Foreground="Orange"/><Grid Grid.Row="3" Margin="0,4,0,0"><Grid.ColumnDefinitions><ColumnDefinition Width="Auto"/><ColumnDefinition Width="*"/><ColumnDefinition Width="Auto"/></Grid.ColumnDefinitions><StackPanel Grid.Column="0" Orientation="Horizontal"><Button x:Name="btnRun" Content="Validate / Remediate Hosts" Background="#155E75" BorderBrush="#48B4C8" FontWeight="SemiBold"/><TextBlock Text="Parallel nodes:" VerticalAlignment="Center"/><ComboBox x:Name="cmbParallel" Width="54" SelectedIndex="1"><ComboBoxItem>3</ComboBoxItem><ComboBoxItem>4</ComboBoxItem><ComboBoxItem>5</ComboBoxItem></ComboBox><Button x:Name="btnAdd" Content="Add Host"/><Button x:Name="btnRemove" Content="Remove Selected"/></StackPanel><StackPanel Grid.Column="2" Orientation="Horizontal" HorizontalAlignment="Right"><Button x:Name="btnLoad" Content="Load Hosts" ToolTip="Load host configuration from a CSV file."/><Button x:Name="btnSave" Content="Save Hosts" ToolTip="Save host configuration without passwords as a CSV file."/><Button x:Name="btnExample" Content="Save Example Hosts" ToolTip="Save an example host CSV template."/></StackPanel></Grid></Grid></TabItem><TabItem Header="Results"><DataGrid x:Name="gridResults" AutoGenerateColumns="True" IsReadOnly="True"/></TabItem><TabItem Header="JSON Generator"><Grid Margin="8" Background="#050A0D"><GroupBox Header="Bulk Commission JSON Settings"><Grid><Grid.ColumnDefinitions><ColumnDefinition Width="160"/><ColumnDefinition Width="*"/></Grid.ColumnDefinitions><Grid.RowDefinitions><RowDefinition Height="34"/><RowDefinition Height="34"/><RowDefinition Height="34"/><RowDefinition Height="34"/><RowDefinition Height="34"/><RowDefinition Height="Auto"/></Grid.RowDefinitions><TextBlock Text="SDDC Manager FQDN"/><TextBox x:Name="txtSddc" Grid.Column="1"/><TextBlock Grid.Row="1" Text="User"/><TextBox x:Name="txtSddcUser" Grid.Row="1" Grid.Column="1" Text="administrator@vsphere.local"/><TextBlock Grid.Row="2" Text="Password"/><PasswordBox x:Name="txtSddcPass" Grid.Row="2" Grid.Column="1"/><TextBlock Grid.Row="3" Text="Network Pool Name"/><ComboBox x:Name="cmbPool" Grid.Row="3" Grid.Column="1" IsEditable="True"/><TextBlock Grid.Row="4" Text="Storage Type"/><ComboBox x:Name="cmbStorage" Grid.Row="4" Grid.Column="1"><ComboBoxItem>vSAN OSA</ComboBoxItem><ComboBoxItem>vSAN Remote</ComboBoxItem><ComboBoxItem>vSAN ESA</ComboBoxItem><ComboBoxItem>vSAN Max</ComboBoxItem><ComboBoxItem>NFS</ComboBoxItem><ComboBoxItem>VMFS on FC</ComboBoxItem><ComboBoxItem>vVol</ComboBoxItem></ComboBox><StackPanel Grid.Row="5" Grid.ColumnSpan="2" Orientation="Horizontal" HorizontalAlignment="Center"><Button x:Name="btnConnect" Content="Connect" Width="120"/><Button x:Name="btnJson" Content="Generate JSON" Width="130"/></StackPanel></Grid></GroupBox></Grid></TabItem></TabControl><GroupBox Grid.Row="2" Header="Log"><TextBox x:Name="txtLog" IsReadOnly="True" TextWrapping="Wrap" VerticalScrollBarVisibility="Auto" HorizontalScrollBarVisibility="Auto" FontFamily="Consolas" FontSize="12" Background="#050A0D" Foreground="#E6E6E6"/></GroupBox><StackPanel Grid.Row="3" Orientation="Horizontal" HorizontalAlignment="Center"><Button x:Name="btnOpen" Content="Open Run Folder"/><Button x:Name="btnClose" Content="Close"/><Button x:Name="btnStop" Content="Stop Queuing New Hosts" IsEnabled="False"/><TextBlock x:Name="lblProgress" Text="Idle" VerticalAlignment="Center"/></StackPanel></Grid></Window>
'@
$w=[Windows.Markup.XamlReader]::Parse($xaml)
foreach($n in 'lblPS','lblPCLI','lblExcel','lblSsh','btnRecheck','btnInstallPowerCLI','btnInstallExcel','btnInstallSSH','txtDns','txtDomains','txtNtp','cmbParallel','chkApply','chkClean','cmbStorageIntent','txtMaxDrift','chkSharedPassword','pwdShared','lblRunMode','lblProgress','lblCredentials','gridValidation','gridResults','btnAdd','btnRemove','btnLoad','btnSave','btnExample','txtLog','btnRun','btnStop','btnOpen','btnClose','txtSddc','txtSddcUser','txtSddcPass','btnConnect','cmbPool','cmbStorage','btnJson'){Set-Variable -Scope Script -Name $n -Value $w.FindName($n)}
$script:Targets=New-Object System.Collections.ObjectModel.ObservableCollection[object];$script:Rows=New-Object System.Collections.ObjectModel.ObservableCollection[object];$gridValidation.ItemsSource=$script:Targets;$gridResults.ItemsSource=$script:Rows;1..2|ForEach-Object{$script:Targets.Add([pscustomobject]@{TargetHost='';Username='root';Password=''})|Out-Null}
$pwdShared.Add_PasswordChanged({UpdateCredentialStatus})
$gridValidation.AddHandler([System.Windows.Controls.PasswordBox]::PasswordChangedEvent,[System.Windows.RoutedEventHandler]{param($s,$e);$p=$e.OriginalSource;if($p-is[System.Windows.Controls.PasswordBox]-and$p.DataContext){$p.DataContext.Password=$p.Password;UpdateCredentialStatus}})
# Never call Items.Refresh from CellEditEnding: WPF is still committing its edit transaction.
# PasswordChanged already updates the password and credential count. Defer only the
# lightweight count update for FQDN/username edits; a grid refresh is not needed.
$gridValidation.Add_CellEditEnding({
 param($sender,$eventArgs)
 try{
  $null=$sender.Dispatcher.BeginInvoke(
   [Action]{try{UpdateSharedPasswordCells;UpdateCredentialStatus}catch{}},
   [System.Windows.Threading.DispatcherPriority]::ContextIdle
  )
 }catch{Log "Credential status update warning: $($_.Exception.Message)" WARN}
})
function UpdateSharedPasswordCells{
 if(!$gridValidation -or !$chkSharedPassword){return}
 $shared=[bool]$chkSharedPassword.IsChecked
 $pwdShared.IsEnabled=$shared
 $col=$gridValidation.Columns[2]
 $col.IsReadOnly=$shared
 $style=[System.Windows.Style]::new([System.Windows.Controls.DataGridCell])
 $background=if($shared){'#425360'}else{'#101B22'}
 $foreground=if($shared){'#D2DCE3'}else{'#E6E6E6'}
 $style.Setters.Add(([System.Windows.Setter]::new([System.Windows.Controls.Control]::BackgroundProperty,([System.Windows.Media.BrushConverter]::new().ConvertFromString($background)))))
 $style.Setters.Add(([System.Windows.Setter]::new([System.Windows.Controls.Control]::ForegroundProperty,([System.Windows.Media.BrushConverter]::new().ConvertFromString($foreground)))))
 $style.Setters.Add(([System.Windows.Setter]::new([System.Windows.Controls.Control]::BorderBrushProperty,([System.Windows.Media.BrushConverter]::new().ConvertFromString('#607D8B')))))
 if($shared){
  $selected=[System.Windows.Trigger]::new()
  $selected.Property=[System.Windows.Controls.DataGridCell]::IsSelectedProperty
  $selected.Value=$true
  $selected.Setters.Add(([System.Windows.Setter]::new([System.Windows.Controls.Control]::BackgroundProperty,([System.Windows.Media.BrushConverter]::new().ConvertFromString('#425360')))))
  $selected.Setters.Add(([System.Windows.Setter]::new([System.Windows.Controls.Control]::ForegroundProperty,([System.Windows.Media.BrushConverter]::new().ConvertFromString('#D2DCE3')))))
  $style.Triggers.Add($selected)
 }
 $col.CellStyle=$style
}
function UpdateCredentialStatus{
 $hosts=@($script:Targets|Where-Object{![string]::IsNullOrWhiteSpace([string]$_.TargetHost)})
 $ready=@($hosts|Where-Object{![string]::IsNullOrWhiteSpace([string]$_.Password)})
 $lblCredentials.Text=if([bool]$chkSharedPassword.IsChecked){"Shared password: $(if([string]::IsNullOrEmpty($pwdShared.Password)){'not entered'}else{'entered'}); applies to $($hosts.Count) hosts. Individual password cells are disabled."}else{"Passwords entered: $($ready.Count) of $($hosts.Count) target hosts. Blank means not entered."}
 $lblCredentials.Foreground=if(([bool]$chkSharedPassword.IsChecked -and ![string]::IsNullOrEmpty($pwdShared.Password) -and $hosts.Count -gt 0) -or (![bool]$chkSharedPassword.IsChecked -and $ready.Count -eq $hosts.Count -and $hosts.Count -gt 0)){'LightGreen'}else{'Orange'}
}
function UpdateRunStatus{
 if($script:IsRunning){
  $mode=if([bool]$chkApply.IsChecked){'Remediation'}else{'Validation only'}
  $lblProgress.Text="$mode | $($script:CompletedCount) of $($script:TotalCount) completed | Active: $($script:ActiveWorkers.Count) | Queued: $($script:QueuedWorkers)"
 }else{$lblProgress.Text='Idle'}
}
function UpdateRunMode{
 $enabled=[bool]$chkApply.IsChecked
 $chkClean.IsEnabled=$false
 if(!$enabled){$chkClean.IsChecked=$false}
 $lblRunMode.Text=if($enabled){'REMEDIATION: reboot only after changes; then one validation-only pass. No retry.'}else{'Validation only. No host remediation or reboot.'}
 $lblRunMode.Foreground=if($enabled){'Orange'}else{'LightGreen'}
}
$chkSharedPassword.Add_Checked({UpdateSharedPasswordCells;UpdateCredentialStatus})
$chkSharedPassword.Add_Unchecked({UpdateSharedPasswordCells;UpdateCredentialStatus})
$chkApply.Add_Checked({UpdateRunMode})
$chkApply.Add_Unchecked({UpdateRunMode})
$btnRecheck.Add_Click({Prereq})
$btnInstallPowerCLI.Add_Click({try{$null=EnsureModule 'VCF.PowerCLI';Prereq}catch{Log $_.Exception.Message ERROR}})
$btnInstallExcel.Add_Click({try{$null=EnsureModule 'ImportExcel';Prereq}catch{Log $_.Exception.Message ERROR}})
$btnInstallSSH.Add_Click({try{$null=EnsureModule 'Posh-SSH';Prereq}catch{Log $_.Exception.Message ERROR}})
$btnOpen.Add_Click({
 try{
  if([string]::IsNullOrWhiteSpace([string]$script:RunDir) -or !(Test-Path -LiteralPath $script:RunDir -PathType Container)){
   throw 'The current run folder is not available.'
  }
  Start-Process -FilePath 'explorer.exe' -ArgumentList ('"{0}"' -f $script:RunDir) -ErrorAction Stop | Out-Null
  Log "Opened run folder: $script:RunDir"
 }catch{
  $message="Unable to open the run folder: $($_.Exception.Message)"
  Log $message ERROR
  [System.Windows.MessageBox]::Show("$message`n`nFolder: $script:RunDir",'Open Run Folder')|Out-Null
 }
})
$w.Add_Closing({param($sender,$e)
 if($script:IsRunning){$e.Cancel=$true;[System.Windows.MessageBox]::Show('A run is active. Stop queuing and wait for active workers and the report before closing.','Host run in progress')|Out-Null}
})
$btnClose.Add_Click({$w.Close()})
$btnStop.Add_Click({
 $script:StopRequested=$true;$btnStop.IsEnabled=$false
 Log 'Stop queuing requested. Already-running workers will continue, including any authorized remediation or reboot.' WARN
})
$btnAdd.Add_Click({$script:Targets.Add([pscustomobject]@{TargetHost='';Username='root';Password=''})|Out-Null;UpdateSharedPasswordCells;UpdateCredentialStatus})
$btnRemove.Add_Click({foreach($i in @($gridValidation.SelectedItems)){$script:Targets.Remove($i)|Out-Null};UpdateSharedPasswordCells;UpdateCredentialStatus})
$btnLoad.Add_Click({$dlg=New-Object Microsoft.Win32.OpenFileDialog;$dlg.Filter='CSV files (*.csv)|*.csv|All files (*.*)|*.*';if($dlg.ShowDialog()){$script:Targets.Clear();$rows=@(Import-Csv $dlg.FileName);if($rows.Count){$txtDns.Text=$rows[0].DnsServers;$txtDomains.Text=$rows[0].SearchDomains;$txtNtp.Text=$rows[0].NtpServers;$chkSharedPassword.IsChecked=([string]$rows[0].SharedPasswordMode -eq 'True');$txtMaxDrift.Text=if($rows[0].MaxDriftSeconds){[string]$rows[0].MaxDriftSeconds}else{'5'};$cmbStorageIntent.SelectedIndex=-1;for($idx=0;$idx -lt $cmbStorageIntent.Items.Count;$idx++){if([string]$cmbStorageIntent.Items[$idx].Tag -eq [string]$rows[0].StorageIntent){$cmbStorageIntent.SelectedIndex=$idx;break}}};$rows|ForEach-Object{$script:Targets.Add([pscustomobject]@{TargetHost=$_.TargetHost;Username=if($_.Username){$_.Username}else{'root'};Password=$_.Password})|Out-Null};UpdateSharedPasswordCells;UpdateCredentialStatus;Log "Loaded $($rows.Count) rows and saved configuration."}})
$btnSave.Add_Click({$p=Join-Path $script:RunDir 'validation-targets.csv';@(TargetRows $false)|ForEach-Object{[pscustomobject]@{TargetHost=$_.TargetHost;Username=$_.Username;Password='';DnsServers=$txtDns.Text;SearchDomains=$txtDomains.Text;NtpServers=$txtNtp.Text;StorageIntent=(Get-StorageIntent);MaxDriftSeconds=$txtMaxDrift.Text;SharedPasswordMode=[bool]$chkSharedPassword.IsChecked}}|Export-Csv -NoTypeInformation -LiteralPath $p;Log "Saved validation CSV without passwords: $p";[System.Windows.MessageBox]::Show("Saved configuration without passwords. Re-enter passwords when loading the CSV.`n`n$p",'CSV saved')|Out-Null})
$btnExample.Add_Click({
 $dlg=New-Object Microsoft.Win32.SaveFileDialog
 $dlg.Filter='CSV files (*.csv)|*.csv';$dlg.FileName='example-validation-targets.csv'
 if($dlg.ShowDialog()){
  @([pscustomobject]@{TargetHost='pod01esx12.corp.example.com';Username='root';Password='';DnsServers='192.0.2.10;192.0.2.11';SearchDomains='corp.example.com';NtpServers='time1.example.com;time2.example.com';StorageIntent='External';MaxDriftSeconds='5';SharedPasswordMode='False'})|Export-Csv -NoTypeInformation -Path $dlg.FileName
  Log "Example CSV saved: $($dlg.FileName) (no password included)."
 }
})
$btnConnect.Add_Click({try{ConnectPools}catch{Log $_.Exception.Message ERROR;[System.Windows.MessageBox]::Show($_.Exception.Message,'Network Pool connect failed')|Out-Null}})
$btnJson.Add_Click({try{ValidateInputs;GenJson;[System.Windows.MessageBox]::Show('JSON generated and opened.','JSON generated')|Out-Null}catch{Log $_.Exception.Message ERROR;[System.Windows.MessageBox]::Show($_.Exception.Message,'Generate JSON failed')|Out-Null}})
$btnRun.Add_Click({
 if($script:IsRunning){return}
 try{ValidateInputs}catch{
  Log "Input validation rejected: $($_.Exception.Message)" WARN
  [System.Windows.MessageBox]::Show($_.Exception.Message,'Input validation rejected')|Out-Null
  return
 }
 $targets=@(TargetRows)
 try{
  Assert-SharedCredentialSnapshot $targets
  $apply=[bool]$chkApply.IsChecked;$clean=[bool]$chkClean.IsChecked;$reboot=if($apply){'Conditional on changes'}else{'No'}
  if($clean){throw 'Automated vSAN cleanup is disabled in this revision.'}
  $mode=if($apply){'REMEDIATION'}else{'VALIDATION ONLY'}
  if(!(Show-HostRunReview -Targets $targets -Apply $apply -Cleanup $clean)){Log 'Host run canceled in themed review dialog.' INFO;return}
  $script:IsRunning=$true;$script:StopRequested=$false
  $btnRun.IsEnabled=$false;$btnStop.IsEnabled=$true
  foreach($control in @($chkApply,$chkClean,$cmbStorageIntent,$txtMaxDrift,$chkSharedPassword,$pwdShared,$gridValidation,$btnAdd,$btnRemove,$btnLoad,$btnSave,$btnExample,$cmbParallel,$btnConnect,$btnJson)){$control.IsEnabled=$false}
  $script:Rows.Clear()
  $script:WorkerResults=[Collections.ArrayList]::new();$script:ActiveWorkers=[Collections.ArrayList]::new();$script:QueuedWorkers=0
  Log "Run started. Mode=$mode; Hosts=$($targets.Count); Reboot=$reboot; Cleanup=$clean"
  $throttle=[int]([System.Windows.Controls.ComboBoxItem]$cmbParallel.SelectedItem).Content
  InvokeParallelHosts $targets $throttle
 }catch{
  $script:StopRequested=$true
  Log "Parent run exception: $($_.Exception.ToString())" ERROR
  [System.Windows.MessageBox]::Show($_.Exception.Message,'Run warning: collecting results')|Out-Null
 }finally{
  try{
   if($script:ActiveWorkers -and $script:ActiveWorkers.Count -gt 0){Log "Waiting for $($script:ActiveWorkers.Count) active workers before reporting." WARN;DrainWorkers}
   $sum=@();$det=@()
   if($script:WorkerResults){foreach($r in @($script:WorkerResults.ToArray())){
    if(!$r -or !$r.Summary){continue}
    $sum+=,$r.Summary;$det+=@($r.Details)
    try{$script:Rows.Add($r.Summary)|Out-Null}catch{Log "Results grid warning: $($_.Exception.Message)" WARN}
   }}
   try{$gridResults.Items.Refresh()}catch{}
   $rep=$null;$reportWritten=$false
   if($sum.Count -gt 0){try{$rep=ExportReport $sum $det;$html=ExportHtmlReport $sum $det;$reportWritten=([bool]$rep -and (Test-Path -LiteralPath $rep -PathType Leaf));if(!$reportWritten){throw 'ExportReport returned without a readable report file.'};Log "Readiness report exported. Report=$rep; Collected=$($sum.Count)/$($targets.Count)" PASS}catch{Log "Report export failed: $($_.Exception.ToString())" ERROR}}
   else{Log 'No worker results collected; inspect worker artifacts.' ERROR}
   $bundle=New-DiagnosticBundle;Log "DiagnosticBundle=$bundle";if($reportWritten){try{Start-Process -FilePath $html -ErrorAction Stop|Out-Null}catch{Log "HTML report saved but could not auto-open: $($_.Exception.Message)" WARN}}
   $passed=@($sum|Where-Object{$_.Overall -eq 'Pass'}).Count
   $failed=@($sum|Where-Object{$_.Overall -eq 'Fail'}).Count
   $other=$sum.Count-$passed-$failed
   if($reportWritten -and $sum.Count -eq $targets.Count){Log "FINAL REPORT COMPLETE: Expected=$($targets.Count); Collected=$($sum.Count); Pass=$passed; Fail=$failed; Other=$other; Report=$rep; Bundle=$bundle" PASS}
   else{Log "FINAL REPORT INCOMPLETE: Expected=$($targets.Count); Collected=$($sum.Count); Pass=$passed; Fail=$failed; Other=$other; ReportWritten=$reportWritten; Report=$rep; Bundle=$bundle" ERROR}
  }catch{try{Log "Final collection exception: $($_.Exception.ToString())" ERROR}catch{}}
  $script:IsRunning=$false;$btnStop.IsEnabled=$false;$btnRun.IsEnabled=$true
  foreach($control in @($chkApply,$cmbStorageIntent,$txtMaxDrift,$chkSharedPassword,$pwdShared,$gridValidation,$btnAdd,$btnRemove,$btnLoad,$btnSave,$btnExample,$cmbParallel,$btnConnect,$btnJson)){$control.IsEnabled=$true}
  UpdateSharedPasswordCells;UpdateRunMode;UpdateRunStatus;Prereq
 }
})

UpdateRunMode
UpdateSharedPasswordCells
UpdateCredentialStatus
Prereq
Log "Script started. Output: $script:RunDir"
$w.ShowDialog()|Out-Null
