<#
.SYNOPSIS
  VCF 9.1 ESX Validation and JSON Generator v1.7.4 Simplified Remediation Controls

.DESCRIPTION
  Production WPF tool for ESX readiness remediation/validation and bulk commission JSON generation.



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
  v46 updates:
- Fixes blank ESXCLI vsan.storage.list result objects being mistaken for existing vSAN ownership.
- Requires an actual non-empty device, vSAN UUID, disk-group UUID/name, mounted, or used-by-host value before ownership is considered present.
- Logs eligible disk count, non-empty ownership entry count, and expected boot/system disk exclusions.
v45 updates:
- Corrects false vSAN failures on brand-new, unclaimed nodes when Clean vSAN residue is not selected.
- Treats raw disks reported as Eligible for use by VSAN / Reason: None as a pass, while ignoring expected ineligible ESXi boot/system devices.
- Still fails validation when existing vSAN ownership is returned or no eligible raw vSAN disk is detected.
v44 updates:
- Streams log entries written by parallel worker processes into the WPF log pane while validation is running.
- Adds worker start/completion progress messages and keeps the UI responsive during parallel processing.
v43 updates:
- Masks ESXi passwords and warns after saving plaintext passwords to CSV.
- Saves/loads DNS, domain, and NTP configuration with CSV targets.
- Runs 3-5 hosts concurrently in isolated hidden PowerShell 7 workers.
- Installs VCF.PowerCLI, ImportExcel, and Posh-SSH in-process under PowerShell 7.
- Creates/trusts a CurrentUser code-signing certificate and signs before STA relaunch.
- Uses guarded OSA/ESA disk reclamation with protected-device checks, ESXCLI V2, HostStorageSystem partition clearing, rescan, and vdq verification.
v41 updates:
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
function New-DiagnosticBundle{if($WorkerInput){return};try{$zip=$script:RunDir+'.zip';if(Test-Path $zip){Remove-Item $zip -Force};Compress-Archive -Path (Join-Path $script:RunDir '*') -DestinationPath $zip -Force;Log "Diagnostic bundle created: $zip" PASS;return $zip}catch{Log "Diagnostic bundle failed: $($_.Exception.Message)" WARN}}
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
function TargetRows{try{$null=$gridValidation.CommitEdit();$null=$gridValidation.CommitEdit([System.Windows.Controls.DataGridEditingUnit]::Row,$true)}catch{};$rows=@();foreach($x in @($script:Targets)){$h=([string]$x.TargetHost).Trim();if(!$h){continue};$u=if([string]::IsNullOrWhiteSpace([string]$x.Username)){'root'}else{([string]$x.Username).Trim()};$rows+=[pscustomobject]@{TargetHost=(SafeLower $h);Username=$u;Password=[string]$x.Password}};@($rows)}
function ValidateInputs{$m=@();if([string]::IsNullOrWhiteSpace($txtDns.Text)){$m+='DNS servers'};if([string]::IsNullOrWhiteSpace($txtNtp.Text)){$m+='NTP servers'};if([string]::IsNullOrWhiteSpace($txtDomains.Text)){$m+='Search domains'};if($m.Count){throw 'Populate required Desired ESX Configuration field(s): '+($m -join ', ')};if(@(TargetRows).Count -eq 0){throw 'Add at least one host.'};$missing=@(TargetRows|Where-Object{[string]::IsNullOrWhiteSpace($_.Password)}|ForEach-Object{$_.TargetHost});if($missing.Count){throw "Enter an ESXi password for every target host before running: $($missing -join ', ')"}}
function Prereq{$lblPS.Text=$PSVersionTable.PSVersion.ToString();$lblPS.Foreground='LightGreen';$pcliFound=HasMod $script:PowerCliModule;$lblPCLI.Text=if($pcliFound){'Found'}else{'Missing'};$lblPCLI.Foreground=if($pcliFound){'LightGreen'}else{'Tomato'};$lblExcel.Text=if(HasMod ImportExcel){'Found'}else{'Missing'};$lblExcel.Foreground=if(HasMod ImportExcel){'LightGreen'}else{'Tomato'};$lblSsh.Text=if(HasMod Posh-SSH){'Found'}else{'Missing'};$lblSsh.Foreground=if(HasMod Posh-SSH){'LightGreen'}else{'Tomato'}}
function ConnectRetry($h,$u,$p){if(!(HasMod $script:PowerCliModule)){throw 'VCF.PowerCLI module is required. Use the Install VCF PowerCLI button or run: Install-Module -Name VCF.PowerCLI -Scope CurrentUser -Force -AllowClobber -SkipPublisherCheck'};Imp $script:PowerCliModule|Out-Null;try{Set-PowerCLIConfiguration -InvalidCertificateAction Ignore -Confirm:$false -Scope User|Out-Null}catch{};for($i=1;$i-le3;$i++){try{Log "[$h] Connect-VIServer attempt $i of 3...";return Connect-VIServer -Server $h -Credential (Cred $u $p) -Force -ErrorAction Stop}catch{Log "[$h] Connect failed attempt $i of 3: $($_.Exception.Message)" WARN;if($i-lt3){SleepUi 5}else{throw}}}}
function MgmtIp($vmh){try{$v=Get-VMHostNetworkAdapter -VMHost $vmh -VMKernel|Where-Object{$_.ManagementTrafficEnabled}|Select-Object -First 1;if($v.IP){return [string]$v.IP}}catch{};return $vmh.Name}
function EnableSsh($vmh){try{$svc=Get-VMHostService -VMHost $vmh|Where-Object{$_.Key -eq 'TSM-SSH'}|Select-Object -First 1;if($svc -and !$svc.Running){Log "[$($vmh.Name)] Starting SSH service for readiness commands..." WARN;Start-VMHostService -HostService $svc -Confirm:$false|Out-Null;SleepUi 6}}catch{Log "[$($vmh.Name)] SSH start warning: $($_.Exception.Message)" WARN}}
function SshRun($h,$u,$p,$cmd,$to=120){if(!(HasMod Posh-SSH)){throw 'Posh-SSH module is required.'};Imp Posh-SSH|Out-Null;$s=$null;$old=$WarningPreference;try{if(!(WaitTcp $h 22 25)){throw 'TCP/22 not reachable.'};$WarningPreference='SilentlyContinue';$s=New-SSHSession -ComputerName $h -Credential (Cred $u $p) -AcceptKey -Force -ConnectionTimeout 15 -WarningAction SilentlyContinue -ErrorAction Stop;$r=Invoke-SSHCommand -SessionId $s.SessionId -Command $cmd -TimeOut $to -ErrorAction Stop;[pscustomobject]@{StdOut=(@($r.Output)-join"`n");StdErr=(@($r.Error)-join"`n");ExitStatus=$r.ExitStatus}}finally{$WarningPreference=$old;if($s){try{Remove-SSHSession -SessionId $s.SessionId|Out-Null}catch{}}}}
function Esx($vmh,$cmd,$to=120){SshRun (MgmtIp $vmh) $script:CurrentShellUser $script:CurrentShellPassword $cmd $to}
function EsxRetry($vmh,$cmd,$to=120,$tries=4){$last='';for($i=1;$i-le$tries;$i++){try{if($i-gt1){Log "[$($vmh.Name)] ESX shell retry $i of $tries..." WARN;EnableSsh $vmh;SleepUi 5};return Esx $vmh $cmd $to}catch{$last=$_.Exception.Message;Log "[$($vmh.Name)] ESX shell attempt $i failed: $last" WARN;if($i-lt$tries){SleepUi 8}}};throw $last}
function DisableSsh($vmh){try{Esx $vmh '(vim-cmd hostsvc/disable_ssh >/dev/null 2>&1 || true); (/etc/init.d/SSH stop || /etc/init.d/TSM-SSH stop || /etc/init.d/ssh stop || true)' 30|Out-Null}catch{};try{$svc=Get-VMHostService -VMHost $vmh|Where-Object{$_.Key -eq 'TSM-SSH'}|Select-Object -First 1;if($svc){Set-VMHostService -HostService $svc -Policy Off -ErrorAction SilentlyContinue|Out-Null;if($svc.Running){Stop-VMHostService -HostService $svc -Confirm:$false -ErrorAction SilentlyContinue|Out-Null}};Log "[$($vmh.Name)] SSH service stopped/disabled after readiness."}catch{Log "[$($vmh.Name)] SSH disable warning: $($_.Exception.Message)" WARN}}
function TestRebootPreflight($vmh,$h){
 try{
  $hostView=Get-View -Id $vmh.Id -ErrorAction Stop
  if($hostView.Runtime.InMaintenanceMode -ne $true){throw 'Host is not confirmed in maintenance mode. No reboot will be requested.'}
  $powered=@(Get-VM -Location $vmh -ErrorAction Stop|Where-Object{$_.PowerState -eq 'PoweredOn'})
  if($powered.Count){throw "Host has $($powered.Count) powered-on VM(s). No reboot will be requested."}
  Log "[$h] Reboot preflight passed: maintenance mode, zero powered-on VMs." PASS
  return $true
 }catch{Log "[$h] Reboot preflight blocked: $($_.Exception.Message)" ERROR;return $false}
}
function InvokeSingleRebootAndWait($target,[int]$TimeoutSeconds=1200){
 $h=SafeLower $target.TargetHost;$server=$null;$sent=$false;$before=$null
 try{
  if(!(WaitTcp $h 443 30)){throw 'Host HTTPS was not reachable for reboot preflight.'}
  $server=ConnectRetry $h $target.Username $target.Password
  $vmh=Get-VMHost -Server $server -ErrorAction Stop|Select-Object -First 1
  if(!$vmh){throw 'Host inventory was not returned for reboot.'}
  if(!(TestRebootPreflight $vmh $h)){throw 'Maintenance mode / powered-on VM reboot preflight failed.'}
  $view=Get-View -Id $vmh.Id -ErrorAction Stop
  $before=$view.Runtime.BootTime
  if(!$before){throw 'Cannot obtain pre-reboot boot time; reboot verification would be unsafe.'}
  Log "[$h] Reboot phase: boot time before=$before; issuing ONE reboot request." WARN
  $sent=$true
  try{Restart-VMHost -VMHost $vmh -Confirm:$false -ErrorAction Stop|Out-Null}
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

function SetHostDns($vmh,$fqdn,$dnsTxt,$domTxt,$apply){$desiredDns=SplitList $dnsTxt;$domain=(SplitList $domTxt|Select-Object -First 1);$short=($fqdn -split '\.')[0];if(!$apply){return Check 'N/A' 'Apply remediation is disabled; hostname/DNS/domain set skipped.'};try{Log "[$fqdn] Setting hostname/FQDN/domain/DNS. Host=$short Domain=$domain DNS=$(($desiredDns -join ','))";$powerCliOk=$false;$powerCliMsg='';try{$net=Get-VMHostNetwork -VMHost $vmh -ErrorAction Stop;Set-VMHostNetwork -Network $net -HostName $short -DomainName $domain -DnsAddress $desiredDns -ErrorAction Stop|Out-Null;$powerCliOk=$true}catch{$powerCliMsg=$_.Exception.Message;Log "[$fqdn] PowerCLI DNS set warning: $powerCliMsg. Applying ESX shell set/confirmation." WARN};$add=($desiredDns|ForEach-Object{"esxcli network ip dns server add -s $(Q $_) >/dev/null 2>&1 || true"}) -join "`n";$cmd=@'
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
(esxcli network ip dns server list 2>/dev/null | awk '/^[0-9]/{print $1}') || true
echo DNS_END
'@;$o=(EsxRetry $vmh $cmd 60 4).StdOut;$curHost=([regex]::Match($o,'(?m)^HOST=(.*)$')).Groups[1].Value.Trim();$curFqdn=([regex]::Match($o,'(?m)^FQDN=(.*)$')).Groups[1].Value.Trim();$curDom=([regex]::Match($o,'(?m)^DOMAIN=(.*)$')).Groups[1].Value.Trim();$block=([regex]::Match($o,'(?s)DNS_BEGIN\s*(.*?)\s*DNS_END')).Groups[1].Value;$curDns=@($block -split '[\r\n]+'|Where-Object{$_ -match '^\d+\.\d+\.\d+\.\d+$'});$okHost=(SafeLower $curHost)-eq(SafeLower $short);$okDom=(SafeLower $curDom)-eq(SafeLower $domain);$okFqdn=([string]::IsNullOrWhiteSpace($curFqdn) -or (SafeLower $curFqdn)-eq(SafeLower $fqdn) -or $curFqdn -eq $curHost);$dnsListOk=ContainsAll $desiredDns $curDns;$dnsFunctionalOk=($dnsReach -and $dnsReach.Status -eq 'Pass');$dnsOk=$dnsListOk -or ($curDns.Count -eq 0 -and $dnsFunctionalOk);$st=if($okHost -and $okDom -and $okFqdn -and $dnsOk){'Pass'}else{'Fail'};$note=if($curDns.Count -eq 0 -and $dnsFunctionalOk){'DNS list parse unavailable/blank; DNS functional query passed, so DNS verification accepted.'}else{''};return Check $st "Host=$curHost DesiredHost=$short; FQDN=$curFqdn DesiredFQDN=$fqdn; CurrentDNS=$(($curDns-join ',')); DesiredDNS=$(($desiredDns-join ',')); DNSListOk=$dnsListOk; DNSFunctionalOk=$dnsFunctionalOk; CurrentDomain=$curDom; DesiredDomain=$domain; $note"}catch{return Check 'Fail' $_.Exception.Message}}
function TestDnsResolution($fqdn){try{$f=@(Resolve-DnsName $fqdn -Type A -ErrorAction Stop|Where-Object{$_.IPAddress}|ForEach-Object{$_.IPAddress});if(!$f){return Check Fail 'Forward DNS returned no A records.'};$ptr=@();foreach($ip in $f){try{$ptr+=@(Resolve-DnsName $ip -Type PTR -ErrorAction Stop|Where-Object{$_.NameHost}|ForEach-Object{$_.NameHost})}catch{}};$ok=@($ptr|ForEach-Object{$_.TrimEnd('.').ToLowerInvariant()}|Where-Object{$_ -eq $fqdn.ToLowerInvariant()}).Count -gt 0;if($ok){Check Pass "Forward=$($f -join ','); PTR=$($ptr -join ','); lowercase hostname match confirmed."}else{Check Fail "Forward=$($f -join ','); PTR=$($ptr -join ','); PTR did not match lowercase FQDN."}}catch{Check Fail $_.Exception.Message}}
function TestDnsReach($vmh,$dnsTxt,$fqdn){$servers=@(SplitList $dnsTxt);$qfq=Q $fqdn;$quoted=($servers|ForEach-Object{Q $_}) -join ' ';$cmd=@"
for server in $quoted; do
 query=FAIL; tcp=UNKNOWN
 if command -v nc >/dev/null 2>&1; then if nc -z -w 3 `$server 53 >/dev/null 2>&1; then tcp=OPEN; else tcp=CLOSED; fi; fi
 if nslookup $qfq `$server >/tmp/dnscheck.out 2>&1; then query=OK; fi
 echo "DNS:`$server TCP53=`$tcp QUERY=`$query"
done
"@;try{$out=((EsxRetry $vmh $cmd 90 4).StdOut).Trim();$lines=@($out -split '[\r\n]+'|Where-Object{$_ -match '^DNS:'});$pass=@($lines|Where-Object{$_ -match 'QUERY=OK'}).Count -gt 0;Check $(if($pass){'Pass'}else{'Fail'}) $out}catch{Check Fail $_.Exception.Message}}
function RestartNtp($h){try{$svc=Get-VMHostService -VMHost $h|Where-Object{$_.Key -eq 'ntpd'}|Select-Object -First 1;if($svc){Set-VMHostService -HostService $svc -Policy On|Out-Null;try{Stop-VMHostService -HostService $svc -Confirm:$false -ErrorAction SilentlyContinue|Out-Null}catch{};SleepUi 3;Start-VMHostService -HostService $svc -Confirm:$false -ErrorAction SilentlyContinue|Out-Null;SleepUi 10;return $true}}catch{};try{EsxRetry $h '(/etc/init.d/ntpd restart || /etc/init.d/ntp restart || true)' 60 3|Out-Null;SleepUi 10;return $true}catch{return $false}}
function GetShellNtp($h){try{$cmd=@'
echo NTP_BEGIN
esxcli system ntp get 2>/dev/null | sed -n 's/.*Servers:[ ]*//p' | tr ',' '\n' | sed 's/^ *//;s/ *$//'
echo NTP_END
'@;$o=(EsxRetry $h $cmd 60 3).StdOut;$b=([regex]::Match($o,'(?s)NTP_BEGIN\s*(.*?)\s*NTP_END')).Groups[1].Value;@(Norm @($b -split '[\r\n]+'|Where-Object{$_.Trim()}))}catch{@()}}
function TestSetNtp($vmh,$ntpTxt,$apply){$desired=@(Norm (SplitList $ntpTxt));$changed=$false;$restarted=$false;try{$cur=@(Norm @(Get-VMHostNtpServer -VMHost $vmh -ErrorAction SilentlyContinue));if(!$cur){$cur=@(GetShellNtp $vmh)};$match=EqualList $desired $cur;if($apply -and !$match){Log "[$($vmh.Name)] Setting NTP servers to $(($desired-join','))";try{foreach($s in $cur){try{Remove-VMHostNtpServer -VMHost $vmh -NtpServer $s -Confirm:$false|Out-Null}catch{}};foreach($s in $desired){Add-VMHostNtpServer -VMHost $vmh -NtpServer $s -Confirm:$false|Out-Null}}catch{};$csv=$desired -join ',';EsxRetry $vmh "esxcli system ntp set -e true -s $(Q $csv) || true" 60 3|Out-Null;$restarted=RestartNtp $vmh;$changed=$true;$cur=@(Norm @(Get-VMHostNtpServer -VMHost $vmh -ErrorAction SilentlyContinue));if(!$cur){$cur=@(GetShellNtp $vmh)};$match=EqualList $desired $cur};$svc=$null;try{$svc=Get-VMHostService -VMHost $vmh|Where-Object{$_.Key -eq 'ntpd'}|Select-Object -First 1}catch{};$running=if($svc){[bool]$svc.Running}else{$apply};if($apply -and $match -and !$running){$restarted=RestartNtp $vmh;$running=$true};$sync=$false;$detail='';for($i=1;$i -le 10;$i++){Log "[$($vmh.Name)] Checking NTP sync attempt $i of 10...";try{$detail=((EsxRetry $vmh "(ntpq -pn 2>/dev/null || /usr/lib/vmware/ntp/bin/ntpq -pn 2>/dev/null || true)" 30 3).StdOut).Trim();if($detail -match '(?m)^\*' -or $detail -match '(?m)^[\+\- ]\S+\s+\S+\s+\d+\s+\w\s+\S+\s+\d+\s+[1-7]'){$sync=$true;break}}catch{$detail=$_.Exception.Message};if(!$sync -and $apply -and $i -eq 5){Log "[$($vmh.Name)] NTP has not selected/reached a peer by attempt 5. Restarting NTP service..." WARN;$restarted=RestartNtp $vmh};if($i -lt 10){SleepUi 15}};$cfg=if($match -and ($running -or $apply)){if($changed){'Remediated'}else{'Pass'}}else{'Fail'};[pscustomobject]@{Status=$cfg;Detail="CurrentNTP=$(($cur-join ',')); DesiredNTP=$(($desired-join ',')); ConfigMatch=$match; ServiceRunning=$running; Changed=$changed; ServiceRestarted=$restarted";SyncStatus=if($sync){'Pass'}else{'Fail'};SyncDetail="SyncPass=$sync; $detail"}}catch{[pscustomobject]@{Status='Fail';Detail=$_.Exception.Message;SyncStatus='Fail';SyncDetail='Skipped due to NTP config failure.'}}}
function TestTimeDrift($vmh){try{$scriptUtc=[DateTimeOffset]::UtcNow;$cmd=@'
echo ESX_EPOCH=$(date -u +%s)
echo ESX_UTC=$(date -u '+%Y-%m-%dT%H:%M:%SZ')
'@;$out=(EsxRetry $vmh $cmd 30 3).StdOut;$epoch=([regex]::Match($out,'(?m)^ESX_EPOCH=(\d+)')).Groups[1].Value;$hostText=([regex]::Match($out,'(?m)^ESX_UTC=(.*)$')).Groups[1].Value.Trim();if(!$epoch){throw "Unable to parse ESX time. Output=$out"};$hostUtc=[DateTimeOffset]::FromUnixTimeSeconds([int64]$epoch);$drift=[math]::Round(($hostUtc.UtcDateTime-$scriptUtc.UtcDateTime).TotalSeconds,2);[pscustomobject]@{Status='Pass';Detail="ScriptTimeUTC=$($scriptUtc.UtcDateTime.ToString('yyyy-MM-ddTHH:mm:ssZ')); HostTimeUTC=$($hostUtc.UtcDateTime.ToString('yyyy-MM-ddTHH:mm:ssZ')); HostReportedUTC=$hostText; DriftSeconds=$drift; AbsoluteDriftSeconds=$([math]::Abs($drift))";DriftSeconds=$drift}}catch{[pscustomobject]@{Status='Fail';Detail=$_.Exception.Message;DriftSeconds=$null}}}
function CertCheck($fqdn){try{$tcp=New-Object Net.Sockets.TcpClient($fqdn,443);$ssl=New-Object Net.Security.SslStream($tcp.GetStream(),$false,({$true}));$ssl.AuthenticateAsClient($fqdn);$cert=New-Object Security.Cryptography.X509Certificates.X509Certificate2($ssl.RemoteCertificate);$tcp.Close();$names=@($cert.GetNameInfo([Security.Cryptography.X509Certificates.X509NameType]::DnsName,$false));try{$san=$cert.Extensions|Where-Object{$_.Oid.FriendlyName -eq 'Subject Alternative Name'}|Select-Object -First 1;if($san){$names+=($san.Format($true)-split '[,\r\n]+'|ForEach-Object{($_ -replace 'DNS Name=','').Trim()})}}catch{};$fq=$fqdn.ToLowerInvariant();$ok=@($names|ForEach-Object{(SafeLower $_)}|Where-Object{$_ -eq $fq}).Count -gt 0;Check $(if($ok){'Pass'}else{'Fail'}) "RequiredLowercaseFQDN=$fq; Subject=$($cert.Subject); Names=$(@($names|Where-Object{$_}) -join ','); Expires=$($cert.NotAfter)"}catch{Check Fail $_.Exception.Message}}
function GenCert($vmh,$fqdn){try{EsxRetry $vmh '/sbin/generate-certificates' 180 3|Out-Null;Check Remediated "Ran /sbin/generate-certificates for lowercase FQDN $($fqdn.ToLowerInvariant()). Mandatory reboot will reload hostd/vpxa."}catch{Check Fail $_.Exception.Message}}
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
  $beforeInt=([regex]::Match($before,'(?im)^\s*Int Value\s*:\s*(-?\d+)\s*$')).Groups[1].Value
  $beforeGlobal=([regex]::Match($before,'(?im)^\s*IPv6 Enabled\s*:\s*(true|false)\s*$')).Groups[1].Value
  $enabled=($beforeInt-eq'1'-or$beforeGlobal-eq'true')
  $beforeKnown=($beforeInt -in '0','1')
  $beforeConflict=($beforeKnown -and $beforeGlobal -in 'true','false' -and (($beforeInt -eq '0') -ne ($beforeGlobal -eq 'false')))
  if(!$beforeKnown -or $beforeConflict){
   $reason=if($beforeConflict){'Conflicting IPv6 baseline evidence'}else{'Unknown IPv6 baseline: persistent Int Value was not returned'}
   $a=Save-DiagnosticArtifact IPV6 "$h-before-unknown" ([ordered]@{Host=$h;IntValue=$beforeInt;GlobalValue=$beforeGlobal;Evidence=$before;Reason=$reason})
   Log "[$h] $reason; no IPv6 remediation attempted. Artifact=$a" ERROR
   return Check Fail "$reason; IntValue=$beforeInt; GlobalValue=$beforeGlobal; Artifact=$a"
  }
  if(!$apply){$a=Save-DiagnosticArtifact IPV6 "$h-before" ([ordered]@{Host=$h;IntValue=$beforeInt;GlobalValue=$beforeGlobal;Enabled=$enabled;Evidence=$before});return Check $(if($enabled){'Fail'}else{'Pass'}) "Enabled=$enabled; IntValue=$beforeInt; GlobalValue=$beforeGlobal; Artifact=$a"}
  Log "[$h] IPv6 remediation starting. PersistentBefore=$enabled; IntValue=$beforeInt; GlobalValue=$beforeGlobal"
  $powerCliSuccess=$false;$powerCliMessage=''
  try{$adv=Get-AdvancedSetting -Entity $vmh -Name 'Net.IPv6Enabled' -ErrorAction Stop|Select-Object -First 1;if(!$adv){throw 'Net.IPv6Enabled advanced setting was not returned.'};if([string]$adv.Value-ne'0'){$null=Set-AdvancedSetting -AdvancedSetting $adv -Value 0 -Confirm:$false -ErrorAction Stop};$verify=Get-AdvancedSetting -Entity $vmh -Name 'Net.IPv6Enabled' -ErrorAction Stop|Select-Object -First 1;$powerCliSuccess=([string]$verify.Value-eq'0');$powerCliMessage="Before=$($adv.Value); After=$($verify.Value)"}catch{$powerCliMessage=$_.Exception.Message;Log "[$h] PowerCLI IPv6 setting warning: $powerCliMessage" WARN}
  $cmd=@'
set +e
O1=$(esxcli network ip set --ipv6-enabled=false 2>&1); R1=$?
O2=$(esxcli system settings advanced set -o /Net/IPv6Enabled -i 0 2>&1); R2=$?
echo "NETWORK_IP_SET_RC=$R1 OUTPUT=$O1"
echo "ADVANCED_SET_RC=$R2 OUTPUT=$O2"
exit 0
'@
  $disableOut=(EsxRetry $vmh $cmd 60 3).StdOut
  $networkRc=([regex]::Match($disableOut,'(?im)^NETWORK_IP_SET_RC=(\d+)')).Groups[1].Value
  $advancedRc=([regex]::Match($disableOut,'(?im)^ADVANCED_SET_RC=(\d+)')).Groups[1].Value
  Start-Sleep 2
  $after=(EsxRetry $vmh $evidenceCmd 60 3).StdOut
  $afterInt=([regex]::Match($after,'(?im)^\s*Int Value\s*:\s*(-?\d+)\s*$')).Groups[1].Value
  $afterGlobal=([regex]::Match($after,'(?im)^\s*IPv6 Enabled\s*:\s*(true|false)\s*$')).Groups[1].Value
  $afterKnown=($afterInt -in '0','1')
  $afterConflict=($afterKnown -and $afterGlobal -in 'true','false' -and (($afterInt -eq '0') -ne ($afterGlobal -eq 'false')))
  $verified=($afterInt -eq '0' -and !$afterConflict -and $afterGlobal -ne 'true')
  $artifact=Save-DiagnosticArtifact IPV6 "$h-remediation" ([ordered]@{Host=$h;Before=[ordered]@{IntValue=$beforeInt;GlobalValue=$beforeGlobal;Evidence=$before};PowerCLI=[ordered]@{Success=$powerCliSuccess;Message=$powerCliMessage};ESXCLI=[ordered]@{NetworkIpSetRC=$networkRc;AdvancedSetRC=$advancedRc;Output=$disableOut};After=[ordered]@{IntValue=$afterInt;GlobalValue=$afterGlobal;VerifiedDisabled=$verified;EvidenceConflict=$afterConflict;PersistentValueKnown=$afterKnown;Evidence=$after};RebootRequired=$true})
  if(!$verified){Log "[$h] IPv6 remediation failed verification. IntValueAfter=$afterInt; GlobalAfter=$afterGlobal; Artifact=$artifact" ERROR;return Check Fail "Persistent IPv6 disable not verified (unknown or conflicting evidence=$afterConflict). IntValueAfter=$afterInt; GlobalAfter=$afterGlobal; NetworkRC=$networkRc; AdvancedRC=$advancedRc; PowerCLI=$powerCliSuccess; Artifact=$artifact"}
  Log "[$h] IPv6 persistent setting verified disabled. Reboot required. Artifact=$artifact" PASS
  return Check Remediated "Persistent IPv6 setting verified disabled. IntValueBefore=$beforeInt; IntValueAfter=$afterInt; GlobalBefore=$beforeGlobal; GlobalAfter=$afterGlobal; NetworkRC=$networkRc; AdvancedRC=$advancedRc; PowerCLI=$powerCliSuccess; RebootRequired=True; Artifact=$artifact"
 }catch{$a=Write-ExceptionDiagnostic $_ "IPV6-$h";Log "[$h] IPv6 exception: $($_.Exception.Message); Artifact=$a" ERROR;return Check Fail "IPv6 exception: $($_.Exception.Message); Artifact=$a"}
}
function CanonicalBase([string]$n){$n-replace ':\d+$',''}
function Vsan($vmh,$clean){try{
 if(!$clean){
  $o=((EsxRetry $vmh 'vdq -q -H 2>/dev/null || vdq -q 2>/dev/null || true' 180 3).StdOut).Trim()
  $entries=@();try{$entries=@((Get-EsxCli -VMHost $vmh -V2).vsan.storage.list.Invoke())}catch{}
  $owned=@($entries|Where-Object{
   $vals=@($_.Device,$_.VSANUUID,$_.VSANDiskGroupUUID,$_.VSANDiskGroupName,$_.DisplayName)|ForEach-Object{([string]$_).Trim()}|Where-Object{$_}
   $flags=@($_.IsMounted,$_.Usedbythishost,$_.InCMMDS)|ForEach-Object{([string]$_).Trim()}|Where-Object{$_ -match '^(?i:true|yes|1)$'}
   $vals.Count -gt 0 -or $flags.Count -gt 0
  })
  $eligibleCount=([regex]::Matches($o,'(?im)^\s*State\s*:\s*Eligible for use by VSAN\s*$')).Count
  if($eligibleCount -eq 0){$eligibleCount=([regex]::Matches($o,'(?im)^\s*StoragePoolState\s*:\s*Eligible for use by Storage Pool\s*$')).Count}
  $hasOwnership=$owned.Count -gt 0;$hasEligible=$eligibleCount -gt 0
  $status=if($hasOwnership){'Fail'}elseif($hasEligible){'Pass'}else{'Fail'}
  $note=if($hasOwnership){"Existing vSAN ownership/reference was detected in $($owned.Count) non-empty entry/entries."}elseif($hasEligible){"$eligibleCount raw disk(s) eligible for vSAN. Expected boot/system-device ineligibility is ignored."}else{'No eligible raw vSAN disk was detected.'}
  $ownedText=if($owned.Count){$owned|Format-List Device,VSANUUID,VSANDiskGroupUUID,VSANDiskGroupName,IsMounted,Usedbythishost,InCMMDS|Out-String}else{'None'}
  return Check $status "$note OwnershipEntries=$ownedText; vdq=$o"
 }
 $hv=Get-View -Id $vmh.Id -ErrorAction Stop;$ss=Get-View -Id $hv.ConfigManager.StorageSystem -ErrorAction Stop;$protected=@{};$why=@{}
 function Protect($d,$r){if(!$d){return};$b=CanonicalBase "$d";$protected[$b]=$true;if(!$why[$b]){$why[$b]=[Collections.Generic.List[string]]::new()};$why[$b].Add($r)}
 foreach($m in @($ss.FileSystemVolumeInfo.MountInfo)){if($m.Volume-is[VMware.Vim.HostVmfsVolume]){foreach($e in @($m.Volume.Extent)){Protect $e.DiskName "Mounted VMFS $($m.MountInfo.Path)"}}}
 $x=Get-EsxCli -VMHost $vmh -V2;try{foreach($d in @($x.system.coredump.partition.list.Invoke())){$a=@($d.Active,$d.IsActive,$d.Configured)|Where-Object{$_}|Select-Object -First 1;if("$a"-match'true|yes|active'){Protect (@($d.Name,$d.Device,$d.Partition)|Where-Object{$_}|Select-Object -First 1) 'Active coredump'}}}catch{}
 $disks=@($ss.StorageDeviceInfo.ScsiLun|Where-Object{$_-is[VMware.Vim.HostScsiDisk]});foreach($d in $disks){try{foreach($i in @($ss.RetrieveDiskPartitionInfo(@($d.DeviceName)))){foreach($p in @($i.Spec.Partition)){if("$($p.Type)"-match'VMware\s*(Boot|Diagnostic|Reserved|Locker|OSData)|bootbank|altbootbank|osdata|locker'){Protect $d.CanonicalName "ESXi system $($p.Type)"}}}}catch{}}
 $vslist=($x.vsan.storage.list.Invoke()|Out-String);$done=@();$skip=@();foreach($d in $disks){$c=CanonicalBase $d.CanonicalName;$local=if($d.PSObject.Properties.Name-contains'LocalDisk'){[bool]$d.LocalDisk}elseif($d.PSObject.Properties.Name-contains'IsLocal'){[bool]$d.IsLocal}else{$false};if(!$local){$skip+="$c(non-local)";continue};if($protected[$c]){$skip+="$c(protected:$($why[$c]-join';'))";continue};$before=0;try{foreach($i in @($ss.RetrieveDiskPartitionInfo(@($d.DeviceName)))){$before+=@($i.Spec.Partition).Count}}catch{$before=-1};if($before-le0-and$vslist-notmatch[regex]::Escape($c)){continue}
  try{$cmd=$x.vsan.storage.remove;$a=$cmd.CreateArgs();$an='ssd','device','disk','diskname'|Where-Object{$a.PSObject.Properties.Name-contains$_}|Select-Object -First 1;if($an){$a.$an=$c;foreach($p in 'evacuationmode','evacuation_mode','mode'){if($a.PSObject.Properties.Name-contains$p){try{$a.$p='noAction'}catch{}}};foreach($p in 'force','noaction'){if($a.PSObject.Properties.Name-contains$p){try{$a.$p=$true}catch{}}};$null=$cmd.Invoke($a)}}catch{Log "[$($vmh.Name)] vSAN remove warning $c`: $($_.Exception.Message)" WARN}
  $empty=New-Object VMware.Vim.HostDiskPartitionSpec;$ss.UpdateDiskPartitions($d.DeviceName,$empty);$ss.RescanAllHba();$ss.RescanVmfs();$ss.RefreshStorageSystem();$done+="$c before=$before"
 }
 Start-Sleep 3;$vdq=((EsxRetry $vmh 'vdq -q -H 2>/dev/null || vdq -q 2>/dev/null || true' 180 3).StdOut).Trim();Check $(if($vdq-match'Ineligible|Has partitions|Reason:\s*(?!None)'){'Fail'}else{'Remediated'}) "Cleaned=$($done-join', '); Protected/skipped=$($skip-join', '); vdq=$vdq"
}catch{Check Fail $_.Exception.Message}}
function RunHost($t){$server=$null;$vmh=$null;$h=SafeLower $t.TargetHost;$details=@();$reboot=$false;try{Log "[$h] Connecting with PowerCLI...";if(!(WaitTcp $h 443 120)){throw 'TCP/443 not reachable after 120 seconds.'};$server=ConnectRetry $h $t.Username $t.Password;$vmh=Get-VMHost -Server $server|Select-Object -First 1;if(!$vmh){throw 'No VMHost object returned.'};$script:CurrentShellUser=$t.Username;$script:CurrentShellPassword=$t.Password;if($rebootAuthorized){if(!(TestRebootPreflight $vmh $h)){throw 'Reboot preflight failed. No remediation attempted.'};$script:PreflightPassed=$true};EnableSsh $vmh;$dnsSet=SetHostDns $vmh $h $txtDns.Text $txtDomains.Text ([bool]$chkApply.IsChecked);Log "[$h] Hostname/DNS/Domain Set: $($dnsSet.Status)";$dnsfr=TestDnsResolution $h;Log "[$h] DNS Forward/Reverse: $($dnsfr.Status)";$dnsr=TestDnsReach $vmh $txtDns.Text $h;Log "[$h] DNS Reachability: $($dnsr.Status)";$dnsVerify=VerifyHostDns $vmh $h $txtDns.Text $txtDomains.Text $dnsr;Log "[$h] Hostname/DNS/Domain Verify: $($dnsVerify.Status)";$ntp=TestSetNtp $vmh $txtNtp.Text ([bool]$chkApply.IsChecked);Log "[$h] NTP Config: $($ntp.Status)";Log "[$h] NTP Sync: $($ntp.SyncStatus)";$td=TestTimeDrift $vmh;Log "[$h] Time Drift: $($td.Status) $($td.DriftSeconds) seconds";$vs=Vsan $vmh ([bool]$chkClean.IsChecked);Log "[$h] vSAN: $($vs.Status)";$certBefore=CertCheck $h;Log "[$h] Certificate Before Generation: $($certBefore.Status)";$certGen=if(([bool]$chkApply.IsChecked) -and $certBefore.Status -ne 'Pass'){GenCert $vmh $h}else{Check 'N/A' 'Certificate already matched lowercase FQDN or remediation disabled.'};$certSummary=if($certBefore.Status -eq 'Pass'){'Pass'}elseif($certGen.Status -eq 'Remediated'){'Remediated'}else{'Fail'};Log "[$h] Certificate Final: $certSummary";$ver=Check $(if((VerCmp $vmh.Version '9.1.0') -ge 0){'Pass'}else{'Fail'}) "Installed ESX version: $($vmh.Version); required: 9.1.0 or greater";$ip6=IPv6 $vmh ([bool]$chkApply.IsChecked);Log "[$h] IPv6: $($ip6.Status)";$rows=@(('Hostname/DNS/Domain Set',$dnsSet),('Hostname/DNS/Domain Verify',$dnsVerify),('DNS Forward/Reverse',$dnsfr),('DNS Reachability',$dnsr),('NTP Config',$ntp),('NTP Sync',[pscustomobject]@{Status=$ntp.SyncStatus;Detail=$ntp.SyncDetail}),('Time Drift',$td),('vSAN',$vs),('Certificate Before Generation',$certBefore),('Certificate Generation',$certGen),('ESXVersion',$ver),('IPv6',$ip6));foreach($r in $rows){$details+=[pscustomobject]@{Host=$h;Check=$r[0];Status=$r[1].Status;Detail=$r[1].Detail}};$statusList=@($dnsSet.Status,$dnsVerify.Status,$dnsfr.Status,$dnsr.Status,$ntp.Status,$ntp.SyncStatus,$td.Status,$vs.Status,$certSummary,$ver.Status,$ip6.Status);$overall=if(@($statusList|Where-Object{!(PassLike $_)}).Count -eq 0){'Pass'}else{'Fail'};[pscustomobject]@{Summary=[pscustomobject]@{Host=$h;FQDN=$h;HostnameDNSDomainSet=$dnsSet.Status;HostnameDNSDomainVerify=$dnsVerify.Status;DNSForwardReverse=$dnsfr.Status;DNSReachability=$dnsr.Status;NTPConfig=$ntp.Status;NTPSync=$ntp.SyncStatus;TimeDrift=$td.Status;TimeDriftSeconds=$td.DriftSeconds;vSAN=$vs.Status;Certificate=$certSummary;ESXVersion=$ver.Status;IPv6=$ip6.Status;Overall=$overall};Details=$details}}catch{Log "[$h] Connect/run failed: $($_.Exception.Message)" ERROR;[pscustomobject]@{Summary=[pscustomobject]@{Host=$h;FQDN=$h;HostnameDNSDomainSet='Fail';HostnameDNSDomainVerify='Fail';DNSForwardReverse='Fail';DNSReachability='Fail';NTPConfig='Fail';NTPSync='Fail';TimeDrift='Fail';TimeDriftSeconds=$null;vSAN='Fail';Certificate='Fail';ESXVersion='Fail';IPv6='Fail';Overall='Fail'};Details=@([pscustomobject]@{Host=$h;Check='Connect/Run';Status='Fail';Detail=$_.Exception.Message})}}finally{try{if($vmh){DisableSsh $vmh}}catch{};if($server){Disconnect-VIServer -Server $server -Force -Confirm:$false -ErrorAction SilentlyContinue|Out-Null}}}
function ExportReport($sum,$det){$p=Join-Path $script:RunDir ("VCF91-ESX-Validation-"+(Get-Date -Format yyyyMMdd-HHmmss)+'.xlsx');if(HasMod ImportExcel){Import-Module ImportExcel -ErrorAction SilentlyContinue;$sum|Export-Excel -Path $p -WorksheetName Hosts -AutoSize;$det|Export-Excel -Path $p -WorksheetName Details -AutoSize -Append}else{$p=$p.Replace('.xlsx','.csv');$sum|Export-Csv -NoTypeInformation -Path $p};$script:LastReportPath=$p;Log "Report saved: $p";$p}
function AddPoolName($n,$id=$null,$raw=$null){$n=([string]$n).Trim();if(!$n){return};foreach($i in @($cmbPool.Items)){if([string]$i.Content -eq $n){return}};$ci=New-Object System.Windows.Controls.ComboBoxItem;$ci.Content=$n;$ci.Tag=[pscustomobject]@{name=$n;id=$id;raw=$raw};[void]$cmbPool.Items.Add($ci)}
function InvokeJson($m,$u,$h=@{},$b=$null){$p=@{Method=$m;Uri=$u;Headers=$h;SkipCertificateCheck=$true;ErrorAction='Stop'};if($null-ne$b){$p.Body=($b|ConvertTo-Json -Depth 50);$p.ContentType='application/json'};$wr=Invoke-WebRequest @p;if($wr.Content){$wr.Content|ConvertFrom-Json}}
function ConnectPools{$fqdn=([string]$txtSddc.Text).Trim();$u=([string]$txtSddcUser.Text).Trim();$p=[string]$txtSddcPass.Password;if(!$fqdn -or !$u -or !$p){throw 'SDDC Manager FQDN, user, and password are required.'};$base=if($fqdn -match '^https?://'){$fqdn.TrimEnd('/')}else{"https://$fqdn"};$cmbPool.Items.Clear();$tok=InvokeJson POST "$base/v1/tokens" @{} @{username=$u;password=$p};$token=@($tok.accessToken,$tok.access_token,$tok.token,$tok.idToken,$tok.id_token)|Where-Object{$_}|Select-Object -First 1;if(!$token){throw 'Token response did not include a token.'};$np=InvokeJson GET "$base/v1/network-pools" @{Authorization="Bearer $token";Accept='application/json'};$items=@($np.elements);if(!$items){$items=@($np.networkPools)};if(!$items){$items=@($np.items)};foreach($pool in $items){$name=@($pool.name,$pool.networkPoolName,$pool.displayName)|Where-Object{$_}|Select-Object -First 1;$id=@($pool.id,$pool.networkPoolId,$pool.uuid)|Where-Object{$_}|Select-Object -First 1;if($name){AddPoolName $name $id $pool}};if($cmbPool.Items.Count){$cmbPool.SelectedIndex=0;Log "Loaded $($cmbPool.Items.Count) Network Pool name(s) from $base.";[System.Windows.MessageBox]::Show('Connected. Network Pool inventory loaded.','Connected')|Out-Null}else{throw 'No Network Pool names returned.'}}
function StorageCode($s){switch -Regex($s){'^vSAN OSA$'{'VSAN';break}'^vSAN Remote$'{'VSAN_REMOTE';break}'^vSAN ESA$'{'VSAN_ESA';break}'^vSAN Max$'{'VSAN_MAX';break}'^NFS$'{'NFS';break}'^VMFS on FC$'{'VMFS_FC';break}'^vVol$'{'VVOL';break}default{$s}}}
function GenJson{$targets=@(TargetRows);if(!$targets){throw 'No valid hosts.'};$missing=@($targets|Where-Object{[string]::IsNullOrWhiteSpace($_.Password)}|ForEach-Object{$_.TargetHost});if($missing.Count){throw "Enter an ESXi password for every target host before generating JSON: $($missing -join ', ')"};$np=if($cmbPool.SelectedItem -and $cmbPool.SelectedItem.Tag){[string]$cmbPool.SelectedItem.Tag.name}else{([string]$cmbPool.Text).Trim()};if(!$np){throw 'Select or type Network Pool Name.'};$storage=if($cmbStorage.SelectedItem){([System.Windows.Controls.ComboBoxItem]$cmbStorage.SelectedItem).Content.ToString()}else{'vSAN OSA'};$code=StorageCode $storage;$hosts=@();foreach($t in $targets){$hosts += [ordered]@{fqdn=$t.TargetHost;username=$t.Username;storageType=$code;password=$t.Password;networkPoolName=$np;vvolStorageProtocolType=''}};$path=Join-Path $script:RunDir ("bulk-commission-hosts-"+(Get-Date -Format yyyyMMdd-HHmmss)+'.json');([ordered]@{hosts=$hosts})|ConvertTo-Json -Depth 50|Out-File $path -Encoding UTF8;Log "Bulk commission JSON generated: $path";try{Start-Process notepad.exe $path}catch{Invoke-Item $path}}

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
  $script:RunDir=$j.RunDir;$script:LogFile=$j.LogFile
  $script:DebugArtifactDir=Join-Path $script:RunDir 'Debug-Artifacts'
  $txtDns=[pscustomobject]@{Text=$j.Dns};$txtDomains=[pscustomobject]@{Text=$j.Domains}
  $txtNtp=[pscustomobject]@{Text=$j.Ntp}
  if($j.Clean -and !$j.Apply){throw 'Destructive cleanup requires remediation authorization.'}
  if($j.Reboot -ne $j.Apply){throw 'Worker mode mismatch: reboot authorization must match Apply remediation.'}
  $chkApply=[pscustomobject]@{IsChecked=[bool]$j.Apply}
  $chkClean=[pscustomobject]@{IsChecked=[bool]$j.Clean}
  $rebootAuthorized=[bool]$j.Apply
  $script:PreflightPassed=$false
  $h=SafeLower $j.Target.TargetHost
  if(!$j.Apply){
   Log "[$h] Validation-only phase: no reboot will be requested."
   $result=RunHost $j.Target
   $result.Summary|Add-Member -NotePropertyName Phase -NotePropertyValue 'Validation only' -Force
   $result.Summary|Add-Member -NotePropertyName RebootStatus -NotePropertyValue 'N/A' -Force
   $result.Summary|Add-Member -NotePropertyName PostRebootStatus -NotePropertyValue 'N/A' -Force
  }else{
   Log "[$h] Phase 1/3: applying remediation and recording pre-reboot results."
   $first=RunHost $j.Target
   $preOverall=$first.Summary.Overall
   $detail=@($first.Details|ForEach-Object{[pscustomobject]@{Host=$_.Host;Check="Pre-reboot / $($_.Check)";Status=$_.Status;Detail=$_.Detail}})
   if($script:PreflightPassed){
    Log "[$h] Phase 2/3: reboot required even if pre-reboot checks failed."
    $rebootResult=InvokeSingleRebootAndWait $j.Target 1200
   }else{
    $rebootResult=Check Fail 'No reboot requested: preflight did not complete successfully before remediation.'
    Log "[$h] $($rebootResult.Detail)" ERROR
   }
   $detail+=,[pscustomobject]@{Host=$h;Check='Reboot verification';Status=$rebootResult.Status;Detail=$rebootResult.Detail}
   if($rebootResult.Status -eq 'Pass'){
    Log "[$h] Phase 3/3: exactly one fresh validation-only pass; remediation and reboot are disabled."
    $chkApply.IsChecked=$false;$chkClean.IsChecked=$false;$rebootAuthorized=$false
    $second=RunHost $j.Target
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
    $summary|Add-Member -NotePropertyName Phase -NotePropertyValue 'Reboot not verified' -Force
    $summary|Add-Member -NotePropertyName PreRebootOverall -NotePropertyValue $preOverall -Force
    $summary|Add-Member -NotePropertyName RebootStatus -NotePropertyValue 'Fail' -Force
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
function InvokeParallelHosts($targets,[int]$throttle){
 $throttle=[Math]::Max(3,[Math]::Min(5,$throttle));$script:CompletedCount=0;$script:TotalCount=@($targets).Count;$q=[Collections.Generic.Queue[object]]::new();$targets|ForEach-Object{$q.Enqueue($_)};$a=@();$done=@();$pwsh=(Get-Process -Id $PID).Path
 InitializeUiLogTail
 while($q.Count-or$a.Count){
  if($script:StopRequested -and $q.Count){
   $skipped=$q.Count
   while($q.Count){
    $skip=$q.Dequeue();$h=$skip.TargetHost
    $done+=,[pscustomobject]@{Summary=[pscustomobject]@{Host=$h;FQDN=$h;Overall='Skipped'};Details=@([pscustomobject]@{Host=$h;Check='Queue';Status='Skipped';Detail='Not started: operator stopped queuing new hosts.'})}
   }
   $script:CompletedCount+=$skipped;UpdateRunStatus
   Log "Stop queue: $skipped host(s) skipped; $($a.Count) active worker(s) will finish normally." WARN
  }
  while($q.Count-and$a.Count-lt$throttle -and !$script:StopRequested){
   $t=$q.Dequeue();$id=[guid]::NewGuid().ToString('N');$i=Join-Path $script:RunDir "worker-$id-in.xml";$o=Join-Path $script:RunDir "worker-$id-out.xml"
   [pscustomobject]@{Target=$t;Dns=$txtDns.Text;Domains=$txtDomains.Text;Ntp=$txtNtp.Text;Apply=[bool]$chkApply.IsChecked;Clean=[bool]$chkClean.IsChecked;Reboot=[bool]$chkApply.IsChecked;RunDir=$script:RunDir;LogFile=$script:LogFile}|Export-Clixml $i -Depth 10
   $stderr=Join-Path $script:RunDir "worker-$id-stderr.log"
   $stdout=Join-Path $script:RunDir "worker-$id-stdout.log"
   # Start-Process combines ArgumentList into one command line. Quote paths containing spaces.
   $workerArgs=@('-NoProfile','-NonInteractive','-ExecutionPolicy','Bypass','-File',('"'+$PSCommandPath+'"'),'-WorkerInput',('"'+$i+'"'),'-WorkerOutput',('"'+$o+'"'))
   try{
    $p=Start-Process -FilePath $pwsh -ArgumentList $workerArgs -WindowStyle Hidden -PassThru -RedirectStandardError $stderr -RedirectStandardOutput $stdout -ErrorAction Stop
    $a+=[pscustomobject]@{P=$p;T=$t;I=$i;O=$o;StdErr=$stderr;StdOut=$stdout}
    Log "[$($t.TargetHost)] Worker started. PID=$($p.Id); active=$($a.Count)/$throttle"
   }catch{
    $h=$t.TargetHost;$msg="Worker launch failed: $($_.Exception.Message)"
    Log "[$h] $msg" ERROR
    Remove-Item -LiteralPath $i -Force -ErrorAction SilentlyContinue
    $done+=,[pscustomobject]@{Summary=[pscustomobject]@{Host=$h;FQDN=$h;Overall='Fail'};Details=@([pscustomobject]@{Host=$h;Check='Worker';Status='Fail';Detail=$msg})}
   }
   UpdateRunStatus;SyncUiLogTail
  }
  foreach($w in @($a)){if($w.P.HasExited){
   SyncUiLogTail
   $errText=if(Test-Path -LiteralPath $w.StdErr){([string](Get-Content -LiteralPath $w.StdErr -Raw -ErrorAction SilentlyContinue)).Trim()}else{''}
   try{if(!(Test-Path -LiteralPath $w.O)){throw 'Worker produced no result file.'};$r=Import-Clixml -LiteralPath $w.O -ErrorAction Stop;if(!$r -or (!$r.Summary -and !$r.Error)){throw 'Worker result was empty.'}}catch{$r=[pscustomobject]@{Error=$_.Exception.Message}}
   $a=@($a|Where-Object{$_-ne$w})
   if($r.Error){
    $h=$w.T.TargetHost;$msg="$($r.Error) ExitCode=$($w.P.ExitCode); stderr=$errText; stderr file=$($w.StdErr)"
    Log "[$h] Worker failed: $msg" ERROR
    $r=[pscustomobject]@{Summary=[pscustomobject]@{Host=$h;FQDN=$h;Overall='Fail'};Details=@([pscustomobject]@{Host=$h;Check='Worker';Status='Fail';Detail=$msg})}
   }
   Remove-Item -LiteralPath $w.I -Force -ErrorAction SilentlyContinue
   $done+=,$r;$script:CompletedCount++;UpdateRunStatus;Log "[$($w.T.TargetHost)] Worker completed. Remaining=$($q.Count+$a.Count)";SyncUiLogTail
  }}
  SyncUiLogTail;DoEvents;Start-Sleep -Milliseconds 250
 }
 SyncUiLogTail;return $done
}

$xaml=@'
<Window xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation" xmlns:x="http://schemas.microsoft.com/winfx/2006/xaml" Title="VCF 9.1 ESX Host Validation and JSON Generator" Height="850" Width="1400" MinWidth="1040" WindowStartupLocation="CenterScreen" Background="#050A0D" Foreground="#E6E6E6" FontFamily="Segoe UI"><Window.Resources><Style TargetType="Button"><Setter Property="Background" Value="#D7DCE2"/><Setter Property="Foreground" Value="#111111"/><Setter Property="BorderBrush" Value="#7F8A96"/><Setter Property="Padding" Value="8,4"/><Setter Property="Margin" Value="4,3,4,3"/><Setter Property="Height" Value="28"/></Style><Style TargetType="TextBlock"><Setter Property="Foreground" Value="#E6E6E6"/><Setter Property="Margin" Value="0,4,8,4"/></Style><Style TargetType="TextBox"><Setter Property="Background" Value="#050A0D"/><Setter Property="Foreground" Value="#E6E6E6"/><Setter Property="BorderBrush" Value="#607D8B"/><Setter Property="Padding" Value="4"/><Setter Property="CaretBrush" Value="#E6E6E6"/></Style><Style TargetType="PasswordBox"><Setter Property="Background" Value="#050A0D"/><Setter Property="Foreground" Value="#E6E6E6"/><Setter Property="BorderBrush" Value="#607D8B"/><Setter Property="Padding" Value="4"/><Setter Property="CaretBrush" Value="#E6E6E6"/></Style><Style TargetType="ComboBox"><Setter Property="Height" Value="24"/></Style><Style TargetType="GroupBox"><Setter Property="Foreground" Value="#E6E6E6"/><Setter Property="Background" Value="#0A1418"/><Setter Property="BorderBrush" Value="#D7DCE2"/><Setter Property="Margin" Value="6"/><Setter Property="Padding" Value="8"/></Style><Style x:Key="GridText" TargetType="TextBlock"><Setter Property="Foreground" Value="#E6E6E6"/><Setter Property="Background" Value="#050A0D"/><Setter Property="Padding" Value="4,1,4,1"/></Style><Style x:Key="GridEdit" TargetType="TextBox"><Setter Property="Foreground" Value="#E6E6E6"/><Setter Property="Background" Value="#050A0D"/><Setter Property="BorderBrush" Value="#0078D7"/></Style><Style TargetType="DataGridColumnHeader"><Setter Property="Background" Value="#D7DCE2"/><Setter Property="Foreground" Value="#111111"/><Setter Property="FontWeight" Value="SemiBold"/></Style><Style TargetType="DataGrid"><Setter Property="Background" Value="#050A0D"/><Setter Property="Foreground" Value="#E6E6E6"/><Setter Property="RowBackground" Value="#050A0D"/><Setter Property="AlternatingRowBackground" Value="#050A0D"/><Setter Property="GridLinesVisibility" Value="All"/><Setter Property="HorizontalGridLinesBrush" Value="#607D8B"/><Setter Property="VerticalGridLinesBrush" Value="#607D8B"/><Setter Property="BorderBrush" Value="#607D8B"/><Setter Property="HeadersVisibility" Value="Column"/><Setter Property="RowHeaderWidth" Value="0"/></Style><Style TargetType="DataGridRow"><Setter Property="Background" Value="#050A0D"/><Setter Property="Foreground" Value="#E6E6E6"/></Style><Style TargetType="TabControl"><Setter Property="Background" Value="#050A0D"/></Style><Style TargetType="TabItem"><Setter Property="Foreground" Value="#111111"/><Setter Property="Padding" Value="8,3"/></Style></Window.Resources><Grid Margin="12" Background="#050A0D"><Grid.RowDefinitions><RowDefinition Height="Auto"/><RowDefinition Height="*"/><RowDefinition Height="180"/><RowDefinition Height="Auto"/></Grid.RowDefinitions><Grid Grid.Row="0"><Grid.ColumnDefinitions><ColumnDefinition Width="1*" MinWidth="440"/><ColumnDefinition Width="1.65*" MinWidth="560"/></Grid.ColumnDefinitions><GroupBox Header="Prerequisites" Grid.Column="0"><Grid><Grid.RowDefinitions><RowDefinition Height="42"/><RowDefinition Height="Auto"/></Grid.RowDefinitions><UniformGrid Columns="4"><StackPanel Orientation="Horizontal"><TextBlock Text="PowerShell:"/><TextBlock x:Name="lblPS"/></StackPanel><StackPanel Orientation="Horizontal"><TextBlock Text="VCF PowerCLI:"/><TextBlock x:Name="lblPCLI"/></StackPanel><StackPanel Orientation="Horizontal"><TextBlock Text="ImportExcel:"/><TextBlock x:Name="lblExcel"/></StackPanel><StackPanel Orientation="Horizontal"><TextBlock Text="Posh-SSH:"/><TextBlock x:Name="lblSsh"/></StackPanel></UniformGrid><StackPanel Grid.Row="1" Orientation="Horizontal"><Button x:Name="btnRecheck" Content="Recheck"/><Button x:Name="btnInstallPowerCLI" Content="Install VCF PowerCLI"/><Button x:Name="btnInstallExcel" Content="Install ImportExcel"/><Button x:Name="btnInstallSSH" Content="Install Posh-SSH"/></StackPanel></Grid></GroupBox><GroupBox Header="Desired ESX Configuration" Grid.Column="1"><Grid Margin="6"><Grid.ColumnDefinitions><ColumnDefinition Width="110"/><ColumnDefinition Width="2*"/><ColumnDefinition Width="24"/><ColumnDefinition Width="110"/><ColumnDefinition Width="1.15*"/></Grid.ColumnDefinitions><Grid.RowDefinitions><RowDefinition Height="32"/><RowDefinition Height="32"/><RowDefinition Height="30"/><RowDefinition Height="26"/></Grid.RowDefinitions><TextBlock Text="DNS servers" VerticalAlignment="Center"/><TextBox x:Name="txtDns" Grid.Column="1" VerticalAlignment="Center"/><TextBlock Grid.Column="3" Text="Search domains" Margin="12,4,8,4" VerticalAlignment="Center"/><TextBox x:Name="txtDomains" Grid.Column="4" VerticalAlignment="Center"/><TextBlock Grid.Row="1" Text="NTP servers" VerticalAlignment="Center"/><TextBox x:Name="txtNtp" Grid.Row="1" Grid.Column="1" VerticalAlignment="Center"/><StackPanel Grid.Row="2" Grid.Column="1" Grid.ColumnSpan="4" Orientation="Horizontal" Margin="0,4,0,0"><CheckBox x:Name="chkApply" Content="Apply remediation" Foreground="#E6E6E6" IsChecked="False" Margin="0,0,24,0"/><CheckBox x:Name="chkClean" Content="Clean vSAN residue" Foreground="#E6E6E6" IsEnabled="False" Margin="0,0,24,0"/></StackPanel><TextBlock x:Name="lblRunMode" Grid.Row="3" Grid.Column="1" Grid.ColumnSpan="4" Text="Validation only. No host remediation or reboot." Foreground="LightGreen"/></Grid></GroupBox></Grid><TabControl Grid.Row="1" Margin="0,8,0,0"><TabItem Header="Validation"><Grid Margin="8" Background="#050A0D"><Grid.RowDefinitions><RowDefinition Height="*"/><RowDefinition Height="24"/><RowDefinition Height="Auto"/></Grid.RowDefinitions><DataGrid x:Name="gridValidation" AutoGenerateColumns="False" CanUserAddRows="False"><DataGrid.Columns><DataGridTextColumn Header="Host FQDN" Binding="{Binding TargetHost}" Width="2*" ElementStyle="{StaticResource GridText}" EditingElementStyle="{StaticResource GridEdit}"/><DataGridTextColumn Header="User Name" Binding="{Binding Username}" Width="*" ElementStyle="{StaticResource GridText}" EditingElementStyle="{StaticResource GridEdit}"/><DataGridTemplateColumn Header="Password" Width="*"><DataGridTemplateColumn.CellTemplate><DataTemplate><TextBlock><TextBlock.Style><Style TargetType="TextBlock" BasedOn="{StaticResource GridText}"><Setter Property="Text" Value="********"/><Style.Triggers><DataTrigger Binding="{Binding Password}" Value=""><Setter Property="Text" Value=""/></DataTrigger><DataTrigger Binding="{Binding Password}" Value="{x:Null}"><Setter Property="Text" Value=""/></DataTrigger></Style.Triggers></Style></TextBlock.Style></TextBlock></DataTemplate></DataGridTemplateColumn.CellTemplate><DataGridTemplateColumn.CellEditingTemplate><DataTemplate><PasswordBox ToolTip="Enter password to set or replace the password for this host."/></DataTemplate></DataGridTemplateColumn.CellEditingTemplate></DataGridTemplateColumn></DataGrid.Columns></DataGrid><TextBlock x:Name="lblCredentials" Grid.Row="1" Text="No host passwords entered." Foreground="Orange"/><StackPanel Grid.Row="2" Orientation="Horizontal" Margin="0,4,0,0"><Button x:Name="btnRun" Content="Validate / Remediate Hosts"/><TextBlock Text="Parallel nodes:" VerticalAlignment="Center"/><ComboBox x:Name="cmbParallel" Width="54" SelectedIndex="1"><ComboBoxItem>3</ComboBoxItem><ComboBoxItem>4</ComboBoxItem><ComboBoxItem>5</ComboBoxItem></ComboBox><Button x:Name="btnAdd" Content="Add Host"/><Button x:Name="btnRemove" Content="Remove Selected"/><Button x:Name="btnLoad" Content="Load CSV"/><Button x:Name="btnSave" Content="Save CSV"/><Button x:Name="btnExample" Content="Save Example CSV"/></StackPanel></Grid></TabItem><TabItem Header="Results"><DataGrid x:Name="gridResults" AutoGenerateColumns="True" IsReadOnly="True"/></TabItem><TabItem Header="JSON Generator"><Grid Margin="8" Background="#050A0D"><GroupBox Header="Bulk Commission JSON Settings"><Grid><Grid.ColumnDefinitions><ColumnDefinition Width="160"/><ColumnDefinition Width="*"/></Grid.ColumnDefinitions><Grid.RowDefinitions><RowDefinition Height="34"/><RowDefinition Height="34"/><RowDefinition Height="34"/><RowDefinition Height="34"/><RowDefinition Height="34"/><RowDefinition Height="Auto"/></Grid.RowDefinitions><TextBlock Text="SDDC Manager FQDN"/><TextBox x:Name="txtSddc" Grid.Column="1"/><TextBlock Grid.Row="1" Text="User"/><TextBox x:Name="txtSddcUser" Grid.Row="1" Grid.Column="1" Text="administrator@vsphere.local"/><TextBlock Grid.Row="2" Text="Password"/><PasswordBox x:Name="txtSddcPass" Grid.Row="2" Grid.Column="1"/><TextBlock Grid.Row="3" Text="Network Pool Name"/><ComboBox x:Name="cmbPool" Grid.Row="3" Grid.Column="1" IsEditable="True"/><TextBlock Grid.Row="4" Text="Storage Type"/><ComboBox x:Name="cmbStorage" Grid.Row="4" Grid.Column="1" SelectedIndex="0"><ComboBoxItem>vSAN OSA</ComboBoxItem><ComboBoxItem>vSAN Remote</ComboBoxItem><ComboBoxItem>vSAN ESA</ComboBoxItem><ComboBoxItem>vSAN Max</ComboBoxItem><ComboBoxItem>NFS</ComboBoxItem><ComboBoxItem>VMFS on FC</ComboBoxItem><ComboBoxItem>vVol</ComboBoxItem></ComboBox><StackPanel Grid.Row="5" Grid.ColumnSpan="2" Orientation="Horizontal" HorizontalAlignment="Center"><Button x:Name="btnConnect" Content="Connect" Width="120"/><Button x:Name="btnJson" Content="Generate JSON" Width="130"/></StackPanel></Grid></GroupBox></Grid></TabItem></TabControl><GroupBox Grid.Row="2" Header="Log"><TextBox x:Name="txtLog" IsReadOnly="True" TextWrapping="Wrap" VerticalScrollBarVisibility="Auto" HorizontalScrollBarVisibility="Auto" FontFamily="Consolas" FontSize="12" Background="#050A0D" Foreground="#E6E6E6"/></GroupBox><StackPanel Grid.Row="3" Orientation="Horizontal" HorizontalAlignment="Center"><Button x:Name="btnOpen" Content="Open Report"/><Button x:Name="btnClose" Content="Close"/><Button x:Name="btnStop" Content="Stop Queuing New Hosts" IsEnabled="False"/><TextBlock x:Name="lblProgress" Text="Idle" VerticalAlignment="Center"/></StackPanel></Grid></Window>
'@
$w=[Windows.Markup.XamlReader]::Parse($xaml)
foreach($n in 'lblPS','lblPCLI','lblExcel','lblSsh','btnRecheck','btnInstallPowerCLI','btnInstallExcel','btnInstallSSH','txtDns','txtDomains','txtNtp','cmbParallel','chkApply','chkClean','lblRunMode','lblProgress','lblCredentials','gridValidation','gridResults','btnAdd','btnRemove','btnLoad','btnSave','btnExample','txtLog','btnRun','btnStop','btnOpen','btnClose','txtSddc','txtSddcUser','txtSddcPass','btnConnect','cmbPool','cmbStorage','btnJson'){Set-Variable -Scope Script -Name $n -Value $w.FindName($n)}
$script:Targets=New-Object System.Collections.ObjectModel.ObservableCollection[object];$script:Rows=New-Object System.Collections.ObjectModel.ObservableCollection[object];$gridValidation.ItemsSource=$script:Targets;$gridResults.ItemsSource=$script:Rows;1..2|ForEach-Object{$script:Targets.Add([pscustomobject]@{TargetHost='';Username='root';Password=''})|Out-Null}
$gridValidation.AddHandler([System.Windows.Controls.PasswordBox]::PasswordChangedEvent,[System.Windows.RoutedEventHandler]{param($s,$e);$p=$e.OriginalSource;if($p-is[System.Windows.Controls.PasswordBox]-and$p.DataContext){$p.DataContext.Password=$p.Password;UpdateCredentialStatus}})
$gridValidation.Add_CellEditEnding({param($s,$e);$s.Dispatcher.BeginInvoke([Action]{$gridValidation.Items.Refresh();UpdateCredentialStatus},[System.Windows.Threading.DispatcherPriority]::Background)|Out-Null})
function UpdateCredentialStatus{
 $hosts=@($script:Targets|Where-Object{![string]::IsNullOrWhiteSpace([string]$_.TargetHost)})
 $ready=@($hosts|Where-Object{![string]::IsNullOrWhiteSpace([string]$_.Password)})
 $lblCredentials.Text="Passwords entered: $($ready.Count) of $($hosts.Count) target hosts. Blank means not entered."
 $lblCredentials.Foreground=if($ready.Count -eq $hosts.Count -and $hosts.Count -gt 0){'LightGreen'}else{'Orange'}
}
function UpdateRunStatus{
 if($script:IsRunning){
  $mode=if([bool]$chkApply.IsChecked){'Remediation'}else{'Validation only'}
  $lblProgress.Text="$mode | $($script:CompletedCount) of $($script:TotalCount) completed | Active: $($a.Count) | Queued: $($q.Count)"
 }else{$lblProgress.Text='Idle'}
}
function UpdateRunMode{
 $enabled=[bool]$chkApply.IsChecked
 $chkClean.IsEnabled=$enabled
 if(!$enabled){$chkClean.IsChecked=$false}
 $lblRunMode.Text=if($enabled){'REMEDIATION: one confirmed reboot per eligible host, then one validation-only pass. No retry.'}else{'Validation only. No host remediation or reboot.'}
 $lblRunMode.Foreground=if($enabled){'Orange'}else{'LightGreen'}
}
$chkApply.Add_Checked({UpdateRunMode})
$chkApply.Add_Unchecked({UpdateRunMode})
$btnRecheck.Add_Click({Prereq})
$btnInstallPowerCLI.Add_Click({try{$null=EnsureModule 'VCF.PowerCLI';Prereq}catch{Log $_.Exception.Message ERROR}})
$btnInstallExcel.Add_Click({try{$null=EnsureModule 'ImportExcel';Prereq}catch{Log $_.Exception.Message ERROR}})
$btnInstallSSH.Add_Click({try{$null=EnsureModule 'Posh-SSH';Prereq}catch{Log $_.Exception.Message ERROR}})
$btnOpen.Add_Click({if($script:LastReportPath -and (Test-Path $script:LastReportPath)){Invoke-Item $script:LastReportPath}else{[System.Windows.MessageBox]::Show('No report has been generated yet.','No report')|Out-Null}})
$w.Add_Closing({param($sender,$e)
 if($script:IsRunning){$e.Cancel=$true;[System.Windows.MessageBox]::Show('A run is active. Stop queuing and wait for active workers and the report before closing.','Host run in progress')|Out-Null}
})
$btnClose.Add_Click({$w.Close()})
$btnStop.Add_Click({
 $script:StopRequested=$true;$btnStop.IsEnabled=$false
 Log 'Stop queuing requested. Already-running workers will continue, including any authorized remediation or reboot.' WARN
})
$btnAdd.Add_Click({$script:Targets.Add([pscustomobject]@{TargetHost='';Username='root';Password=''})|Out-Null;UpdateCredentialStatus})
$btnRemove.Add_Click({foreach($i in @($gridValidation.SelectedItems)){$script:Targets.Remove($i)|Out-Null};UpdateCredentialStatus})
$btnLoad.Add_Click({$dlg=New-Object Microsoft.Win32.OpenFileDialog;$dlg.Filter='CSV files (*.csv)|*.csv|All files (*.*)|*.*';if($dlg.ShowDialog()){$script:Targets.Clear();$rows=@(Import-Csv $dlg.FileName);if($rows.Count){$txtDns.Text=$rows[0].DnsServers;$txtDomains.Text=$rows[0].SearchDomains;$txtNtp.Text=$rows[0].NtpServers};$rows|ForEach-Object{$script:Targets.Add([pscustomobject]@{TargetHost=$_.TargetHost;Username=if($_.Username){$_.Username}else{'root'};Password=$_.Password})|Out-Null};UpdateCredentialStatus;Log "Loaded $($rows.Count) rows and saved configuration."}})
$btnSave.Add_Click({$p=Join-Path $script:RunDir 'validation-targets.csv';@(TargetRows)|ForEach-Object{[pscustomobject]@{TargetHost=$_.TargetHost;Username=$_.Username;Password=$_.Password;DnsServers=$txtDns.Text;SearchDomains=$txtDomains.Text;NtpServers=$txtNtp.Text}}|Export-Csv -NoTypeInformation $p;Log "Saved validation CSV: $p";[System.Windows.MessageBox]::Show("WARNING: ESXi passwords were saved in clear text.`n`nProtect this CSV with restrictive NTFS permissions and delete it when no longer needed.`n`n$p",'Plaintext password saved','OK','Warning')|Out-Null})
$btnExample.Add_Click({
 $dlg=New-Object Microsoft.Win32.SaveFileDialog
 $dlg.Filter='CSV files (*.csv)|*.csv';$dlg.FileName='example-validation-targets.csv'
 if($dlg.ShowDialog()){
  @([pscustomobject]@{TargetHost='pod01esx12.corp.example.com';Username='root';Password='';DnsServers='192.0.2.10;192.0.2.11';SearchDomains='corp.example.com';NtpServers='time1.example.com;time2.example.com'})|Export-Csv -NoTypeInformation -Path $dlg.FileName
  Log "Example CSV saved: $($dlg.FileName) (no password included)."
 }
})
$btnConnect.Add_Click({try{ConnectPools}catch{Log $_.Exception.Message ERROR;[System.Windows.MessageBox]::Show($_.Exception.Message,'Network Pool connect failed')|Out-Null}})
$btnJson.Add_Click({try{GenJson;[System.Windows.MessageBox]::Show('JSON generated and opened.','JSON generated')|Out-Null}catch{Log $_.Exception.Message ERROR;[System.Windows.MessageBox]::Show($_.Exception.Message,'Generate JSON failed')|Out-Null}})
$btnRun.Add_Click({
 try{
  if($script:IsRunning){return}
  ValidateInputs
  $targets=@(TargetRows)
  $apply=[bool]$chkApply.IsChecked;$clean=[bool]$chkClean.IsChecked;$reboot=$apply
  if(!$apply -and $clean){throw 'vSAN cleanup requires Apply remediation.'}
  if($clean){
   $warning='DESTRUCTIVE DISK CLEANUP: this can erase data. Verify disk ownership and change approval before continuing.'
   if([System.Windows.MessageBox]::Show($warning,'Destructive vSAN Cleanup','YesNo','Warning') -ne 'Yes'){return}
  }
  $mode=if($apply){'REMEDIATION'}else{'VALIDATION ONLY'}
  $hosts=($targets|ForEach-Object{$_.TargetHost}) -join [Environment]::NewLine
  $message="Mode: $mode`nTargets: $($targets.Count)`nReboot requested: $reboot`nvSAN cleanup: $clean`n`n$hosts`n`n"
  if($apply){$message+='CONFIRM ONE REBOOT PER HOST: only hosts already in maintenance mode with zero powered-on VMs will be remediated. After applying changes, each eligible host is rebooted ONCE even if pre-reboot checks fail. The tool waits up to 20 minutes for a changed boot time, performs ONE validation-only pass, then stops regardless of the final result. It never retries remediation or reboot. IPv6 changes may affect vMotion.'}
  else{$message+='No host remediation, disk cleanup or reboot will be performed. SSH may be enabled temporarily for validation and will be disabled afterward.'}
  if([System.Windows.MessageBox]::Show($message,'Review Host Run','YesNo','Warning') -ne 'Yes'){return}
  $script:IsRunning=$true;$script:StopRequested=$false
  $btnRun.IsEnabled=$false;$btnStop.IsEnabled=$true
  foreach($control in @($chkApply,$chkClean,$gridValidation,$btnAdd,$btnRemove,$btnLoad,$btnSave,$btnExample,$cmbParallel,$btnConnect,$btnJson)){$control.IsEnabled=$false}
  $script:Rows.Clear();$sum=@();$det=@()
  Log "Run started. Mode=$mode; Hosts=$($targets.Count); Reboot=$reboot; Cleanup=$clean"
  $throttle=[int]([System.Windows.Controls.ComboBoxItem]$cmbParallel.SelectedItem).Content
  foreach($r in @(InvokeParallelHosts $targets $throttle)){
   $sum+=$r.Summary;$det+=$r.Details
   $script:Rows.Add($r.Summary)|Out-Null;$gridResults.Items.Refresh();DoEvents
  }
  $rep=ExportReport $sum $det;$bundle=New-DiagnosticBundle
  Log "Readiness complete. Report=$rep; DiagnosticBundle=$bundle"
 }catch{Log $_.Exception.Message ERROR;[System.Windows.MessageBox]::Show($_.Exception.Message,'Run failed')|Out-Null}
 finally{
  $script:IsRunning=$false;$btnStop.IsEnabled=$false;$btnRun.IsEnabled=$true
  foreach($control in @($chkApply,$gridValidation,$btnAdd,$btnRemove,$btnLoad,$btnSave,$btnExample,$cmbParallel,$btnConnect,$btnJson)){$control.IsEnabled=$true}
  UpdateRunMode;UpdateRunStatus;Prereq
 }
})

UpdateRunMode
UpdateCredentialStatus
Prereq
Log "Script started. Output: $script:RunDir"
$w.ShowDialog()|Out-Null
# SIG # Begin signature block
# MIIF2gYJKoZIhvcNAQcCoIIFyzCCBccCAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCBQPAUr92QVzILF
# 0qvQPU3V7FVA+0DdcbMkOPOc8T53fqCCAzgwggM0MIICHKADAgECAhAT5IH8AflW
# vkXGwe16QFlxMA0GCSqGSIb3DQEBCwUAMDIxMDAuBgNVBAMMJ1ZDRjkxIEVTWCBW
# YWxpZGF0aW9uIExvY2FsIENvZGUgU2lnbmluZzAeFw0yNjA5MTMxMzQ1MzBaFw0y
# OTA5MTMxMzU1MzBaMDIxMDAuBgNVBAMMJ1ZDRjkxIEVTWCBWYWxpZGF0aW9uIExv
# Y2FsIENvZGUgU2lnbmluZzCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEB
# AMKM95Z8WyGbTbffYNnb07AJopBE0Vn+Hlu0fQgXy7HBJyugTKljsRWyxC2Y4vM5
# +jPOPrW1NHJTCGDsT6aqVtwtVvlUmv7oK4Y1lEIcDJESj5dtbK55hHAel+A8GlH/
# JPiqnFzuiSR7o+CWYS3OXJ5XQ9zE1IuFdr1HH4uoxlKyjWufMp00T5K9A6g/R7R5
# XHUSaq/8lmThieoaagg3edBxBuVciex1UAc8IVcIbs3JthFuMkgev5LgmXlmerU9
# Zn3RkhGFJlRblyYq9+4F3Ukp1wuxYa+1B5x5vqZeTQLb2vr41L1JUTvOAtlQGFmH
# mMxv0evIH3Ye1ersiOzxehECAwEAAaNGMEQwDgYDVR0PAQH/BAQDAgeAMBMGA1Ud
# JQQMMAoGCCsGAQUFBwMDMB0GA1UdDgQWBBRK/XQn8pqTvy21Je5VIGMiZBIHmDAN
# BgkqhkiG9w0BAQsFAAOCAQEAocCW3xLCG3UuCDvu4QpdYqWZViEBGJPpEhIKKiug
# KKADX4mibTywtSZmxWFseSulaklxkLMCb2B+dr8PJTp9GdWdYcCM3FyIBWy62Rwe
# maI0My7AG6k3b7bUtoaqAWuoR3Wr8ocSlUzQ7qI0o0LRCUU4bSCQqH0o6rDieS04
# 0y7+qvbnQvJwENWvcmKVf5vardVseonWQ51BiVCOJ8I+GZU05FfHnNxtsojYlE6R
# 689hL6hc635px8PfUPjSek9BeOT5OIT0fJM0STDTd23Pl1aNbp/4NHPyl5MwusfA
# 0rgB3oDFKxbjhowVSf5oDJrrNvZfC1vMbrFDsH0FoHe4nDGCAfgwggH0AgEBMEYw
# MjEwMC4GA1UEAwwnVkNGOTEgRVNYIFZhbGlkYXRpb24gTG9jYWwgQ29kZSBTaWdu
# aW5nAhAT5IH8AflWvkXGwe16QFlxMA0GCWCGSAFlAwQCAQUAoIGEMBgGCisGAQQB
# gjcCAQwxCjAIoAKAAKECgAAwGQYJKoZIhvcNAQkDMQwGCisGAQQBgjcCAQQwHAYK
# KwYBBAGCNwIBCzEOMAwGCisGAQQBgjcCARUwLwYJKoZIhvcNAQkEMSIEIJ8S6gH1
# R2566GeQ5Bs7H9VJR+GODrdBwdj7ltYs2tM9MA0GCSqGSIb3DQEBAQUABIIBAInh
# Nq578Kqo1Jr/95Tgfy4hSdLguGGU/VTqJVMs/FoEp+qyewWCJQbcz+liqEwd5LVj
# 8jqdzDskGGPe1t8jteqjsy5YCYEjPBGKuICySwWBLIevhraUcLKoKOiRY12OHClo
# OMHkbLLo2BR5ZpZEz+jIKg5/cAPyU1rnkU3Hi9d1XroySzeOQFk6P6FPcP8QH7QP
# umCf2Nr3heF3EArbJbjjO1jX19680C1nq+30qLlnQ8HlFO8XaEAnVL1zjndFdPGn
# qv3ssRLJ5zZ2o5itxnWD67iMd39U5uMcQMDa1LveidSxSt46e78QS2tfo/t0lOle
# dpJCLjoLAILsKY/s1ts=
# SIG # End signature block
