[CmdletBinding(DefaultParameterSetName = "Goal")]
param(
  [Parameter(Mandatory = $true, Position = 0)]
  [ValidateNotNullOrEmpty()]
  [string]$ProjectPath,

  [Parameter(Mandatory = $true, ParameterSetName = "Goal", Position = 1)]
  [ValidateNotNullOrEmpty()]
  [string]$Goal,

  [Parameter(Mandatory = $true, ParameterSetName = "Spec")]
  [ValidateNotNullOrEmpty()]
  [string]$SpecPath,

  [Parameter(Mandatory = $true, ParameterSetName = "ResumeLatest")]
  [switch]$ResumeLatest,

  [Parameter(Mandatory = $true, ParameterSetName = "ResumeRunId")]
  [ValidateNotNullOrEmpty()]
  [string]$ResumeRunId,

  [Parameter(Mandatory = $true, ParameterSetName = "RecoverFailedRun")]
  [ValidateNotNullOrEmpty()]
  [string]$RecoverFailedRunId,

  [Parameter(Mandatory = $true, ParameterSetName = "RecoverFailedRun")]
  [ValidatePattern("^[0-9a-f]{64}$")]
  [string]$ExpectedDecisionRecoverySha256,

  [string]$LogPath,

  [ValidateSet("EconomySafe", "EconomyMax", "Android", "Strict")]
  [string]$Mode = "EconomySafe",

  [switch]$DoctorOnly,

  [switch]$NoMonitor
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"
$env:PYTHONUTF8 = "1"
$env:PYTHONIOENCODING = "utf-8"

$ForgeRoot = $PSScriptRoot
$ForgeScript = Join-Path $ForgeRoot "forge.py"
$RequestedConfigFile = switch ($Mode) {
  "EconomyMax" { "forge.max-economy.config.json" }
  "Android" { "forge.android.config.json" }
  "Strict" { "forge.strict.config.json" }
  default { "forge.config.json" }
}
$RequestedConfigPath = Join-Path $ForgeRoot $RequestedConfigFile
$StrictConfigPath = Join-Path $ForgeRoot "forge.strict.config.json"
# EconomySafe is the unattended default. On Windows it must use the audited
# WSL2 strict runtime rather than starting natively and failing only after the
# supervisor has already been created.
$UseStrictWslRuntime = $Mode -in @("EconomySafe", "Strict")
$ConfigPath = if ($UseStrictWslRuntime) { $StrictConfigPath } else { $RequestedConfigPath }
$ExitCode = 1
$LastForgeExitCode = 1
$TranscriptStarted = $false
$ResolvedLogPath = $null
$MonitorOpened = $false
$IsResume = $PSCmdlet.ParameterSetName -in @(
  "ResumeLatest",
  "ResumeRunId",
  "RecoverFailedRun"
)
$StrictWslDistribution = "Ubuntu-24.04"
$StrictWslUser = "forge"
$StrictWslForgeRoot = "/home/forge/GPT-Claude-Forge"
$StrictWslPath = "/home/forge/.local/bin:/usr/local/bin:/usr/bin:/bin"

function Test-PythonCandidate {
  param(
    [Parameter(Mandatory = $true)]
    [string]$File,

    [string[]]$PrefixArgs = @()
  )

  if (-not (Test-Path -LiteralPath $File -PathType Leaf)) {
    return $false
  }

  try {
    & $File @PrefixArgs -c "import sys, pydantic; raise SystemExit(0 if sys.version_info >= (3, 11) else 1)" *> $null
    return $LASTEXITCODE -eq 0
  }
  catch {
    return $false
  }
}

function Find-ForgePython {
  $Candidates = @()

  $VenvPython = Join-Path $ForgeRoot ".venv\Scripts\python.exe"
  $Candidates += [pscustomobject]@{ File = $VenvPython; PrefixArgs = @(); Label = "Forge .venv" }

  $PythonCommand = Get-Command python.exe -ErrorAction SilentlyContinue | Select-Object -First 1
  if ($null -ne $PythonCommand) {
    $Candidates += [pscustomobject]@{ File = $PythonCommand.Source; PrefixArgs = @(); Label = "python.exe" }
  }

  $PyLauncher = Get-Command py.exe -ErrorAction SilentlyContinue | Select-Object -First 1
  if ($null -ne $PyLauncher) {
    $Candidates += [pscustomobject]@{ File = $PyLauncher.Source; PrefixArgs = @("-3.12"); Label = "py -3.12" }
  }

  $BundledPython = Join-Path $env:USERPROFILE ".cache\codex-runtimes\codex-primary-runtime\dependencies\python\python.exe"
  $Candidates += [pscustomobject]@{ File = $BundledPython; PrefixArgs = @(); Label = "Codex bundled Python" }

  foreach ($Candidate in $Candidates) {
    if (Test-PythonCandidate -File $Candidate.File -PrefixArgs $Candidate.PrefixArgs) {
      return $Candidate
    }
  }

  throw "Nenasiel sa Python 3.11+ s balikom pydantic. Oprav Forge .venv alebo znovu spusti install_windows.ps1."
}

function Get-StrictWslCommand {
  $WslCommand = Get-Command wsl.exe -ErrorAction SilentlyContinue | Select-Object -First 1
  if ($null -eq $WslCommand) {
    throw "Bezobsluzny rezim $Mode vyzaduje auditovany WSL2 strict runtime, ale wsl.exe sa nenasiel. Forge sa zastavil pred prvym modelovym volanim."
  }
  return $WslCommand.Source
}

function Invoke-StrictWslProbe {
  param(
    [Parameter(Mandatory = $true)]
    [string]$WslExecutable,

    [Parameter(Mandatory = $true)]
    [string[]]$Arguments,

    [switch]$SuppressOutput
  )

  if ($SuppressOutput) {
    # Windows PowerShell promotes native stderr to ErrorRecord objects. The
    # deny-side canary intentionally produces stderr, so keep it non-terminating
    # while still preserving the native exit code.
    $ErrorActionPreference = "Continue"
    & $WslExecutable @(
      "-d", $StrictWslDistribution,
      "-u", $StrictWslUser,
      "--",
      "/usr/bin/env", "PATH=$StrictWslPath"
    ) @Arguments *> $null
    $ProbeExitCode = [int]$LASTEXITCODE
  }
  else {
    $ProbeOutput = & $WslExecutable @(
      "-d", $StrictWslDistribution,
      "-u", $StrictWslUser,
      "--",
      "/usr/bin/env", "PATH=$StrictWslPath"
    ) @Arguments
    $ProbeExitCode = [int]$LASTEXITCODE
  }
  return $ProbeExitCode
}

function Get-StrictWslSha256 {
  param(
    [Parameter(Mandatory = $true)]
    [string]$WslExecutable,

    [Parameter(Mandatory = $true)]
    [string]$Path
  )

  $Output = & $WslExecutable @(
    "-d", $StrictWslDistribution,
    "-u", $StrictWslUser,
    "--",
    "/usr/bin/sha256sum", $Path
  )
  if ($LASTEXITCODE -ne 0 -or [string]::IsNullOrWhiteSpace([string]$Output)) {
    throw "Nepodarilo sa overit SHA-256 WSL suboru: $Path"
  }
  $Hash = ([string]$Output -split "\s+")[0].Trim().ToLowerInvariant()
  if ($Hash -notmatch "^[0-9a-f]{64}$") {
    throw "WSL vratil neplatny SHA-256 pre subor: $Path"
  }
  return $Hash
}

function Assert-StrictWslMirror {
  param(
    [Parameter(Mandatory = $true)]
    [string]$WslExecutable,

    [Parameter(Mandatory = $true)]
    [string]$WindowsPath,

    [Parameter(Mandatory = $true)]
    [string]$WslPath
  )

  $WindowsHash = (Get-FileHash -Algorithm SHA256 -LiteralPath $WindowsPath).Hash.ToLowerInvariant()
  $WslHash = Get-StrictWslSha256 -WslExecutable $WslExecutable -Path $WslPath
  if ($WindowsHash -ne $WslHash) {
    throw "Auditovany WSL Forge mirror sa nezhoduje s Windows zdrojom: $WindowsPath"
  }
}

function Convert-ToStrictWslPath {
  param(
    [Parameter(Mandatory = $true)]
    [string]$WslExecutable,

    [Parameter(Mandatory = $true)]
    [string]$WindowsPath
  )

  $FullPath = [System.IO.Path]::GetFullPath($WindowsPath)
  if ($FullPath -notmatch "^([A-Za-z]):\\(.*)$") {
    throw "Auditovany WSL2 strict runtime podporuje iba lokalnu Windows cestu s pismenom disku: $WindowsPath"
  }
  $Drive = $Matches[1].ToLowerInvariant()
  $RelativePath = $Matches[2].Replace("\", "/")
  $TranslatedPath = if ([string]::IsNullOrWhiteSpace($RelativePath)) {
    "/mnt/$Drive"
  }
  else {
    "/mnt/$Drive/$RelativePath"
  }

  $ProbeOutput = & $WslExecutable @(
    "-d", $StrictWslDistribution,
    "-u", $StrictWslUser,
    "--",
    "/usr/bin/test", "-d", $TranslatedPath
  )
  if ($LASTEXITCODE -ne 0) {
    throw "Nepodarilo sa bezpecne prelozit Windows cestu do WSL: $WindowsPath"
  }
  return $TranslatedPath
}

function Assert-StrictWslProjectSandbox {
  param(
    [Parameter(Mandatory = $true)]
    [string]$WslExecutable,

    [Parameter(Mandatory = $true)]
    [string]$WindowsProjectPath,

    [Parameter(Mandatory = $true)]
    [string]$WslProjectPath,

    [Parameter(Mandatory = $true)]
    [string]$WslPython
  )

  # This is deliberately a project-specific DrvFS canary. It proves both
  # sides of the filesystem policy before any model process starts:
  # one exact harmless file is writable and a second exact sentinel remains
  # protected by denyWrite. No credentials or application files are read.
  $CanaryId = [Guid]::NewGuid().ToString("N")
  $ForgeStateDirectory = Join-Path $WindowsProjectPath ".forge"
  New-Item -ItemType Directory -Force -Path $ForgeStateDirectory | Out-Null
  $AllowedName = "wrapper-srt-canary-$CanaryId.allowed"
  $DeniedName = "wrapper-srt-canary-$CanaryId.denied"
  $SettingsName = "wrapper-srt-canary-$CanaryId.settings.json"
  $AllowedWindowsPath = Join-Path $ForgeStateDirectory $AllowedName
  $DeniedWindowsPath = Join-Path $ForgeStateDirectory $DeniedName
  $SettingsWindowsPath = Join-Path $ForgeStateDirectory $SettingsName
  $WslForgeState = $WslProjectPath.TrimEnd("/") + "/.forge"
  $AllowedWslPath = "$WslForgeState/$AllowedName"
  $DeniedWslPath = "$WslForgeState/$DeniedName"
  $SettingsWslPath = "$WslForgeState/$SettingsName"
  $AllowedToken = "forge-srt-allow-$CanaryId"
  $DeniedToken = "forge-srt-deny-$CanaryId"
  $DeniedAttempt = "forge-srt-overwrite-$CanaryId"
  $Utf8NoBom = New-Object System.Text.UTF8Encoding($false)

  try {
    [System.IO.File]::WriteAllText($AllowedWindowsPath, "unwritten", $Utf8NoBom)
    [System.IO.File]::WriteAllText($DeniedWindowsPath, $DeniedToken, $Utf8NoBom)
    $Settings = [ordered]@{
      network = [ordered]@{
        allowedDomains = @()
        deniedDomains = @()
        strictAllowlist = $true
        allowLocalBinding = $false
        tlsTerminate = [ordered]@{}
      }
      filesystem = [ordered]@{
        denyRead = @(
          "/home/forge/.ssh",
          "/home/forge/.aws",
          "/home/forge/.kube",
          "/home/forge/.claude",
          "/home/forge/.codex",
          "/mnt/c/Users"
        )
        allowRead = @($AllowedWslPath, $DeniedWslPath)
        # Include both exact sentinels in the grant, then carve the protected
        # one back out. This proves denyWrite precedence rather than merely
        # observing the default read-only filesystem.
        allowWrite = @($AllowedWslPath, $DeniedWslPath)
        denyWrite = @($DeniedWslPath)
      }
    }
    [System.IO.File]::WriteAllText(
      $SettingsWindowsPath,
      ($Settings | ConvertTo-Json -Depth 8),
      $Utf8NoBom
    )

    $WriteScript = "from pathlib import Path; import sys; Path(sys.argv[1]).write_text(sys.argv[2], encoding='utf-8')"
    $AllowedExitCode = Invoke-StrictWslProbe `
      -WslExecutable $WslExecutable `
      -SuppressOutput `
      -Arguments @(
        "/usr/bin/env", "-i",
        "PATH=$StrictWslPath",
        "HOME=/home/forge",
        "USER=forge",
        "LOGNAME=forge",
        "LANG=C.UTF-8",
        "/home/forge/.local/bin/srt",
        "--settings", $SettingsWslPath,
        "--",
        $WslPython,
        "-I", "-B", "-c", $WriteScript,
        $AllowedWslPath, $AllowedToken
      )
    if ($AllowedExitCode -ne 0) {
      throw "WSL Sandbox Runtime nedokazal zapisat do presne povoleneho DrvFS canary suboru projektu."
    }
    $AllowedContent = [System.IO.File]::ReadAllText($AllowedWindowsPath, $Utf8NoBom)
    if ($AllowedContent -cne $AllowedToken) {
      throw "WSL Sandbox Runtime vratil uspech, ale obsah povoleneho DrvFS canary suboru nesedi."
    }

    $DeniedExitCode = Invoke-StrictWslProbe `
      -WslExecutable $WslExecutable `
      -SuppressOutput `
      -Arguments @(
        "/usr/bin/env", "-i",
        "PATH=$StrictWslPath",
        "HOME=/home/forge",
        "USER=forge",
        "LOGNAME=forge",
        "LANG=C.UTF-8",
        "/home/forge/.local/bin/srt",
        "--settings", $SettingsWslPath,
        "--",
        $WslPython,
        "-I", "-B", "-c", $WriteScript,
        $DeniedWslPath, $DeniedAttempt
      )
    $DeniedContent = [System.IO.File]::ReadAllText($DeniedWindowsPath, $Utf8NoBom)
    if ($DeniedExitCode -eq 0 -or $DeniedContent -cne $DeniedToken) {
      throw "WSL Sandbox Runtime nepresadil denyWrite nad neuskodnym DrvFS sentinel suborom projektu."
    }
  }
  finally {
    $CleanupFailed = $false
    foreach ($TemporaryPath in @(
      $AllowedWindowsPath,
      $DeniedWindowsPath,
      $SettingsWindowsPath
    )) {
      try {
        if ([System.IO.File]::Exists($TemporaryPath)) {
          [System.IO.File]::Delete($TemporaryPath)
        }
      }
      catch {
        $CleanupFailed = $true
      }
      if ([System.IO.File]::Exists($TemporaryPath)) {
        $CleanupFailed = $true
      }
    }
    if ($CleanupFailed) {
      throw "Docasny WSL Sandbox Runtime canary sa nepodarilo uplne vycistit; Forge sa zastavil pred prvym modelovym volanim."
    }
  }
}

function Find-StrictWslPython {
  $WslExecutable = Get-StrictWslCommand
  $WslForgeScript = "$StrictWslForgeRoot/forge.py"
  $WslConfigPath = "$StrictWslForgeRoot/forge.strict.config.json"
  $WslPython = "$StrictWslForgeRoot/.venv/bin/python"
  $WslSrt = "/home/forge/.local/bin/srt"

  foreach ($RuntimeSource in @("forge.py", "forge_adaptive.py", "forge_reports.py")) {
    Assert-StrictWslMirror `
      -WslExecutable $WslExecutable `
      -WindowsPath (Join-Path $ForgeRoot $RuntimeSource) `
      -WslPath "$StrictWslForgeRoot/$RuntimeSource"
  }
  Assert-StrictWslMirror -WslExecutable $WslExecutable -WindowsPath $StrictConfigPath -WslPath $WslConfigPath

  $PythonExitCode = Invoke-StrictWslProbe -WslExecutable $WslExecutable -Arguments @(
    $WslPython,
    "-c",
    "import sys, pydantic; raise SystemExit(0 if sys.version_info >= (3, 11) else 1)"
  )
  if ($PythonExitCode -ne 0) {
    throw "Auditovany WSL Forge Python 3.11+ s balikom pydantic nie je dostupny."
  }

  $SrtExitCode = Invoke-StrictWslProbe -WslExecutable $WslExecutable -Arguments @(
    $WslSrt,
    "--version"
  )
  if ($SrtExitCode -ne 0) {
    throw "Bezobsluzny Forge sa zastavil pred workerom: overeny WSL Sandbox Runtime (srt) nie je dostupny."
  }

  # A version string alone does not prove that the sandbox backend can start.
  # This canary is local, model-free and performs no project write.
  $SrtCanaryExitCode = Invoke-StrictWslProbe -WslExecutable $WslExecutable -Arguments @(
    $WslSrt,
    "--",
    "/usr/bin/true"
  )
  if ($SrtCanaryExitCode -ne 0) {
    throw "WSL Sandbox Runtime odpoveda na --version, ale funkcny canary nedokazal spustit izolovany proces. Forge sa zastavil pred prvym modelovym volanim."
  }

  return [pscustomobject]@{
    File = $WslExecutable
    PrefixArgs = @(
      "-d", $StrictWslDistribution,
      "-u", $StrictWslUser,
      "--",
      "/usr/bin/env", "PATH=$StrictWslPath",
      $WslPython
    )
    ForgeScript = $WslForgeScript
    ConfigPath = $WslConfigPath
    Label = "Forge WSL2 strict .venv (SRT basic canary OK)"
  }
}

function Assert-NativeSrtFunctional {
  $SrtCommand = Get-Command srt -ErrorAction SilentlyContinue | Select-Object -First 1
  if ($null -eq $SrtCommand) {
    throw "Bezobsluzny rezim $Mode nema na Windows overeny Sandbox Runtime. Pouzi predvoleny EconomySafe/Strict cez auditovany WSL2 runtime alebo najprv nainstaluj a over SRT. Forge sa zastavil pred prvym modelovym volanim."
  }
  & $SrtCommand.Source --version *> $null
  if ($LASTEXITCODE -ne 0) {
    throw "Windows Sandbox Runtime nepresiel kontrolou --version. Forge sa zastavil pred prvym modelovym volanim."
  }
  & $SrtCommand.Source -- powershell.exe -NoProfile -NonInteractive -Command "exit 0" *> $null
  if ($LASTEXITCODE -ne 0) {
    throw "Windows Sandbox Runtime odpoveda na --version, ale funkcny canary nedokazal spustit izolovany proces. Forge sa zastavil pred prvym modelovym volanim."
  }
}

function Test-JsonBoolean {
  param([AllowNull()][object]$Value)
  return $Value -is [bool]
}

function Test-JsonInteger {
  param([AllowNull()][object]$Value)
  return (
    $Value -is [byte] -or
    $Value -is [sbyte] -or
    $Value -is [int16] -or
    $Value -is [uint16] -or
    $Value -is [int32] -or
    $Value -is [uint32] -or
    $Value -is [int64] -or
    $Value -is [uint64]
  )
}

function Assert-ResumeEligibility {
  param(
    [Parameter(Mandatory = $true)][object]$Python,
    [Parameter(Mandatory = $true)][string]$Project,
    [Parameter(Mandatory = $true)][string]$RequestedRunId,
    [Parameter(Mandatory = $true)][string]$SupervisorConfig,
    [string]$ExpectedDecisionRecoverySha256
  )

  $Executable = [string]$Python.File
  $RuntimeForgeScript = if ($Python.PSObject.Properties.Name -contains "ForgeScript") {
    [string]$Python.ForgeScript
  }
  else {
    $ForgeScript
  }
  $Arguments = @($Python.PrefixArgs) + @(
    $RuntimeForgeScript,
    "resume-eligibility",
    "--project", $Project,
    "--run-id", $RequestedRunId,
    "--config", $SupervisorConfig
  )
  if (-not [string]::IsNullOrWhiteSpace($ExpectedDecisionRecoverySha256)) {
    if ($RequestedRunId -eq "latest") {
      throw "Decision recovery vyzaduje presny ResumeRunId; ResumeLatest je zakazany."
    }
    $Arguments += @(
      "--expected-decision-recovery-sha256",
      $ExpectedDecisionRecoverySha256
    )
  }
  $PreviousErrorActionPreference = $ErrorActionPreference
  try {
    # The command is model-free and non-mutating. Keep native stderr
    # non-terminating so a rejected verdict can still be parsed fail-closed.
    $ErrorActionPreference = "Continue"
    $EligibilityOutput = @(& $Executable @Arguments)
    $EligibilityExitCode = [int]$LASTEXITCODE
  }
  finally {
    $ErrorActionPreference = $PreviousErrorActionPreference
  }

  $Eligibility = $null
  try {
    $EligibilityText = ($EligibilityOutput | ForEach-Object { [string]$_ }) -join [Environment]::NewLine
    $Eligibility = $EligibilityText | ConvertFrom-Json
  }
  catch {
    throw "Forge resume-eligibility nevratil jeden citatelny JSON verdikt. Resume sa zastavil pred workerom."
  }

  $EligibleProperty = $Eligibility.PSObject.Properties["eligible"]
  if (
    $null -eq $EligibleProperty -or
    -not (Test-JsonBoolean $EligibleProperty.Value)
  ) {
    throw "Forge resume-eligibility verdikt nema striktne boolean pole 'eligible'."
  }
  if ($EligibilityExitCode -ne 0 -or $Eligibility.eligible -ne $true) {
    $ReasonProperty = $Eligibility.PSObject.Properties["reason_code"]
    $Reason = if ($null -ne $ReasonProperty) {
      [string]$ReasonProperty.Value
    }
    else {
      "invalid_or_rejected_verdict"
    }
    if ([string]::IsNullOrWhiteSpace($Reason)) {
      $Reason = "invalid_or_rejected_verdict"
    }
    throw "Resume eligibility bola zamietnuta ($Reason). Forge sa zastavil pred workerom."
  }

  foreach ($RequiredProperty in @(
    "schema_version",
    "source_run_id",
    "source_stop_reason_code",
    "source_automatic_resume_allowed",
    "action",
    "state_mutated",
    "model_calls_made",
    "supervisor_config_enforced",
    "post_worker_decision_recovery_eligible",
    "bounded_packet_recovery_eligible",
    "budget_tranche_extension_eligible"
  )) {
    if ($null -eq $Eligibility.PSObject.Properties[$RequiredProperty]) {
      throw "Forge resume-eligibility verdiktu chyba povinne pole '$RequiredProperty'."
    }
  }
  if (
    -not (Test-JsonInteger $Eligibility.schema_version) -or
    -not (Test-JsonInteger $Eligibility.model_calls_made) -or
    -not (Test-JsonBoolean $Eligibility.source_automatic_resume_allowed) -or
    -not (Test-JsonBoolean $Eligibility.state_mutated) -or
    -not (Test-JsonBoolean $Eligibility.supervisor_config_enforced) -or
    -not (Test-JsonBoolean $Eligibility.post_worker_decision_recovery_eligible) -or
    -not (Test-JsonBoolean $Eligibility.bounded_packet_recovery_eligible) -or
    -not (Test-JsonBoolean $Eligibility.budget_tranche_extension_eligible)
  ) {
    throw "Forge resume-eligibility verdikt obsahuje neplatne JSON typy."
  }
  foreach ($StringProperty in @(
    "source_run_id",
    "source_stop_reason_code",
    "action",
    "effective_security_profile"
  )) {
    if (
      $null -eq $Eligibility.PSObject.Properties[$StringProperty] -or
      $Eligibility.$StringProperty -isnot [string]
    ) {
      throw "Forge resume-eligibility verdikt obsahuje neplatny JSON typ pola '$StringProperty'."
    }
  }
  $ExactSourceRunId = [string]$Eligibility.source_run_id
  if (
    $ExactSourceRunId -notmatch "^[A-Za-z0-9_.-]+$" -or
    (
      $RequestedRunId -ne "latest" -and
      $ExactSourceRunId -cne $RequestedRunId
    )
  ) {
    throw "Forge resume-eligibility nevratila presnu identitu pozadovaneho zdrojoveho runu."
  }
  $AllowedActions = @(
    "bounded_final_review_recovery",
    "extend_chain_budget_one_tranche",
    "validated_post_worker_decision_recovery",
    "validated_exact_resume"
  )
  if (
    [int]$Eligibility.schema_version -lt 4 -or
    $Eligibility.state_mutated -ne $false -or
    [int]$Eligibility.model_calls_made -ne 0 -or
    $Eligibility.supervisor_config_enforced -ne $true -or
    $AllowedActions -notcontains [string]$Eligibility.action
  ) {
    throw "Forge resume-eligibility vratila nekonzistentny uspesny verdikt."
  }
  if (
    [string]$Eligibility.source_stop_reason_code -eq "packet_attempts_exhausted" -and
    (
      [string]$Eligibility.action -ne "bounded_final_review_recovery" -or
      -not (Test-JsonBoolean $Eligibility.bounded_packet_recovery_eligible) -or
      $Eligibility.bounded_packet_recovery_eligible -ne $true
    )
  ) {
    throw "Packet-attempt resume nema platnu jednorazovu final-review recovery autorizaciu."
  }
  if (
    [string]$Eligibility.source_stop_reason_code -eq "chain_budget_exhausted" -and
    (
      [string]$Eligibility.action -ne "extend_chain_budget_one_tranche" -or
      -not (Test-JsonBoolean $Eligibility.budget_tranche_extension_eligible) -or
      $Eligibility.budget_tranche_extension_eligible -ne $true
    )
  ) {
    throw "Chain-budget resume nema platne povolenie na jeden kumulativny budget tranche."
  }
  if (
    [string]$Eligibility.source_stop_reason_code -eq "technical_failure" -and
    (
      [string]$Eligibility.action -ne "validated_post_worker_decision_recovery" -or
      $Eligibility.source_automatic_resume_allowed -ne $false -or
      $Eligibility.post_worker_decision_recovery_eligible -ne $true -or
      $Eligibility.bounded_packet_recovery_eligible -ne $false -or
      $Eligibility.budget_tranche_extension_eligible -ne $false -or
      [string]::IsNullOrWhiteSpace($ExpectedDecisionRecoverySha256) -or
      $null -eq $Eligibility.post_worker_decision_recovery -or
      [string]$Eligibility.post_worker_decision_recovery.raw_decision_sha256 -cne $ExpectedDecisionRecoverySha256
    )
  ) {
    throw "Technical-failure resume nema platnu auditovanu post-worker decision recovery autorizaciu."
  }
  if (
    [string]$Eligibility.action -ne "validated_post_worker_decision_recovery" -and
    $Eligibility.post_worker_decision_recovery_eligible -ne $false
  ) {
    throw "Non-recovery resume nesmie niest post-worker decision recovery autorizaciu."
  }
  if (
    [string]$Eligibility.action -eq "bounded_final_review_recovery" -and
    (
      $Eligibility.bounded_packet_recovery_eligible -ne $true -or
      $Eligibility.budget_tranche_extension_eligible -ne $false
    )
  ) {
    throw "Bounded packet recovery ma nekonzistentne akcne priznaky."
  }
  if (
    [string]$Eligibility.action -eq "extend_chain_budget_one_tranche" -and
    (
      $Eligibility.bounded_packet_recovery_eligible -ne $false -or
      $Eligibility.budget_tranche_extension_eligible -ne $true
    )
  ) {
    throw "Budget-tranche recovery ma nekonzistentne akcne priznaky."
  }
  if (
    [string]$Eligibility.action -eq "validated_exact_resume" -and
    (
      $Eligibility.bounded_packet_recovery_eligible -ne $false -or
      $Eligibility.budget_tranche_extension_eligible -ne $false
    )
  ) {
    throw "Exact resume nesmie niest recovery alebo budget autorizaciu."
  }
  if (
    [string]$Eligibility.source_stop_reason_code -notin @(
      "packet_attempts_exhausted",
      "chain_budget_exhausted",
      "technical_failure"
    ) -and
    [string]$Eligibility.action -ne "validated_exact_resume"
  ) {
    throw "Resume eligibility vratila akciu, ktora nezodpoveda stop reason zdrojoveho runu."
  }
  if (
    $UseStrictWslRuntime -and
    [string]$Eligibility.effective_security_profile -ne "strict"
  ) {
    throw "Resume eligibility nepotvrdila strict WSL security profile."
  }

  Write-Host ("Resume eligibility: {0} (model-free, bez mutacie)" -f [string]$Eligibility.action)
  return $ExactSourceRunId
}

function Set-PreferredCodexPath {
  $CodexBinRoot = Join-Path $env:LOCALAPPDATA "OpenAI\Codex\bin"
  if (-not (Test-Path -LiteralPath $CodexBinRoot -PathType Container)) {
    return $null
  }

  $Candidates = Get-ChildItem -LiteralPath $CodexBinRoot -Recurse -Filter "codex.exe" -File -ErrorAction SilentlyContinue |
    Sort-Object LastWriteTime -Descending
  foreach ($Candidate in $Candidates) {
    try {
      & $Candidate.FullName --version *> $null
      if ($LASTEXITCODE -eq 0) {
        $CodexDirectory = Split-Path -Parent $Candidate.FullName
        $env:Path = $CodexDirectory + [System.IO.Path]::PathSeparator + $env:Path
        return $Candidate.FullName
      }
    }
    catch {
      continue
    }
  }

  return $null
}

function Set-PreferredClaudePath {
  $Candidates = @()
  $Existing = Get-Command claude.exe -ErrorAction SilentlyContinue | Select-Object -First 1
  if ($null -ne $Existing) {
    $Candidates += Get-Item -LiteralPath $Existing.Source -ErrorAction SilentlyContinue
  }

  $PackagesRoot = Join-Path $env:LOCALAPPDATA "Packages"
  if (Test-Path -LiteralPath $PackagesRoot -PathType Container) {
    $ClaudePackages = Get-ChildItem -LiteralPath $PackagesRoot -Directory -Filter "Claude_*" -ErrorAction SilentlyContinue
    foreach ($Package in $ClaudePackages) {
      $ClaudeCodeRoot = Join-Path $Package.FullName "LocalCache\Roaming\Claude\claude-code"
      if (Test-Path -LiteralPath $ClaudeCodeRoot -PathType Container) {
        $Candidates += Get-ChildItem -LiteralPath $ClaudeCodeRoot -Recurse -Filter "claude.exe" -File -ErrorAction SilentlyContinue |
          Sort-Object LastWriteTime -Descending
      }
    }
  }

  foreach ($Candidate in $Candidates) {
    if ($null -eq $Candidate) { continue }
    try {
      & $Candidate.FullName --version *> $null
      if ($LASTEXITCODE -eq 0) {
        $ClaudeDirectory = Split-Path -Parent $Candidate.FullName
        $env:Path = $ClaudeDirectory + [System.IO.Path]::PathSeparator + $env:Path
        return $Candidate.FullName
      }
    }
    catch { continue }
  }
  return $null
}

function Invoke-ForgePython {
  param(
    [Parameter(Mandatory = $true)]
    [object]$Python,

    [Parameter(Mandatory = $true)]
    [string[]]$Arguments
  )

  $Executable = [string]$Python.File
  $RuntimeForgeScript = if ($Python.PSObject.Properties.Name -contains "ForgeScript") {
    [string]$Python.ForgeScript
  }
  else {
    $ForgeScript
  }
  $AllArguments = @($Python.PrefixArgs) + @($RuntimeForgeScript) + $Arguments
  & $Executable @AllArguments
  $script:LastForgeExitCode = [int]$LASTEXITCODE
}

function Format-PowerShellLiteral {
  param([Parameter(Mandatory = $true)][string]$Value)
  return "'" + $Value.Replace("'", "''") + "'"
}

function Get-MonitorCommand {
  param(
    [Parameter(Mandatory = $true)][string]$Project,
    [Parameter(Mandatory = $true)][string]$NotBeforeUtc
  )
  $WatchScript = Join-Path $ForgeRoot "Watch-Forge.ps1"
  return (
    "& {0} -Project {1} -NotBeforeUtc {2}" -f
      (Format-PowerShellLiteral $WatchScript),
      (Format-PowerShellLiteral $Project),
      (Format-PowerShellLiteral $NotBeforeUtc)
  )
}

function Open-ForgeMonitor {
  param(
    [Parameter(Mandatory = $true)][string]$Project,
    [Parameter(Mandatory = $true)][string]$NotBeforeUtc
  )

  $WatchScript = Join-Path $ForgeRoot "Watch-Forge.ps1"
  if (-not (Test-Path -LiteralPath $WatchScript -PathType Leaf)) {
    throw "Monitor script sa nenasiel: $WatchScript"
  }
  $PowerShell = Get-Command powershell.exe -ErrorAction Stop | Select-Object -First 1
  $WatchArgument = '"' + $WatchScript + '"'
  $ProjectArgument = '"' + $Project + '"'
  $NotBeforeArgument = '"' + $NotBeforeUtc + '"'
  Start-Process -FilePath $PowerShell.Source -ArgumentList @(
    "-NoProfile",
    "-ExecutionPolicy", "Bypass",
    "-File", $WatchArgument,
    "-Project", $ProjectArgument,
    "-NotBeforeUtc", $NotBeforeArgument
  ) -PassThru | Out-Null
}

try {
  if (-not (Test-Path -LiteralPath $ForgeScript -PathType Leaf)) {
    throw "Forge skript sa nenasiel: $ForgeScript"
  }
  if (-not (Test-Path -LiteralPath $RequestedConfigPath -PathType Leaf)) {
    throw "Pozadovana Forge konfiguracia sa nenasla: $RequestedConfigPath"
  }
  if (-not (Test-Path -LiteralPath $ConfigPath -PathType Leaf)) {
    throw "Auditovana runtime Forge konfiguracia sa nenasla: $ConfigPath"
  }

  $ProjectItem = Get-Item -LiteralPath $ProjectPath -ErrorAction Stop
  if (-not $ProjectItem.PSIsContainer) {
    throw "Cesta projektu nie je priecinok: $ProjectPath"
  }
  $ResolvedProjectPath = $ProjectItem.FullName

  if ([string]::IsNullOrWhiteSpace($LogPath)) {
    $LogDirectory = Join-Path $ResolvedProjectPath ".forge\wrapper-logs"
    $ResolvedLogPath = Join-Path $LogDirectory ("forge-wrapper-{0}.log" -f (Get-Date -Format "yyyyMMdd-HHmmss"))
  }
  else {
    $ResolvedLogPath = [System.IO.Path]::GetFullPath($LogPath)
    $LogDirectory = Split-Path -Parent $ResolvedLogPath
  }
  if ([string]::IsNullOrWhiteSpace($LogDirectory)) {
    throw "Cesta logu musi obsahovat platny nadradeny priecinok."
  }
  New-Item -ItemType Directory -Force -Path $LogDirectory | Out-Null

  Start-Transcript -LiteralPath $ResolvedLogPath -Append | Out-Null
  $TranscriptStarted = $true

  $Config = Get-Content -Raw -Encoding UTF8 -LiteralPath $ConfigPath | ConvertFrom-Json
  $ExpectedSecurityProfile = if ($UseStrictWslRuntime) { "strict" } else { "balanced" }
  if ([string]$Config.security_profile -ne $ExpectedSecurityProfile) {
    throw "Konfiguracia nezodpoveda rezimu ${Mode}: ocakavany security_profile=$ExpectedSecurityProfile."
  }
  foreach ($RequiredFlag in @("require_chatgpt_auth", "strict_subscription_auth", "ignore_codex_user_config", "ignore_codex_rules", "claude_safe_mode", "claude_strict_mcp", "final_review_after_last_worker", "incremental_evidence", "run_scoped_logs", "runtime_preflight", "adaptive_orchestration", "adaptive_auto_supervisor", "unattended_requires_sandbox")) {
    if (
      -not (Test-JsonBoolean $Config.$RequiredFlag) -or
      $Config.$RequiredFlag -ne $true
    ) {
      throw "Bezpecnostna volba '$RequiredFlag' musi zostat zapnuta v auditovanej runtime konfiguracii."
    }
  }
  if (
    $UseStrictWslRuntime -and
    (
      -not (Test-JsonBoolean $Config.claude_outer_srt_on_wsl) -or
      $Config.claude_outer_srt_on_wsl -ne $true
    )
  ) {
    throw "Bezpecnostna volba 'claude_outer_srt_on_wsl' musi byt v auditovanom WSL2 strict profile native JSON true."
  }

  if ($PSCmdlet.ParameterSetName -eq "Spec") {
    $SpecItem = Get-Item -LiteralPath $SpecPath -ErrorAction Stop
    if ($SpecItem.PSIsContainer) {
      throw "SpecPath musi byt subor, nie priecinok: $SpecPath"
    }
    $ResolvedSpecPath = $SpecItem.FullName
    $ProjectPrefix = $ResolvedProjectPath.TrimEnd("\") + "\"
    if (-not $ResolvedSpecPath.StartsWith($ProjectPrefix, [System.StringComparison]::OrdinalIgnoreCase)) {
      throw "SPEC.md musi byt vo vnutri projektu, aby ho Forge mohol bezpecne citat."
    }
    $RelativeSpecPath = $ResolvedSpecPath.Substring($ProjectPrefix.Length)
    $GoalText = "Implementuj a dokonci projekt podla specifikacie v subore '$RelativeSpecPath'. Pokracuj autonomne, kym Codex vysledok neschvali a vsetky povinne kontroly neprejdu. Nenasadzuj, nepublikuj a nic neposielaj na vzdialeny Git."
  }
  elseif ($PSCmdlet.ParameterSetName -eq "Goal") {
    $GoalText = $Goal.Trim()
  }
  else {
    $GoalText = $null
  }

  if (-not $IsResume -and [string]::IsNullOrWhiteSpace($GoalText)) {
    throw "Zadanie nesmie byt prazdne."
  }

  $SelectedResumeRunId = $null
  if ($IsResume) {
    $SelectedResumeRunId = if ($PSCmdlet.ParameterSetName -eq "ResumeLatest") {
      "latest"
    }
    elseif ($PSCmdlet.ParameterSetName -eq "RecoverFailedRun") {
      $RecoverFailedRunId.Trim()
    }
    else {
      $ResumeRunId.Trim()
    }
  }

  if ($UseStrictWslRuntime) {
    $PreferredCodex = $null
    $PreferredClaude = $null
    $Python = Find-StrictWslPython
    $RuntimeProjectPath = Convert-ToStrictWslPath -WslExecutable $Python.File -WindowsPath $ResolvedProjectPath
    Assert-StrictWslProjectSandbox `
      -WslExecutable $Python.File `
      -WindowsProjectPath $ResolvedProjectPath `
      -WslProjectPath $RuntimeProjectPath `
      -WslPython "$StrictWslForgeRoot/.venv/bin/python"
    $Python.Label = "Forge WSL2 strict .venv (project DrvFS SRT canary OK)"
    $RuntimeConfigPath = [string]$Python.ConfigPath
  }
  else {
    if (-not $DoctorOnly) {
      Assert-NativeSrtFunctional
    }
    $PreferredCodex = Set-PreferredCodexPath
    $PreferredClaude = Set-PreferredClaudePath
    $Python = Find-ForgePython
    $RuntimeProjectPath = $ResolvedProjectPath
    $RuntimeConfigPath = $ConfigPath
  }
  if ($IsResume) {
    $SelectedResumeRunId = Assert-ResumeEligibility `
      -Python $Python `
      -Project $RuntimeProjectPath `
      -RequestedRunId $SelectedResumeRunId `
      -SupervisorConfig $RuntimeConfigPath `
      -ExpectedDecisionRecoverySha256 $ExpectedDecisionRecoverySha256
  }
  Write-Host "Forge: $ForgeRoot"
  Write-Host "Projekt: $ResolvedProjectPath"
  Write-Host "Rezim: $Mode"
  if ($Mode -eq "EconomySafe" -and $UseStrictWslRuntime) {
    Write-Host "Runtime route: auditovany WSL2 strict (predvoleny bezobsluzny EconomySafe)"
  }
  Write-Host "Konfiguracia runtime: $ConfigPath ($ExpectedSecurityProfile)"
  if ($IsResume) {
    Write-Host "Resume pouzije presnu konfiguraciu ulozenu v zdrojovom rune."
  }
  Write-Host "Python: $($Python.Label)"
  if (-not [string]::IsNullOrWhiteSpace($PreferredCodex)) {
    Write-Host "Codex CLI: $PreferredCodex"
  }
  if (-not [string]::IsNullOrWhiteSpace($PreferredClaude)) {
    Write-Host "Claude CLI: $PreferredClaude"
  }
  Write-Host "Log: $ResolvedLogPath"

  Write-Host ""
  Write-Host "=== FORGE DOCTOR ==="
  Invoke-ForgePython -Python $Python -Arguments @("doctor")
  $DoctorExitCode = $LastForgeExitCode
  if ($DoctorExitCode -ne 0) {
    [Console]::Error.WriteLine("Forge doctor nepresiel (exit code $DoctorExitCode). Autonomny cyklus sa nespustil.")
    $ExitCode = $DoctorExitCode
  }
  elseif ($DoctorOnly) {
    Write-Host "Forge doctor presiel. Doctor-only rezim ukoncil wrapper bez spustenia autonomneho cyklu."
    $ExitCode = 0
  }
  else {
    $MonitorNotBeforeUtc = [DateTimeOffset]::UtcNow.ToString("o")
    $ManualMonitorCommand = Get-MonitorCommand `
      -Project $ResolvedProjectPath `
      -NotBeforeUtc $MonitorNotBeforeUtc
    if (-not $NoMonitor -and -not $MonitorOpened) {
      try {
        Open-ForgeMonitor `
          -Project $ResolvedProjectPath `
          -NotBeforeUtc $MonitorNotBeforeUtc
        $MonitorOpened = $true
        Write-Host "Forge Live Monitor bol otvoreny v novom PowerShell okne."
      }
      catch {
        [Console]::Error.WriteLine("Monitor sa nepodarilo otvorit: $($_.Exception.Message)")
        Write-Host "Forge bude pokracovat. Monitor otvor manualne:"
        Write-Host $ManualMonitorCommand
      }
    }
    elseif ($NoMonitor) {
      Write-Host "Automaticke otvorenie monitora je vypnute parametrom -NoMonitor."
      Write-Host "Manualny prikaz monitora: $ManualMonitorCommand"
    }
    Write-Host ""
    Write-Host "=== FORGE AUTONOMOUS RUN ==="
    if ($IsResume) {
      $ResumeArguments = @(
        "run-chain",
        "--project", $RuntimeProjectPath,
        "--resume-run-id", $SelectedResumeRunId,
        "--config", $RuntimeConfigPath
      )
      if (-not [string]::IsNullOrWhiteSpace($ExpectedDecisionRecoverySha256)) {
        $ResumeArguments += @(
          "--expected-decision-recovery-sha256",
          $ExpectedDecisionRecoverySha256
        )
      }
      Invoke-ForgePython -Python $Python -Arguments $ResumeArguments
    }
    else {
      Invoke-ForgePython -Python $Python -Arguments @(
        "run-chain",
        "--project", $RuntimeProjectPath,
        "--goal", $GoalText,
        "--config", $RuntimeConfigPath
      )
    }
    $ExitCode = $LastForgeExitCode
    if ($ExitCode -eq 4) {
      $LatestResultPath = Join-Path $ResolvedProjectPath ".forge\result.json"
      $LatestResult = $null
      try {
        $LatestResult = Get-Content -Raw -Encoding UTF8 -LiteralPath $LatestResultPath | ConvertFrom-Json
      }
      catch {
        $LatestResult = $null
      }
      Write-Host ""
      if ($null -eq $LatestResult) {
        Write-Host "Forge skoncil exit code 4, ale citatelny result.json chyba."
        Write-Host "Resume prikaz sa z bezpecnostnych dovodov negeneruje; skontroluj wrapper log."
      }
      else {
        $SchemaVersion = 1
        $SchemaValid = $true
        $SchemaProperty = $LatestResult.PSObject.Properties["schema_version"]
        if ($null -ne $SchemaProperty) {
          if (
            -not (Test-JsonInteger $SchemaProperty.Value) -or
            [int64]$SchemaProperty.Value -lt 1
          ) {
            $SchemaValid = $false
            $SchemaVersion = 0
          }
          else {
            $SchemaVersion = [int64]$SchemaProperty.Value
          }
        }
        $StopReasonProperty = $LatestResult.PSObject.Properties["stop_reason_code"]
        $AutomaticResumeProperty = $LatestResult.PSObject.Properties["automatic_resume_allowed"]
        $FinalMessageProperty = $LatestResult.PSObject.Properties["final_message"]
        $FinalStatusProperty = $LatestResult.PSObject.Properties["final_status"]
        $RunIdProperty = $LatestResult.PSObject.Properties["run_id"]
        $CurrentContractValid = (
          $SchemaValid -and
          $SchemaVersion -ge 4 -and
          $null -ne $StopReasonProperty -and
          $StopReasonProperty.Value -is [string] -and
          -not [string]::IsNullOrWhiteSpace([string]$StopReasonProperty.Value) -and
          $null -ne $AutomaticResumeProperty -and
          (Test-JsonBoolean $AutomaticResumeProperty.Value) -and
          $null -ne $FinalStatusProperty -and
          $FinalStatusProperty.Value -is [string] -and
          $null -ne $RunIdProperty -and
          $RunIdProperty.Value -is [string] -and
          [string]$RunIdProperty.Value -match "^[A-Za-z0-9_.-]+$"
        )
        $StopReasonCode = if ($CurrentContractValid) {
          [string]$StopReasonProperty.Value
        } else {
          ""
        }
        $AutomaticResumeAllowed = if ($CurrentContractValid) {
          [bool]$AutomaticResumeProperty.Value
        } else {
          $null
        }
        $FinalStatus = if ($CurrentContractValid) {
          [string]$FinalStatusProperty.Value
        } else {
          ""
        }
        $FinalMessage = if (
          $null -ne $FinalMessageProperty -and
          $FinalMessageProperty.Value -is [string]
        ) {
          [string]$FinalMessageProperty.Value
        } else {
          ""
        }
        $ContinuationRunId = if ($CurrentContractValid) {
          [string]$RunIdProperty.Value
        } else {
          ""
        }
        $ExpectedFinalStatus = @{
          chain_budget_exhausted = "needs_continuation"
          packet_attempts_exhausted = "needs_continuation"
          reviewer_continue = "needs_continuation"
          iterations_exhausted = "needs_continuation"
          next_packet_ready = "needs_continuation"
          external_change_review_required = "needs_continuation"
          blocked = "blocked"
          subscription_limit = "subscription_limit"
          technical_failure = "failed"
          completed = "done"
        }
        $AutomaticReasons = @(
          "reviewer_continue",
          "iterations_exhausted",
          "next_packet_ready",
          "external_change_review_required"
        )
        if ($CurrentContractValid) {
          $CurrentContractValid = (
            $ExpectedFinalStatus.ContainsKey($StopReasonCode) -and
            $FinalStatus -ceq [string]$ExpectedFinalStatus[$StopReasonCode] -and
            $AutomaticResumeAllowed -eq ($AutomaticReasons -contains $StopReasonCode)
          )
        }

        if (-not $SchemaValid -or ($SchemaVersion -ge 4 -and -not $CurrentContractValid)) {
          Write-Host "Forge vratil current result.json s neplatnymi schema/type alebo termination poliami."
          Write-Host "Resume prikaz sa z bezpecnostnych dovodov negeneruje; skontroluj wrapper log."
        }
        elseif (
          $SchemaVersion -ge 4 -and
          $StopReasonCode -eq "chain_budget_exhausted" -and
          $AutomaticResumeAllowed -eq $false -and
          -not [string]::IsNullOrWhiteSpace($ContinuationRunId)
        ) {
          $WrapperLiteral = Format-PowerShellLiteral $PSCommandPath
          $ProjectLiteral = Format-PowerShellLiteral $ResolvedProjectPath
          $RunLiteral = Format-PowerShellLiteral $ContinuationRunId
          Write-Host "Forge chain vycerpal globalny chain budget. Aktivny packet nemusi byt chybny."
          Write-Host "Nespustil sa ziadny genericky restart. Neskor pokracuj explicitnym resume prikazom:"
          Write-Host "& $WrapperLiteral -ProjectPath $ProjectLiteral -ResumeRunId $RunLiteral -Mode $Mode"
        }
        elseif (
          $SchemaVersion -ge 4 -and
          $StopReasonCode -eq "packet_attempts_exhausted" -and
          $AutomaticResumeAllowed -eq $false
        ) {
          Write-Host "Forge zastavil konkretny pracovny balik: vycerpal jeho packet attempts."
          Write-Host "Globalny chain budget tym nemusi byt vycerpany. Opakovany ResumeRunId by sa zastavil na tom istom limite, preto ho wrapper neponuka."
          Write-Host "Je potrebny ohraniceny recovery/repair packet alebo oprava attempt politiky; pozri Posledny vysledok v monitore."
        }
        elseif ($SchemaVersion -ge 4) {
          Write-Host "Forge zastavil continuation bod: stop_reason_code=$StopReasonCode; automatic_resume_allowed=$AutomaticResumeAllowed."
          Write-Host "Tato kombinacia neopravnuje wrapper generovat manualny ResumeRunId. Skontroluj posledny vysledok a supervisor log."
        }
        elseif (
          $SchemaVersion -le 3 -and
          $FinalMessage -match "(?i)chain.*budget exhausted" -and
          -not [string]::IsNullOrWhiteSpace($ContinuationRunId)
        ) {
          $WrapperLiteral = Format-PowerShellLiteral $PSCommandPath
          $ProjectLiteral = Format-PowerShellLiteral $ResolvedProjectPath
          $RunLiteral = Format-PowerShellLiteral $ContinuationRunId
          Write-Host "Legacy Forge result uvadza vycerpanie chain budgetu."
          Write-Host "Nespustil sa ziadny genericky restart."
          Write-Host "Neskor pokracuj explicitnym resume prikazom:"
          Write-Host "& $WrapperLiteral -ProjectPath $ProjectLiteral -ResumeRunId $RunLiteral -Mode $Mode"
        }
        else {
          Write-Host "Legacy continuation nema jednoznacny dokaz vycerpania globalneho chain budgetu."
          Write-Host "Resume prikaz sa negeneruje; najprv skontroluj zdrojovy result.json."
        }
      }
    }
  }
}
catch {
  [Console]::Error.WriteLine("CHYBA: $($_.Exception.Message)")
  $ExitCode = 1
}
finally {
  if ($TranscriptStarted) {
    Stop-Transcript | Out-Null
  }
}

if (-not [string]::IsNullOrWhiteSpace($ResolvedLogPath)) {
  Write-Host "Forge wrapper log: $ResolvedLogPath"
}
exit $ExitCode
