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
$ConfigFile = switch ($Mode) {
  "EconomyMax" { "forge.max-economy.config.json" }
  "Android" { "forge.android.config.json" }
  "Strict" { "forge.strict.config.json" }
  default { "forge.config.json" }
}
$ConfigPath = Join-Path $ForgeRoot $ConfigFile
$ExitCode = 1
$LastForgeExitCode = 1
$TranscriptStarted = $false
$ResolvedLogPath = $null
$MonitorOpened = $false
$IsResume = $PSCmdlet.ParameterSetName -in @("ResumeLatest", "ResumeRunId")

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
  $AllArguments = @($Python.PrefixArgs) + @($ForgeScript) + $Arguments
  & $Executable @AllArguments
  $script:LastForgeExitCode = [int]$LASTEXITCODE
}

function Format-PowerShellLiteral {
  param([Parameter(Mandatory = $true)][string]$Value)
  return "'" + $Value.Replace("'", "''") + "'"
}

function Get-MonitorCommand {
  param([Parameter(Mandatory = $true)][string]$Project)
  $WatchScript = Join-Path $ForgeRoot "Watch-Forge.ps1"
  return "& $(Format-PowerShellLiteral $WatchScript) -Project $(Format-PowerShellLiteral $Project)"
}

function Open-ForgeMonitor {
  param([Parameter(Mandatory = $true)][string]$Project)

  $WatchScript = Join-Path $ForgeRoot "Watch-Forge.ps1"
  if (-not (Test-Path -LiteralPath $WatchScript -PathType Leaf)) {
    throw "Monitor script sa nenasiel: $WatchScript"
  }
  $PowerShell = Get-Command powershell.exe -ErrorAction Stop | Select-Object -First 1
  $WatchArgument = '"' + $WatchScript + '"'
  $ProjectArgument = '"' + $Project + '"'
  Start-Process -FilePath $PowerShell.Source -ArgumentList @(
    "-NoProfile",
    "-ExecutionPolicy", "Bypass",
    "-File", $WatchArgument,
    "-Project", $ProjectArgument
  ) -PassThru | Out-Null
}

try {
  if (-not (Test-Path -LiteralPath $ForgeScript -PathType Leaf)) {
    throw "Forge skript sa nenasiel: $ForgeScript"
  }
  if (-not (Test-Path -LiteralPath $ConfigPath -PathType Leaf)) {
    throw "Auditovana Forge konfiguracia sa nenasla: $ConfigPath"
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
  $ExpectedSecurityProfile = if ($Mode -eq "Strict") { "strict" } else { "balanced" }
  if ([string]$Config.security_profile -ne $ExpectedSecurityProfile) {
    throw "Konfiguracia nezodpoveda rezimu ${Mode}: ocakavany security_profile=$ExpectedSecurityProfile."
  }
  foreach ($RequiredFlag in @("require_chatgpt_auth", "strict_subscription_auth", "ignore_codex_user_config", "ignore_codex_rules", "claude_safe_mode", "claude_strict_mcp", "final_review_after_last_worker", "incremental_evidence", "run_scoped_logs", "runtime_preflight", "adaptive_orchestration", "adaptive_auto_supervisor")) {
    if ($Config.$RequiredFlag -ne $true) {
      throw "Bezpecnostna volba '$RequiredFlag' musi zostat zapnuta v forge.config.json."
    }
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

  $PreferredCodex = Set-PreferredCodexPath
  $PreferredClaude = Set-PreferredClaudePath
  $Python = Find-ForgePython
  Write-Host "Forge: $ForgeRoot"
  Write-Host "Projekt: $ResolvedProjectPath"
  Write-Host "Rezim: $Mode"
  Write-Host "Konfiguracia: $ConfigPath ($ExpectedSecurityProfile)"
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
    $ManualMonitorCommand = Get-MonitorCommand -Project $ResolvedProjectPath
    if (-not $NoMonitor -and -not $MonitorOpened) {
      try {
        Open-ForgeMonitor -Project $ResolvedProjectPath
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
      $SelectedRunId = if ($PSCmdlet.ParameterSetName -eq "ResumeLatest") {
        "latest"
      }
      else {
        $ResumeRunId.Trim()
      }
      Invoke-ForgePython -Python $Python -Arguments @(
        "run-chain",
        "--project", $ResolvedProjectPath,
        "--resume-run-id", $SelectedRunId
      )
    }
    else {
      Invoke-ForgePython -Python $Python -Arguments @(
        "run-chain",
        "--project", $ResolvedProjectPath,
        "--goal", $GoalText,
        "--config", $ConfigPath
      )
    }
    $ExitCode = $LastForgeExitCode
    if ($ExitCode -eq 4) {
      $LatestResultPath = Join-Path $ResolvedProjectPath ".forge\result.json"
      $ContinuationRunId = "latest"
      try {
        $LatestResult = Get-Content -Raw -Encoding UTF8 -LiteralPath $LatestResultPath | ConvertFrom-Json
        if (
          [string]$LatestResult.final_status -eq "needs_continuation" -and
          -not [string]::IsNullOrWhiteSpace([string]$LatestResult.run_id)
        ) {
          $ContinuationRunId = [string]$LatestResult.run_id
        }
      }
      catch {
        $ContinuationRunId = "latest"
      }
      $WrapperLiteral = Format-PowerShellLiteral $PSCommandPath
      $ProjectLiteral = Format-PowerShellLiteral $ResolvedProjectPath
      $RunLiteral = Format-PowerShellLiteral $ContinuationRunId
      Write-Host ""
      Write-Host "Forge chain skoncil stavom needs_continuation po vycerpani bezpecneho budgetu."
      Write-Host "Nespustil sa ziadny genericky restart. Neskor pokracuj explicitnym resume prikazom:"
      Write-Host "& $WrapperLiteral -ProjectPath $ProjectLiteral -ResumeRunId $RunLiteral -Mode $Mode"
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
