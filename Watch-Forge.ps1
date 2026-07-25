[CmdletBinding()]
param(
  [Parameter(Mandatory = $true)]
  [ValidateNotNullOrEmpty()]
  [string]$Project,

  [ValidateRange(1, 3600)]
  [int]$RefreshSeconds = 2,

  [switch]$ShowFullCommands,

  [switch]$ShowTechnicalDetails,

  [switch]$ShowDiffStat = $true,

  [switch]$NoClear,

  [string]$NotBeforeUtc = "",

  [ValidateRange(10, 3600)]
  [int]$SupervisorGraceSeconds = 90
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"
$env:PYTHONUTF8 = "1"
$env:PYTHONIOENCODING = "utf-8"
$Utf8 = New-Object System.Text.UTF8Encoding($false)
[Console]::OutputEncoding = $Utf8
$OutputEncoding = $Utf8
$MonitorStartedAt = [DateTimeOffset]::UtcNow
$ExpectedGenerationNotBefore = $null
if (-not [string]::IsNullOrWhiteSpace($NotBeforeUtc)) {
  try {
    $ExpectedGenerationNotBefore = [DateTimeOffset]::Parse(
      $NotBeforeUtc,
      [System.Globalization.CultureInfo]::InvariantCulture,
      [System.Globalization.DateTimeStyles]::RoundtripKind
    )
  }
  catch {
    throw "NotBeforeUtc must be a valid round-trip UTC timestamp."
  }
}

function Protect-Text {
  param([AllowNull()][object]$Value)

  if ($null -eq $Value) {
    return ""
  }
  $Text = [string]$Value
  $Patterns = @(
    '(?is)-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----.*?-----END (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----',
    '(?im)^(?:authorization|cookie|set-cookie)\s*:\s*.*$',
    '(?i)\b(?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?|redis)://[^\s"'']+',
    '(?i)\bsk(?:-ant)?-[A-Za-z0-9_-]{12,}\b',
    '(?i)\b[A-Z][A-Z0-9_]*(?:KEY|TOKEN|SECRET|PASSWORD|PASSWD|CREDENTIALS?)\s*=\s*(?:"[^"]*"|''[^'']*''|[^\s]+)',
    '(?i)\b(?:api[_-]?key|access[_-]?token|refresh[_-]?token|token|password|passwd|secret|client[_-]?secret|connection[_-]?string)\b\s*[:=]\s*(?:"[^"]*"|''[^'']*''|[^\s,;]+)',
    '(?i)\bBearer\s+[A-Za-z0-9._~+/=-]{8,}'
  )
  foreach ($Pattern in $Patterns) {
    $Text = [regex]::Replace($Text, $Pattern, '[REDACTED]')
  }
  return $Text
}

function Shorten-Text {
  param(
    [AllowNull()][object]$Value,
    [int]$Limit = 260
  )

  $Text = Protect-Text $Value
  if ($Text.Length -le $Limit) {
    return $Text
  }
  return $Text.Substring(0, $Limit) + " ..."
}

function Read-JsonFile {
  param([string]$Path)

  if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) {
    return $null
  }
  try {
    return Get-Content -Raw -Encoding UTF8 -LiteralPath $Path | ConvertFrom-Json
  }
  catch {
    return $null
  }
}

function Get-OptionalProperty {
  param(
    [AllowNull()][object]$Object,
    [Parameter(Mandatory = $true)][string]$Name
  )
  if ($null -eq $Object) {
    return $null
  }
  $Property = $Object.PSObject.Properties[$Name]
  if ($null -eq $Property) {
    return $null
  }
  return $Property.Value
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

function Get-StateTimestamp {
  param(
    [AllowNull()][object]$Object,
    [Parameter(Mandatory = $true)][string[]]$Names
  )
  foreach ($Name in $Names) {
    $Value = Get-OptionalProperty -Object $Object -Name $Name
    if ($null -eq $Value) {
      continue
    }
    if ($Value -is [DateTimeOffset]) {
      return [DateTimeOffset]$Value
    }
    if ($Value -is [DateTime]) {
      return [DateTimeOffset]([DateTime]$Value)
    }
    if ($Value -isnot [string]) {
      return $null
    }
    try {
      return [DateTimeOffset]::Parse(
        [string]$Value,
        [System.Globalization.CultureInfo]::InvariantCulture,
        [System.Globalization.DateTimeStyles]::RoundtripKind
      )
    }
    catch {
      return $null
    }
  }
  return $null
}

function Test-StateInExpectedGeneration {
  param(
    [AllowNull()][object]$Object,
    [Parameter(Mandatory = $true)][string[]]$TimestampNames
  )
  if ($null -eq $Object -or $null -eq $ExpectedGenerationNotBefore) {
    return $null -ne $Object
  }
  $Timestamp = Get-StateTimestamp -Object $Object -Names $TimestampNames
  return (
    $null -ne $Timestamp -and
    $Timestamp -ge $ExpectedGenerationNotBefore
  )
}

function Get-SupervisorObservation {
  param(
    [AllowNull()][object]$Supervisor,
    [bool]$FileExists,
    [Parameter(Mandatory = $true)][string]$ResolvedProjectPath
  )

  if ($null -eq $Supervisor) {
    return [pscustomobject]@{
      Present = $FileExists
      CurrentGeneration = $false
      Valid = -not $FileExists
      IsTerminal = $false
      IsRunning = $false
      Status = ""
      ExitCode = $null
      AgeSeconds = $null
      Message = $(if ($FileExists) {
        "chain-supervisor.json nie je citatelny platny JSON."
      } else {
        ""
      })
    }
  }

  $StartedAt = Get-StateTimestamp -Object $Supervisor -Names @("started_at")
  $CurrentGeneration = (
    $null -eq $ExpectedGenerationNotBefore -or
    ($null -ne $StartedAt -and $StartedAt -ge $ExpectedGenerationNotBefore)
  )
  if (-not $CurrentGeneration) {
    return [pscustomobject]@{
      Present = $true
      CurrentGeneration = $false
      Valid = $true
      IsTerminal = $false
      IsRunning = $false
      Status = ""
      ExitCode = $null
      AgeSeconds = $null
      Message = ""
    }
  }

  $SchemaProperty = $Supervisor.PSObject.Properties["schema_version"]
  $StatusProperty = $Supervisor.PSObject.Properties["status"]
  $ProjectProperty = $Supervisor.PSObject.Properties["project"]
  if (
    $null -eq $SchemaProperty -or
    -not (Test-JsonInteger $SchemaProperty.Value) -or
    [int64]$SchemaProperty.Value -lt 4 -or
    $null -eq $StatusProperty -or
    $StatusProperty.Value -isnot [string] -or
    $null -eq $ProjectProperty -or
    $ProjectProperty.Value -isnot [string] -or
    $null -eq $StartedAt
  ) {
    return [pscustomobject]@{
      Present = $true
      CurrentGeneration = $true
      Valid = $false
      IsTerminal = $false
      IsRunning = $false
      Status = ""
      ExitCode = $null
      AgeSeconds = $null
      Message = "chain-supervisor.json nema platnu schema/type identitu."
    }
  }

  try {
    $SupervisorProject = [System.IO.Path]::GetFullPath(
      (Convert-ForgeRuntimePath $ProjectProperty.Value)
    )
    if ($SupervisorProject -cne [System.IO.Path]::GetFullPath($ResolvedProjectPath)) {
      throw "project mismatch"
    }
  }
  catch {
    return [pscustomobject]@{
      Present = $true
      CurrentGeneration = $true
      Valid = $false
      IsTerminal = $false
      IsRunning = $false
      Status = ""
      ExitCode = $null
      AgeSeconds = $null
      Message = "chain-supervisor.json patri inemu alebo neplatnemu projektu."
    }
  }

  $Status = [string]$StatusProperty.Value
  $TerminalExitCodes = @{
    done = 0
    failed = 1
    blocked = 2
    subscription_limit = 3
    needs_continuation = 4
  }
  if ($Status -ne "running" -and -not $TerminalExitCodes.ContainsKey($Status)) {
    return [pscustomobject]@{
      Present = $true
      CurrentGeneration = $true
      Valid = $false
      IsTerminal = $false
      IsRunning = $false
      Status = $Status
      ExitCode = $null
      AgeSeconds = $null
      Message = "chain-supervisor.json obsahuje neznamy stav."
    }
  }

  $ExitProperty = $Supervisor.PSObject.Properties["exit_code"]
  $ExitCode = $null
  if ($Status -eq "running") {
    if ($null -ne $ExitProperty) {
      return [pscustomobject]@{
        Present = $true
        CurrentGeneration = $true
        Valid = $false
        IsTerminal = $false
        IsRunning = $true
        Status = $Status
        ExitCode = $null
        AgeSeconds = $null
        Message = "Beziaci supervisor nesmie mat terminalny exit_code."
      }
    }
  }
  else {
    if (
      $null -eq $ExitProperty -or
      -not (Test-JsonInteger $ExitProperty.Value) -or
      [int64]$ExitProperty.Value -ne [int64]$TerminalExitCodes[$Status]
    ) {
      return [pscustomobject]@{
        Present = $true
        CurrentGeneration = $true
        Valid = $false
        IsTerminal = $true
        IsRunning = $false
        Status = $Status
        ExitCode = $null
        AgeSeconds = $null
        Message = "Terminalny supervisor nema konzistentny native JSON exit_code."
      }
    }
    $ExitCode = [int64]$ExitProperty.Value
    $AutomaticProperty = $Supervisor.PSObject.Properties["automatic_resume_allowed"]
    if (
      $null -ne $AutomaticProperty -and
      -not (Test-JsonBoolean $AutomaticProperty.Value)
    ) {
      return [pscustomobject]@{
        Present = $true
        CurrentGeneration = $true
        Valid = $false
        IsTerminal = $true
        IsRunning = $false
        Status = $Status
        ExitCode = $ExitCode
        AgeSeconds = $null
        Message = "Terminalny supervisor ma neplatny JSON typ automatic_resume_allowed."
      }
    }
  }

  $ActivityAt = Get-StateTimestamp `
    -Object $Supervisor `
    -Names @("updated_at", "finished_at", "started_at")
  $AgeSeconds = if ($null -ne $ActivityAt) {
    ([DateTimeOffset]::UtcNow - $ActivityAt).TotalSeconds
  }
  else {
    $null
  }
  return [pscustomobject]@{
    Present = $true
    CurrentGeneration = $true
    Valid = $true
    IsTerminal = $Status -ne "running"
    IsRunning = $Status -eq "running"
    Status = $Status
    ExitCode = $ExitCode
    AgeSeconds = $AgeSeconds
    Message = ""
  }
}

function Convert-ForgeRuntimePath {
  param([AllowNull()][object]$Value)

  $PathText = [string]$Value
  if ($PathText -match '^/mnt/([A-Za-z])(?:/(.*))?$') {
    $Drive = $Matches[1].ToUpperInvariant()
    $Relative = [string]$Matches[2]
    if ([string]::IsNullOrWhiteSpace($Relative)) {
      return "${Drive}:\"
    }
    return "${Drive}:\" + $Relative.Replace("/", "\")
  }
  return $PathText
}

function Format-PowerShellLiteral {
  param([Parameter(Mandatory = $true)][string]$Value)
  return "'" + $Value.Replace("'", "''") + "'"
}

function Get-ResumeWrapperMode {
  param(
    [Parameter(Mandatory = $true)][string]$ForgeDirectory,
    [Parameter(Mandatory = $true)][string]$RunId
  )

  if ([string]::IsNullOrWhiteSpace($RunId) -or $RunId -notmatch "^[A-Za-z0-9_.-]+$") {
    return $null
  }
  try {
    $RunsDirectory = [System.IO.Path]::GetFullPath((Join-Path $ForgeDirectory "runs"))
    $RunDirectory = [System.IO.Path]::GetFullPath((Join-Path $RunsDirectory $RunId))
    $AllowedPrefix = $RunsDirectory.TrimEnd("\") + "\"
    if (-not $RunDirectory.StartsWith($AllowedPrefix, [System.StringComparison]::OrdinalIgnoreCase)) {
      return $null
    }
    $RunPayload = Read-JsonFile (Join-Path $RunDirectory "run.json")
    if ($null -eq $RunPayload -or [string]$RunPayload.run_id -cne $RunId) {
      return $null
    }
    $Config = Get-OptionalProperty -Object $RunPayload -Name "config"
    if ($null -eq $Config) {
      return $null
    }
    $StoredMode = ([string](Get-OptionalProperty -Object $Config -Name "mode")).Trim().ToLowerInvariant()
    $SecurityProfile = ([string](Get-OptionalProperty -Object $Config -Name "security_profile")).Trim().ToLowerInvariant()
    $RequiresSandbox = Get-OptionalProperty -Object $Config -Name "unattended_requires_sandbox"
    if (
      -not (Test-JsonBoolean $RequiresSandbox) -or
      $RequiresSandbox -ne $true
    ) {
      return $null
    }

    # The wrapper mode must select a runtime capable of safely loading the
    # immutable source config. Older balanced EconomySafe runs are deliberately
    # not mapped: today's EconomySafe route is strict WSL and rejects them.
    if ($StoredMode -eq "economy-safe-strict" -and $SecurityProfile -eq "strict") {
      return "Strict"
    }
    if ($StoredMode -eq "economy-max" -and $SecurityProfile -eq "balanced") {
      return "EconomyMax"
    }
    if ($StoredMode -eq "economy-safe-android" -and $SecurityProfile -eq "balanced") {
      return "Android"
    }
  }
  catch {
    return $null
  }
  return $null
}

function Test-ChainBudgetResumeCandidate {
  param([AllowNull()][object]$Result)

  if ($null -eq $Result) {
    return $false
  }
  $Base = Get-OptionalProperty -Object $Result -Name "base_chain_budgets"
  $Effective = Get-OptionalProperty -Object $Result -Name "effective_chain_budgets"
  $ExtensionProperty = $Result.PSObject.Properties["budget_extension_count"]
  if ($null -eq $Base -or $null -eq $Effective -or $null -eq $ExtensionProperty) {
    return $false
  }

  try {
    if (-not (Test-JsonInteger $ExtensionProperty.Value)) {
      return $false
    }
    $ExtensionCount = [int64]$ExtensionProperty.Value
    if ($ExtensionCount -lt 0) {
      return $false
    }
    $Multiplier = $ExtensionCount + 1
    $Fields = @(
      [pscustomobject]@{ Limit = "max_child_runs"; Counter = "chain_child_runs"; Min = 0; Cap = 50 },
      [pscustomobject]@{ Limit = "max_codex_calls"; Counter = "chain_codex_calls"; Min = 1; Cap = 200 },
      [pscustomobject]@{ Limit = "max_worker_calls"; Counter = "chain_worker_calls"; Min = 1; Cap = 200 },
      [pscustomobject]@{ Limit = "max_elapsed_seconds"; Counter = "chain_elapsed_seconds"; Min = 60; Cap = 604800 },
      [pscustomobject]@{ Limit = "max_full_check_suites"; Counter = "chain_full_check_suites"; Min = 1; Cap = 50 },
      [pscustomobject]@{ Limit = "max_no_progress_events"; Counter = "chain_no_progress_events"; Min = 1; Cap = 20 }
    )
    $ExtensibleLimitReached = $false
    foreach ($Field in $Fields) {
      if (
        $null -eq $Base.PSObject.Properties[$Field.Limit] -or
        $null -eq $Effective.PSObject.Properties[$Field.Limit] -or
        $null -eq $Result.PSObject.Properties[$Field.Counter] -or
        -not (Test-JsonInteger $Base.PSObject.Properties[$Field.Limit].Value) -or
        -not (Test-JsonInteger $Effective.PSObject.Properties[$Field.Limit].Value)
      ) {
        return $false
      }
      $CounterProperty = $Result.PSObject.Properties[$Field.Counter]
      $CounterIsNumber = (
        (Test-JsonInteger $CounterProperty.Value) -or
        $CounterProperty.Value -is [double] -or
        $CounterProperty.Value -is [single] -or
        $CounterProperty.Value -is [decimal]
      )
      if (-not $CounterIsNumber) {
        return $false
      }
      $BaseValue = [double]$Base.PSObject.Properties[$Field.Limit].Value
      $EffectiveValue = [double]$Effective.PSObject.Properties[$Field.Limit].Value
      $CounterValue = [double]$CounterProperty.Value
      if (
        $BaseValue -lt [double]$Field.Min -or
        $EffectiveValue -ne ($BaseValue * $Multiplier) -or
        ($EffectiveValue + $BaseValue) -gt [double]$Field.Cap
      ) {
        return $false
      }
      if ($BaseValue -gt 0 -and $CounterValue -ge $EffectiveValue) {
        $ExtensibleLimitReached = $true
      }
    }
    if (
      $null -eq $Base.PSObject.Properties["max_premium_escalations"] -or
      $null -eq $Effective.PSObject.Properties["max_premium_escalations"] -or
      $null -eq $Result.PSObject.Properties["chain_premium_escalations"] -or
      -not (Test-JsonInteger $Base.PSObject.Properties["max_premium_escalations"].Value) -or
      -not (Test-JsonInteger $Effective.PSObject.Properties["max_premium_escalations"].Value) -or
      -not (Test-JsonInteger $Result.PSObject.Properties["chain_premium_escalations"].Value)
    ) {
      return $false
    }
    $BasePremium = [int64]$Base.PSObject.Properties["max_premium_escalations"].Value
    $EffectivePremium = [int64]$Effective.PSObject.Properties["max_premium_escalations"].Value
    $PremiumCounter = [int64]$Result.PSObject.Properties["chain_premium_escalations"].Value
    if (
      $BasePremium -lt 0 -or
      $BasePremium -gt 10 -or
      $BasePremium -ne $EffectivePremium -or
      $PremiumCounter -ge $EffectivePremium
    ) {
      return $false
    }
    return $ExtensibleLimitReached
  }
  catch {
    return $false
  }
}

function Get-IterationFile {
  param(
    [string]$Logs,
    [int]$Iteration,
    [string]$Suffix,
    [DateTimeOffset]$RunStarted
  )

  $Expected = Join-Path $Logs (("{0:D2}-{1}" -f $Iteration, $Suffix))
  if (Test-Path -LiteralPath $Expected -PathType Leaf) {
    $ExpectedItem = Get-Item -LiteralPath $Expected
    if ($ExpectedItem.LastWriteTimeUtc -ge $RunStarted.UtcDateTime.AddSeconds(-2)) {
      return $Expected
    }
  }
  $Latest = Get-ChildItem -LiteralPath $Logs -Filter ("*-{0}" -f $Suffix) -File -ErrorAction SilentlyContinue |
    Where-Object { $_.Name -match '^\d{2}-' } |
    Where-Object { $_.LastWriteTimeUtc -ge $RunStarted.UtcDateTime.AddSeconds(-2) } |
    Sort-Object LastWriteTime -Descending |
    Select-Object -First 1
  if ($null -ne $Latest) {
    return $Latest.FullName
  }
  return $null
}

function Write-Section {
  param([string]$Title)
  Write-Host ""
  Write-Host $Title -ForegroundColor Cyan
  Write-Host ("=" * $Title.Length) -ForegroundColor DarkCyan
}

function Get-PhaseProgress {
  param(
    [AllowNull()][string]$Phase,
    [AllowNull()][string]$FinalStatus
  )

  if ($FinalStatus -eq "done" -or $Phase -eq "done") {
    return 100
  }
  switch ($Phase) {
    "starting" { return 5 }
    "preflight" { return 10 }
    "codex_review" { return 20 }
    "claude_implementation" { return 45 }
    "claude_escalation" { return 60 }
    "automatic_checks" { return 70 }
    "final_codex_review" { return 90 }
    "needs_continuation" { return 90 }
    "blocked" { return 90 }
    "subscription_limit" { return 90 }
    "failed" { return 90 }
    default { return 10 }
  }
}

function Get-SpecChecklist {
  param([string]$ProjectPath)

  $SpecPath = Join-Path $ProjectPath "SPEC.md"
  if (-not (Test-Path -LiteralPath $SpecPath -PathType Leaf)) {
    return @()
  }
  $Items = @()
  foreach ($Line in @(Get-Content -Encoding UTF8 -LiteralPath $SpecPath -ErrorAction SilentlyContinue)) {
    if ($Line -match '^\s*[-*]\s+\[([ xX])\]\s+(.+?)\s*$') {
      $CheckboxMarker = $Matches[1]
      $CheckboxTitle = $Matches[2]
      $Items += [pscustomobject]@{
        Done = $CheckboxMarker -match '[xX]'
        Title = Protect-Text $CheckboxTitle
      }
    }
  }
  return @($Items)
}

function Get-FriendlyClaudeActivity {
  param(
    [AllowNull()][string]$Phase,
    [AllowNull()][object]$Tool,
    [AllowNull()][object]$File,
    [AllowNull()][string]$StopReasonCode,
    [AllowNull()][object]$AutomaticResumeAllowed
  )

  $SafeFile = Shorten-Text $File 160
  if ($Phase -eq "codex_review") {
    return "Claude čaká, kým Codex pripraví ďalšiu konkrétnu úlohu."
  }
  if ($Phase -eq "automatic_checks") {
    return "Claude dokončil úpravu; počítač teraz kontroluje výsledok."
  }
  if ($Phase -eq "final_codex_review") {
    return "Claude čaká na záverečnú kontrolu Codexu."
  }
  if ($Phase -eq "done") {
    return "Claude dokončil pridelenú prácu."
  }
  if ($Phase -eq "needs_continuation") {
    if ($AutomaticResumeAllowed -eq $true) {
      return "Claude dokončil tento úsek; Forge supervisor pripravuje presné automatické pokračovanie."
    }
    if ($StopReasonCode -eq "packet_attempts_exhausted") {
      return "Claude už nepracuje; Forge zastavil iba tento pracovný balík po vyčerpaní jeho pokusov."
    }
    if ($StopReasonCode -eq "chain_budget_exhausted") {
      return "Claude už nepracuje; celý ohraničený Forge chain dosiahol svoj globálny limit."
    }
    return "Claude dokončil tento úsek; ďalší presný krok je bezpečne uložený."
  }
  switch ([string]$Tool) {
    "Edit" { return $(if ($SafeFile) { "Upravuje súbor $SafeFile." } else { "Upravuje potrebnú časť aplikácie." }) }
    "Write" { return $(if ($SafeFile) { "Vytvára súbor $SafeFile." } else { "Vytvára potrebnú časť aplikácie." }) }
    "Read" { return $(if ($SafeFile) { "Kontroluje súbor $SafeFile." } else { "Kontroluje existujúce riešenie." }) }
    "Glob" { return "Hľadá súbory, ktoré súvisia s aktuálnou úlohou." }
    "Grep" { return "Hľadá miesto, ktoré treba upraviť." }
    "Bash" { return "Overuje vykonanú zmenu." }
    default {
      if ($Phase -eq "claude_escalation") {
        return "Claude rieši preukázané zablokovanie."
      }
      if ($Phase -eq "claude_implementation") {
        return "Claude vykonáva konkrétnu úlohu od Codexu."
      }
      return "Claude čaká na pridelenie alebo pokračovanie úlohy."
    }
  }
}

function Get-NextFriendlyStep {
  param(
    [AllowNull()][string]$Phase,
    [AllowNull()][string]$FinalStatus,
    [AllowNull()][string]$StopReasonCode,
    [AllowNull()][object]$AutomaticResumeAllowed
  )

  if ($FinalStatus -eq "done" -or $Phase -eq "done") {
    return "Úloha je ukončená."
  }
  switch ($Phase) {
    "starting" { return "Bezpečnostná kontrola nástrojov." }
    "preflight" { return "Codex pripraví konkrétne zadanie." }
    "codex_review" { return "Claude začne vykonávať zadanie." }
    "claude_implementation" { return "Automatické kontroly vykonanej zmeny." }
    "claude_escalation" { return "Opakované automatické kontroly." }
    "automatic_checks" { return "Codex vyhodnotí výsledky kontrol." }
    "final_codex_review" { return "Finálne schválenie alebo presný ďalší krok." }
    "needs_continuation" {
      if ($AutomaticResumeAllowed -eq $true) {
        return "Forge supervisor automaticky otvorí ďalší presný child run."
      }
      if ($StopReasonCode -eq "chain_budget_exhausted") {
        return "Neskoršie explicitné pokračovanie z uloženého runu."
      }
      if ($StopReasonCode -eq "packet_attempts_exhausted") {
        return "Vytvoriť ohraničený recovery/repair packet; rovnaký Resume by nepomohol."
      }
      return "Skontrolovať štruktúrovaný dôvod zastavenia; Resume sa nevytvára naslepo."
    }
    "subscription_limit" { return "Pokračovanie po obnovení limitu predplatného." }
    "blocked" { return "Rozhodnutie používateľa podľa poslednej správy." }
    "failed" { return "Kontrola technickej chyby podľa poslednej správy." }
    default { return "Ďalší bezpečný krok Forge cyklu." }
  }
}

function Get-UserAction {
  param(
    [AllowNull()][string]$Phase,
    [AllowNull()][string]$FinalStatus,
    [AllowNull()][string]$StopReasonCode,
    [AllowNull()][object]$AutomaticResumeAllowed,
    [AllowNull()][string]$ResumeMode,
    [AllowNull()][object]$NeedsHuman
  )

  $State = if ($FinalStatus) { $FinalStatus } else { $Phase }
  switch ($State) {
    "needs_continuation" {
      if ($AutomaticResumeAllowed -eq $true) {
        return "NIE JE POTREBNÝ – Forge supervisor pokračuje automaticky."
      }
      if ($StopReasonCode -eq "chain_budget_exhausted") {
        if ($ResumeMode) {
          return "ÁNO – neskôr použite nižšie uvedený presný resume príkaz."
        }
        return "ÁNO – režim zdrojového runu sa nedá bezpečne určiť; monitor Resume príkaz nevytvoril."
      }
      if ($StopReasonCode -eq "packet_attempts_exhausted") {
        return "ÁNO – treba recovery/repair packet; neopakujte rovnaký ResumeRunId."
      }
      return "ÁNO – skontrolujte dôvod zastavenia; monitor nevytvorí neoverený Resume."
    }
    "subscription_limit" { return "ÁNO – obnovte neskôr predplatiteľský limit; nekupujte API kredity." }
    "blocked" { return "ÁNO – pozrite poslednú správu a rozhodnite o zablokovaní." }
    "failed" { return "ÁNO – pozrite poslednú správu s technickou chybou." }
    default {
      if ($NeedsHuman -eq $true) {
        return "ÁNO – Forge označil stav ako vyžadujúci ľudský zásah."
      }
      return "NIE JE POTREBNÝ"
    }
  }
}

$ProjectItem = Get-Item -LiteralPath $Project -ErrorAction Stop
if (-not $ProjectItem.PSIsContainer) {
  throw "Project must be a directory: $Project"
}
$ResolvedProject = $ProjectItem.FullName
$ForgeDirectory = Join-Path $ResolvedProject ".forge"
$StatusPath = Join-Path $ForgeDirectory "status.json"
$PlanPath = Join-Path $ForgeDirectory "project-plan.json"
$ResultPath = Join-Path $ForgeDirectory "result.json"
$SupervisorPath = Join-Path $ForgeDirectory "chain-supervisor.json"
$Logs = Join-Path $ForgeDirectory "logs"
$TerminalPhases = @("done", "blocked", "needs_continuation", "failed", "subscription_limit")
$OutputRedirected = $false
try {
  $OutputRedirected = [Console]::IsOutputRedirected
}
catch {
  $OutputRedirected = $false
}

Write-Host "Forge Live Monitor – Varianta 3" -ForegroundColor Green
Write-Host "Jednoduchý kontrolný zoznam projektu"
Write-Host ("Projekt: {0}" -f (Protect-Text $ResolvedProject))
Write-Host "Čakám na prvý stav Forge..."

while ($true) {
  $StatusFileExists = Test-Path -LiteralPath $StatusPath -PathType Leaf
  $Status = Read-JsonFile $StatusPath
  if (
    $null -ne $Status -and
    -not (Test-StateInExpectedGeneration `
      -Object $Status `
      -TimestampNames @("run_started_at"))
  ) {
    $Status = $null
    $StatusFileExists = $false
  }
  $ProjectPlan = Read-JsonFile $PlanPath
  $LatestResult = Read-JsonFile $ResultPath
  $SupervisorFileExists = Test-Path -LiteralPath $SupervisorPath -PathType Leaf
  $Supervisor = Read-JsonFile $SupervisorPath
  if (
    $SupervisorFileExists -and
    $null -eq $Supervisor -and
    $null -ne $ExpectedGenerationNotBefore
  ) {
    try {
      if (
        (Get-Item -LiteralPath $SupervisorPath).LastWriteTimeUtc -lt
        $ExpectedGenerationNotBefore.UtcDateTime
      ) {
        $SupervisorFileExists = $false
      }
    }
    catch { }
  }
  $SupervisorObservation = Get-SupervisorObservation `
    -Supervisor $Supervisor `
    -FileExists $SupervisorFileExists `
    -ResolvedProjectPath $ResolvedProject
  if (
    $SupervisorObservation.CurrentGeneration -and
    -not $SupervisorObservation.Valid
  ) {
    Write-Section "NEPLATNÝ STAV SUPERVISORA"
    Write-Host (Protect-Text $SupervisorObservation.Message)
    Write-Host "Monitor skončil: failed" -ForegroundColor Yellow
    break
  }
  if (
    $SupervisorObservation.CurrentGeneration -and
    $SupervisorObservation.Valid -and
    $SupervisorObservation.IsTerminal -and
    (
      [string]$SupervisorObservation.Status -ne "needs_continuation" -or
      $null -eq $Status
    )
  ) {
    $SupervisorStatus = [string]$SupervisorObservation.Status
    $TerminalTitle = switch ($SupervisorStatus) {
      "done" { "FORGE SUPERVISOR DOKONČIL CHAIN" }
      "blocked" { "FORGE SUPERVISOR JE ZABLOKOVANÝ" }
      "subscription_limit" { "FORGE DOSIAHOL LIMIT PREDPLATNÉHO" }
      "needs_continuation" { "FORGE SUPERVISOR ČAKÁ NA PRESNÉ POKRAČOVANIE" }
      default { "SUPERVISOR SA ZASTAVIL" }
    }
    Write-Section $TerminalTitle
    $SupervisorReason = Get-OptionalProperty -Object $Supervisor -Name "stop_reason"
    if (-not [string]::IsNullOrWhiteSpace([string]$SupervisorReason)) {
      Write-Host ("Posledný výsledok: {0}" -f (Shorten-Text $SupervisorReason 500))
    }
    Write-Host (
      "Terminálny stav chain supervisora je autoritatívny aj vtedy, keď status/result pointer zostal neúplný alebo zastaraný."
    )
    Write-Host ("Monitor skončil: {0}" -f $SupervisorStatus) -ForegroundColor Yellow
    break
  }
  if ($null -eq $Status) {
    $WaitAnchor = if ($null -ne $ExpectedGenerationNotBefore) {
      $ExpectedGenerationNotBefore
    }
    else {
      $MonitorStartedAt
    }
    $WaitAge = ([DateTimeOffset]::UtcNow - $WaitAnchor).TotalSeconds
    if (
      $SupervisorObservation.CurrentGeneration -and
      $SupervisorObservation.IsRunning -and
      $null -ne $SupervisorObservation.AgeSeconds -and
      $SupervisorObservation.AgeSeconds -gt $SupervisorGraceSeconds
    ) {
      Write-Section "SUPERVISOR NEREAGUJE"
      Write-Host "Supervisor zostal v stave running, ale nevytvoril čitateľný aktuálny status projektu."
      Write-Host "Monitor skončil: failed" -ForegroundColor Yellow
      break
    }
    if (
      -not $SupervisorObservation.CurrentGeneration -and
      $WaitAge -gt $SupervisorGraceSeconds
    ) {
      Write-Section "SUPERVISOR SA NESPUSTIL"
      Write-Host "Počas ochranného intervalu nevznikol stav supervisora patriaci tomuto spusteniu."
      Write-Host "Skontrolujte wrapper log; monitor už nebude čakať donekonečna."
      Write-Host "Monitor skončil: failed" -ForegroundColor Yellow
      break
    }
    Start-Sleep -Seconds $RefreshSeconds
    continue
  }
  $StatusRunId = [string](Get-OptionalProperty -Object $Status -Name "run_id")
  $MatchingResult = $null
  if ($null -ne $LatestResult) {
    $ResultRunId = [string](Get-OptionalProperty -Object $LatestResult -Name "run_id")
    if (
      -not [string]::IsNullOrWhiteSpace($StatusRunId) -and
      -not [string]::IsNullOrWhiteSpace($ResultRunId) -and
      $ResultRunId -ceq $StatusRunId
    ) {
      $MatchingResult = $LatestResult
    }
  }

  $TerminationKnown = $false
  $StopReasonCode = ""
  $AutomaticResumeAllowed = $null
  $ResumeMode = $null
  $ChainResumeCandidate = $false
  $ResultSchemaVersion = 1
  $ResultSchemaIsValid = $true
  $FinalMessage = ""
  if ($null -ne $MatchingResult) {
    $SchemaProperty = $MatchingResult.PSObject.Properties["schema_version"]
    $FinalMessageProperty = $MatchingResult.PSObject.Properties["final_message"]
    if (
      $null -ne $FinalMessageProperty -and
      $FinalMessageProperty.Value -is [string]
    ) {
      $FinalMessage = [string]$FinalMessageProperty.Value
    }
    if ($null -eq $SchemaProperty) {
      $ResultSchemaVersion = 1
    }
    elseif (-not (Test-JsonInteger $SchemaProperty.Value)) {
      $ResultSchemaVersion = 0
      $ResultSchemaIsValid = $false
      $StopReasonCode = "invalid_result_termination"
      $AutomaticResumeAllowed = $false
      $TerminationKnown = $true
    }
    else {
      $ResultSchemaVersion = [int64]$SchemaProperty.Value
      if ($ResultSchemaVersion -lt 1) {
        $ResultSchemaIsValid = $false
        $StopReasonCode = "invalid_result_termination"
        $AutomaticResumeAllowed = $false
        $TerminationKnown = $true
      }
    }
    if ($ResultSchemaIsValid -and $ResultSchemaVersion -ge 4) {
      $StopReasonProperty = $MatchingResult.PSObject.Properties["stop_reason_code"]
      $AutomaticProperty = $MatchingResult.PSObject.Properties["automatic_resume_allowed"]
      $FinalStatusProperty = $MatchingResult.PSObject.Properties["final_status"]
      if (
        $null -ne $StopReasonProperty -and
        $StopReasonProperty.Value -is [string] -and
        -not [string]::IsNullOrWhiteSpace([string]$StopReasonProperty.Value) -and
        $null -ne $AutomaticProperty -and
        (Test-JsonBoolean $AutomaticProperty.Value) -and
        $null -ne $FinalStatusProperty -and
        $FinalStatusProperty.Value -is [string]
      ) {
        $CandidateStopReason = [string]$StopReasonProperty.Value
        $CandidateFinalStatus = [string]$FinalStatusProperty.Value
        $CandidateAutomatic = [bool]$AutomaticProperty.Value
        $ExpectedStatuses = @{
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
        if (
          $ExpectedStatuses.ContainsKey($CandidateStopReason) -and
          $CandidateFinalStatus -ceq [string]$ExpectedStatuses[$CandidateStopReason] -and
          $CandidateAutomatic -eq ($AutomaticReasons -contains $CandidateStopReason)
        ) {
          $StopReasonCode = $CandidateStopReason
          $AutomaticResumeAllowed = $CandidateAutomatic
          $TerminationKnown = $true
        }
        else {
          $StopReasonCode = "invalid_result_termination"
          $AutomaticResumeAllowed = $false
          $TerminationKnown = $true
        }
      }
      else {
        $StopReasonCode = "invalid_result_termination"
        $AutomaticResumeAllowed = $false
        $TerminationKnown = $true
      }
    }
    elseif ($ResultSchemaIsValid) {
      # Text routing is deliberately restricted to legacy schema <= 3.
      if ($FinalMessage -match "(?i)chain.*budget exhausted") {
        $StopReasonCode = "chain_budget_exhausted"
      }
      elseif ($FinalMessage -match "(?i)packet.*attempt") {
        $StopReasonCode = "packet_attempts_exhausted"
      }
      else {
        $StopReasonCode = "legacy_continuation_unknown"
      }
      $AutomaticResumeAllowed = $false
      $TerminationKnown = $true
    }
  }
  if (
    $TerminationKnown -and
    $StopReasonCode -eq "chain_budget_exhausted" -and
    $AutomaticResumeAllowed -eq $false
  ) {
    $ChainResumeCandidate = Test-ChainBudgetResumeCandidate -Result $MatchingResult
    $ResumeRunIdForMode = if ($null -ne $MatchingResult) {
      [string](Get-OptionalProperty -Object $MatchingResult -Name "run_id")
    }
    else {
      $StatusRunId
    }
    if ($ChainResumeCandidate) {
      $ResumeMode = Get-ResumeWrapperMode `
        -ForgeDirectory $ForgeDirectory `
        -RunId $ResumeRunIdForMode
    }
  }

  # New Forge versions keep immutable logs per run. Trust the status path only
  # when it resolves inside this project's .forge directory.
  $StatusLogs = ""
  $StatusLogsProperty = $Status.PSObject.Properties["logs_path"]
  if ($null -ne $StatusLogsProperty) {
    $StatusLogs = [string]$StatusLogsProperty.Value
  }
  if (-not [string]::IsNullOrWhiteSpace($StatusLogs)) {
    try {
      $CandidateLogs = [System.IO.Path]::GetFullPath(
        (Convert-ForgeRuntimePath $StatusLogs)
      )
      $AllowedPrefix = [System.IO.Path]::GetFullPath($ForgeDirectory).TrimEnd("\") + "\"
      if ($CandidateLogs.StartsWith($AllowedPrefix, [System.StringComparison]::OrdinalIgnoreCase)) {
        $Logs = $CandidateLogs
      }
    }
    catch { }
  }

  if (-not $NoClear -and -not $OutputRedirected) {
    Clear-Host
  }

  $Iteration = 0
  try { $Iteration = [int]$Status.iteration } catch { $Iteration = 0 }
  $Phase = Protect-Text $Status.phase
  $RunStarted = [DateTimeOffset]::UtcNow.AddYears(-100)
  try { $RunStarted = [DateTimeOffset]::Parse([string]$Status.run_started_at) } catch { }
  $ElapsedSeconds = Protect-Text $Status.elapsed_seconds
  try {
    $PhaseStarted = [DateTimeOffset]::Parse([string]$Status.phase_started_at)
    $ElapsedSeconds = [math]::Round(([DateTimeOffset]::UtcNow - $PhaseStarted).TotalSeconds, 1)
  }
  catch {
    $ElapsedSeconds = Protect-Text $Status.elapsed_seconds
  }

  $DecisionPath = $null
  if ($Phase -eq "final_codex_review") {
    $FinalDecisionPath = Join-Path $Logs "final-decision.json"
    if (Test-Path -LiteralPath $FinalDecisionPath -PathType Leaf) {
      $FinalDecisionItem = Get-Item -LiteralPath $FinalDecisionPath
      if ($FinalDecisionItem.LastWriteTimeUtc -ge $RunStarted.UtcDateTime.AddSeconds(-2)) {
        $DecisionPath = $FinalDecisionPath
      }
    }
  }
  if ($null -eq $DecisionPath) {
    $DecisionPath = Get-IterationFile -Logs $Logs -Iteration $Iteration -Suffix "decision.json" -RunStarted $RunStarted
  }
  $Decision = if ($null -ne $DecisionPath) { Read-JsonFile $DecisionPath } else { $null }

  $ChecksPath = Get-IterationFile -Logs $Logs -Iteration $Iteration -Suffix "checks.json" -RunStarted $RunStarted
  $Checks = if ($null -ne $ChecksPath) { Read-JsonFile $ChecksPath } else { $null }

  $FinalStatus = Protect-Text $Status.final_status
  if ($TerminationKnown -and $null -ne $MatchingResult) {
    $ResultFinalStatus = Protect-Text (
      Get-OptionalProperty -Object $MatchingResult -Name "final_status"
    )
    if ($TerminalPhases -contains $ResultFinalStatus) {
      # Older Forge builds could atomically publish result.json while leaving
      # status.json on the preceding codex_review phase. A matching immutable
      # terminal result is authoritative and must not be displayed as a hang.
      $FinalStatus = $ResultFinalStatus
    }
  }
  $ProjectName = Split-Path -Leaf $ResolvedProject
  $SpecChecklist = @(Get-SpecChecklist -ProjectPath $ResolvedProject)
  $Progress = Get-PhaseProgress -Phase $Phase -FinalStatus $FinalStatus
  $PacketTotal = 0
  $PacketCompleted = 0
  try { $PacketTotal = [int]$Status.packet_total } catch { $PacketTotal = 0 }
  try { $PacketCompleted = [int]$Status.packet_completed } catch { $PacketCompleted = 0 }
  if ($PacketTotal -gt 0) {
    $Progress = [math]::Round(($PacketCompleted * 100.0) / $PacketTotal)
  }
  elseif ($SpecChecklist.Count -gt 0) {
    $CompletedSpecItems = @($SpecChecklist | Where-Object { $_.Done }).Count
    $Progress = [math]::Round(($CompletedSpecItems * 100.0) / $SpecChecklist.Count)
  }
  $ProgressLabel = if ($SpecChecklist.Count -gt 0 -or $FinalStatus -eq "done" -or $Phase -eq "done") {
    "HOTOVÉ"
  }
  else {
    "ODHAD POSTUPU"
  }

  Write-Host ""
  Write-Host ("{0}    {1}% {2}" -f (Protect-Text $ProjectName.ToUpperInvariant()), $Progress, $ProgressLabel) -ForegroundColor Green

  Write-Section "KONTROLNÝ ZOZNAM PROJEKTU"
  if ($null -ne $ProjectPlan -and $null -ne $ProjectPlan.PSObject.Properties["work_packets"]) {
    $Packets = @($ProjectPlan.work_packets)
    foreach ($Packet in @($Packets | Select-Object -First 12)) {
      $PacketStatus = [string]$Packet.status
      $Marker = switch ($PacketStatus) {
        "completed" { "✓" }
        "in_progress" { "◉" }
        "verification" { "◉" }
        "blocked" { "!" }
        "superseded" { "–" }
        default { "○" }
      }
      Write-Host ("{0} {1}" -f $Marker, (Shorten-Text $Packet.title 120))
    }
    if ($Packets.Count -gt 12) {
      Write-Host ("… a ďalších {0} pracovných balíkov" -f ($Packets.Count - 12))
    }
  }
  elseif ($SpecChecklist.Count -gt 0) {
    $CurrentShown = $false
    foreach ($Item in @($SpecChecklist | Select-Object -First 8)) {
      if ($Item.Done) {
        $Marker = "✓"
      }
      elseif (-not $CurrentShown) {
        $Marker = "◉"
        $CurrentShown = $true
      }
      else {
        $Marker = "○"
      }
      Write-Host ("{0} {1}" -f $Marker, (Shorten-Text $Item.Title 120))
    }
    if ($SpecChecklist.Count -gt 8) {
      Write-Host ("… a ďalších {0} položiek v SPEC.md" -f ($SpecChecklist.Count - 8))
    }
  }
  else {
    $Criteria = @()
    if ($null -ne $Decision -and $null -ne $Decision.PSObject.Properties["acceptance_criteria"]) {
      $Criteria = @($Decision.acceptance_criteria)
    }
    if ($Criteria.Count -gt 0) {
      $CurrentShown = $false
      foreach ($Criterion in @($Criteria | Select-Object -First 6)) {
        if ($FinalStatus -eq "done" -or $Phase -eq "done") {
          $Marker = "✓"
        }
        elseif (-not $CurrentShown) {
          $Marker = "◉"
          $CurrentShown = $true
        }
        else {
          $Marker = "○"
        }
        Write-Host ("{0} {1}" -f $Marker, (Shorten-Text $Criterion 120))
      }
    }
    else {
      $Stages = @(
        [pscustomobject]@{ Title = "Codex pripravil konkrétne zadanie"; CompleteAt = 20 },
        [pscustomobject]@{ Title = "Claude vykonal implementáciu"; CompleteAt = 70 },
        [pscustomobject]@{ Title = "Automatické kontroly"; CompleteAt = 90 },
        [pscustomobject]@{ Title = "Codex schválil výsledok"; CompleteAt = 100 }
      )
      $CurrentShown = $false
      foreach ($Stage in $Stages) {
        if ($Progress -ge $Stage.CompleteAt) {
          $Marker = "✓"
        }
        elseif (-not $CurrentShown) {
          $Marker = "◉"
          $CurrentShown = $true
        }
        else {
          $Marker = "○"
        }
        Write-Host ("{0} {1}" -f $Marker, $Stage.Title)
      }
    }
  }

  $CodexTask = Protect-Text $Status.goal
  if ($null -ne $Status.PSObject.Properties["codex_assignment"] -and -not [string]::IsNullOrWhiteSpace([string]$Status.codex_assignment)) {
    $CodexTask = Protect-Text $Status.codex_assignment
  }
  if ($null -ne $Decision -and $null -ne $Decision.PSObject.Properties["next_prompt"] -and -not [string]::IsNullOrWhiteSpace([string]$Decision.next_prompt)) {
    $CodexTask = Protect-Text $Decision.next_prompt
  }
  $ClaudeActivity = Get-FriendlyClaudeActivity `
    -Phase $Phase `
    -Tool $Status.current_tool `
    -File $Status.current_file `
    -StopReasonCode $StopReasonCode `
    -AutomaticResumeAllowed $AutomaticResumeAllowed
  $CurrentStep = Shorten-Text $Status.last_visible_message 320
  if ([string]::IsNullOrWhiteSpace($CurrentStep)) {
    $CurrentStep = $ClaudeActivity
  }
  $LastResult = "Kontroly ešte neboli dokončené."
  if ($null -ne $Status.PSObject.Properties["last_result"] -and -not [string]::IsNullOrWhiteSpace([string]$Status.last_result)) {
    $LastResult = Shorten-Text $Status.last_result 320
  }
  if ($null -ne $Checks) {
    $CheckItems = @($Checks)
    $PassedChecks = @($CheckItems | Where-Object { [int]$_.exit_code -eq 0 }).Count
    if ($PassedChecks -eq $CheckItems.Count) {
      $LastResult = "Prešlo všetkých $PassedChecks z $($CheckItems.Count) kontrol."
    }
    else {
      $LastResult = "Prešlo $PassedChecks z $($CheckItems.Count) kontrol; nájdený problém sa ešte rieši."
    }
  }
  if ($Phase -eq "needs_continuation" -or $FinalStatus -eq "needs_continuation") {
    if ($StopReasonCode -eq "packet_attempts_exhausted") {
      $LastResult = "Aktívny pracovný balík vyčerpal svoje pokusy; globálny chain budget môže mať stále rezervu."
    }
    elseif ($StopReasonCode -eq "chain_budget_exhausted") {
      $LastResult = "Celý continuation chain dosiahol svoj globálny bezpečný limit."
    }
    elseif ($TerminationKnown -and -not [string]::IsNullOrWhiteSpace($FinalMessage)) {
      $LastResult = Shorten-Text $FinalMessage 320
    }
  }

  Write-Section "AKTUÁLNA ÚLOHA"
  $ActivePacket = Shorten-Text (Get-OptionalProperty -Object $Status -Name "active_packet_title") 180
  if ([string]::IsNullOrWhiteSpace($ActivePacket)) {
    $ActivePacket = Shorten-Text (Get-OptionalProperty -Object $Status -Name "active_packet_id") 180
  }
  Write-Host ""
  Write-Host "Aktívny pracovný balík:" -ForegroundColor Yellow
  Write-Host $(if ($ActivePacket) { $ActivePacket } else { "Forge pripravuje prvý pracovný balík." })
  Write-Host ""
  Write-Host "Codex zadal:" -ForegroundColor Yellow
  Write-Host (Shorten-Text $CodexTask 380)
  Write-Host ""
  Write-Host "Claude práve:" -ForegroundColor Yellow
  Write-Host $ClaudeActivity
  $WorkerProfile = Shorten-Text (Get-OptionalProperty -Object $Status -Name "worker_profile") 80
  $WorkerReason = Shorten-Text (Get-OptionalProperty -Object $Status -Name "worker_profile_reason") 220
  if ($WorkerProfile) {
    Write-Host ("Profil pracovníka: {0}" -f $WorkerProfile) -ForegroundColor DarkYellow
    if ($WorkerReason) {
      Write-Host ("Prečo: {0}" -f $WorkerReason)
    }
    $RequestedTurns = Get-OptionalProperty -Object $Status -Name "requested_turn_budget"
    $TurnLimitEnforced = Get-OptionalProperty -Object $Status -Name "cli_turn_limit_enforced"
    $EffectiveTimeout = Get-OptionalProperty -Object $Status -Name "effective_timeout"
    if ($RequestedTurns) {
      $EnforcementText = if ($TurnLimitEnforced) {
        "áno, priamo cez Claude CLI"
      }
      else {
        "nie; Forge používa časový a chain limit"
      }
      Write-Host (
        "Limit pokusu: {0} turnov | CLI vynútenie: {1} | čas: {2} s" -f `
          (Protect-Text $RequestedTurns), $EnforcementText, (Protect-Text $EffectiveTimeout)
      ) -ForegroundColor DarkCyan
    }
  }
  Write-Host ""
  Write-Host "Aktuálny krok:" -ForegroundColor Yellow
  Write-Host $CurrentStep
  Write-Host ""
  Write-Host "Posledný výsledok:" -ForegroundColor Yellow
  Write-Host $LastResult
  Write-Host ""
  Write-Host "Nasleduje:" -ForegroundColor Yellow
  $NextAction = Shorten-Text (Get-OptionalProperty -Object $Status -Name "next_action") 260
  if ($Phase -eq "needs_continuation" -or $FinalStatus -eq "needs_continuation") {
    $NextAction = Get-NextFriendlyStep `
      -Phase $Phase `
      -FinalStatus $FinalStatus `
      -StopReasonCode $StopReasonCode `
      -AutomaticResumeAllowed $AutomaticResumeAllowed
  }
  elseif (-not $NextAction) {
    $NextAction = Get-NextFriendlyStep `
      -Phase $Phase `
      -FinalStatus $FinalStatus `
      -StopReasonCode $StopReasonCode `
      -AutomaticResumeAllowed $AutomaticResumeAllowed
  }
  Write-Host $NextAction
  $CheckTier = Shorten-Text (Get-OptionalProperty -Object $Status -Name "check_tier") 60
  if ($CheckTier) {
    Write-Host ""
    Write-Host ("Úroveň kontroly: {0}" -f $CheckTier) -ForegroundColor Yellow
  }
  $BudgetText = ""
  if ($null -ne $Status.PSObject.Properties["remaining_chain_budget"] -and $null -ne $Status.remaining_chain_budget) {
    $BudgetPairs = @()
    foreach ($Property in $Status.remaining_chain_budget.PSObject.Properties) {
      $BudgetPairs += ("{0}: {1}" -f $Property.Name, (Protect-Text $Property.Value))
    }
    $BudgetText = $BudgetPairs -join " | "
  }
  if ($BudgetText) {
    Write-Host ("Zostávajúci bezpečný limit: {0}" -f $BudgetText) -ForegroundColor DarkCyan
  }
  Write-Host ("Prémiové/frontier použitia: {0}" -f (Protect-Text (Get-OptionalProperty -Object $Status -Name "premium_uses"))) -ForegroundColor DarkCyan
  $ActivityState = [string](Get-OptionalProperty -Object $Status -Name "activity_state")
  $NeedsHuman = Get-OptionalProperty -Object $Status -Name "needs_human"
  if (
    ($Phase -eq "needs_continuation" -or $FinalStatus -eq "needs_continuation") -and
    $TerminationKnown -and
    $AutomaticResumeAllowed -eq $false
  ) {
    $NeedsHuman = $true
  }
  $HeartbeatAge = $null
  try {
    $HeartbeatAt = [DateTimeOffset]::Parse([string]$Status.heartbeat_at)
    $HeartbeatAge = ([DateTimeOffset]::UtcNow - $HeartbeatAt).TotalSeconds
  }
  catch { }
  if (
    ($Phase -eq "needs_continuation" -or $FinalStatus -eq "needs_continuation") -and
    $AutomaticResumeAllowed -eq $true
  ) {
    Write-Host "Stav aktivity: child run skončil; Forge supervisor pripravuje presné automatické pokračovanie." -ForegroundColor DarkYellow
  }
  elseif (
    $ActivityState -eq "terminal" -or
    $TerminalPhases -contains $Phase -or
    $TerminalPhases -contains $FinalStatus
  ) {
    Write-Host "Stav aktivity: proces je ukončený alebo bezpečne zastavený; nejde o hang." -ForegroundColor DarkYellow
  }
  elseif ($null -ne $HeartbeatAge -and $HeartbeatAge -gt 90) {
    Write-Host "Stav aktivity: pravdepodobný hang – heartbeat je starší než 90 sekúnd." -ForegroundColor Red
  }
  elseif ($Phase -eq "automatic_checks" -and $ElapsedSeconds -gt 30) {
    Write-Host "Stav aktivity: prebieha dlhšia lokálna kontrola." -ForegroundColor DarkYellow
  }
  elseif ($null -ne $HeartbeatAge -and $HeartbeatAge -gt 30) {
    Write-Host "Stav aktivity: tichý lokálny subprocess, Forge stále čaká." -ForegroundColor DarkYellow
  }
  else {
    Write-Host "Stav aktivity: aktívna práca." -ForegroundColor DarkGreen
  }
  Write-Host ""
  Write-Host (
    "Váš zásah: {0}" -f (
      Get-UserAction `
        -Phase $Phase `
        -FinalStatus $FinalStatus `
        -StopReasonCode $StopReasonCode `
        -AutomaticResumeAllowed $AutomaticResumeAllowed `
        -ResumeMode $ResumeMode `
        -NeedsHuman $NeedsHuman
    )
  ) -ForegroundColor Magenta

  if (
    -not ($TerminalPhases -contains $Phase) -and
    -not ($TerminalPhases -contains $FinalStatus) -and
    $null -ne $HeartbeatAge -and
    $HeartbeatAge -gt $SupervisorGraceSeconds -and
    (
      -not $SupervisorObservation.CurrentGeneration -or
      (
        $SupervisorObservation.IsRunning -and
        $null -ne $SupervisorObservation.AgeSeconds -and
        $SupervisorObservation.AgeSeconds -gt $SupervisorGraceSeconds
      )
    )
  ) {
    Write-Section "SUPERVISOR NEREAGUJE"
    Write-Host "Status aj supervisor heartbeat zostali počas ochranného intervalu bez pohybu."
    Write-Host "Monitor skončil: failed" -ForegroundColor Yellow
    break
  }

  $TechnicalDetails = $ShowTechnicalDetails -or $ShowFullCommands
  if ($TechnicalDetails) {
    Write-Section "TECHNICKÉ PODROBNOSTI"
    Write-Host ("Projekt: {0}" -f (Protect-Text $Status.project))
    Write-Host ("Beh: {0}" -f (Protect-Text $Status.run_id))
    Write-Host ("Logy behu: {0}" -f (Protect-Text $Logs))
    Write-Host ("Iterácia: {0}" -f $Iteration)
    Write-Host ("Fáza: {0}" -f $Phase)
    Write-Host ("Agent: {0}" -f (Protect-Text $Status.current_agent))
    Write-Host ("Trvanie fázy: {0}s" -f $ElapsedSeconds)
    $Command = Protect-Text $Status.current_command
    if (-not $ShowFullCommands) {
      $Command = Shorten-Text $Command 260
    }
    Write-Host ("Nástroj: {0}" -f (Protect-Text $Status.current_tool))
    Write-Host ("Súbor: {0}" -f (Protect-Text $Status.current_file))
    Write-Host ("Príkaz: {0}" -f $Command)

    Write-Host ""
    Write-Host "Zmenené súbory:" -ForegroundColor DarkCyan
    try {
      $GitStatus = & git -C $ResolvedProject status --short 2>&1
      if ($null -eq $GitStatus -or $GitStatus.Count -eq 0) {
        Write-Host "(bez zmien)"
      }
      else {
        $GitStatus | ForEach-Object { Write-Host (Protect-Text $_) }
      }
      if ($ShowDiffStat) {
        $DiffStat = & git -C $ResolvedProject diff --stat 2>&1
        if ($null -ne $DiffStat -and $DiffStat.Count -gt 0) {
          $DiffStat | ForEach-Object { Write-Host (Protect-Text $_) }
        }
      }
    }
    catch {
      Write-Host ("Git stav sa nepodarilo načítať: {0}" -f (Protect-Text $_.Exception.Message))
    }

    Write-Host ""
    Write-Host "Kontroly:" -ForegroundColor DarkCyan
    if ($null -ne $Checks) {
      foreach ($Check in @($Checks)) {
        Write-Host ("[{0}] {1}" -f (Protect-Text $Check.exit_code), (Protect-Text $Check.command))
        if ($Check.exit_code -ne 0) {
          Write-Host (Shorten-Text $Check.output 700)
        }
      }
    }
    else {
      Write-Host "(zatiaľ bez výsledkov)"
    }

    Write-Host ""
    Write-Host "Posledné udalosti:" -ForegroundColor DarkCyan
    $LivePath = Get-IterationFile -Logs $Logs -Iteration $Iteration -Suffix "claude-live.log" -RunStarted $RunStarted
    if ($null -ne $LivePath -and (Test-Path -LiteralPath $LivePath -PathType Leaf)) {
      Get-Content -Encoding UTF8 -LiteralPath $LivePath -Tail 10 |
        ForEach-Object { Write-Host (Protect-Text $_) }
    }
    else {
      Write-Host "(zatiaľ bez udalostí)"
    }
  }

  if ($TerminalPhases -contains $Phase -or $TerminalPhases -contains $FinalStatus) {
    if ($Phase -eq "needs_continuation" -or $FinalStatus -eq "needs_continuation") {
      if (-not $TerminationKnown) {
        if (
          $SupervisorObservation.CurrentGeneration -and
          $SupervisorObservation.IsTerminal
        ) {
          Write-Section "NEÚPLNÝ TERMINÁLNY VÝSLEDOK"
          Write-Host "Supervisor už skončil, ale matching result.json nemá platný štruktúrovaný termination kontrakt."
          Write-Host "Monitor nevytvára Resume príkaz a nebude čakať donekonečna."
          Write-Host "Monitor skončil: failed" -ForegroundColor Yellow
          break
        }
        if (
          (
            -not $SupervisorObservation.CurrentGeneration -or
            (
              $SupervisorObservation.IsRunning -and
              $null -ne $SupervisorObservation.AgeSeconds -and
              $SupervisorObservation.AgeSeconds -gt $SupervisorGraceSeconds
            )
          ) -and
          $null -ne $HeartbeatAge -and
          $HeartbeatAge -gt $SupervisorGraceSeconds
        ) {
          Write-Section "SUPERVISOR NEREAGUJE"
          Write-Host "Matching result.json nevznikol a supervisor chýba alebo sa počas ochranného intervalu neposunul."
          Write-Host "Monitor skončil: failed" -ForegroundColor Yellow
          break
        }
        Write-Section "ČAKÁM NA ŠTRUKTÚROVANÝ VÝSLEDOK"
        Write-Host "Child run už oznámil continuation bod, ale jeho matching result.json ešte nie je atomicky dostupný."
        Write-Host "Monitor zatiaľ negeneruje Resume ani neoznačuje proces ako hang."
        Start-Sleep -Seconds $RefreshSeconds
        continue
      }
      if ($AutomaticResumeAllowed -eq $true) {
        if (
          $SupervisorObservation.CurrentGeneration -and
          $SupervisorObservation.IsTerminal
        ) {
          Write-Section "NEKONZISTENTNÝ TERMINÁLNY SUPERVISOR"
          Write-Host "Child result povoľoval automatické pokračovanie, ale chain supervisor už má terminálny stav."
          Write-Host "Manuálny Resume sa negeneruje; skontrolujte wrapper a chain-supervisor log."
          Write-Host ""
          Write-Host "Monitor skončil: failed" -ForegroundColor Yellow
          break
        }
        if (
          (
            -not $SupervisorObservation.CurrentGeneration -or
            (
              $SupervisorObservation.IsRunning -and
              $null -ne $SupervisorObservation.AgeSeconds -and
              $SupervisorObservation.AgeSeconds -gt $SupervisorGraceSeconds
            )
          ) -and
          $null -ne $HeartbeatAge -and
          $HeartbeatAge -gt $SupervisorGraceSeconds
        ) {
          Write-Section "SUPERVISOR NEREAGUJE"
          Write-Host "Child run je ukončený, ale supervisor chýba alebo sa spolu s heartbeat počas ochranného intervalu neposunul."
          Write-Host "Monitor tento stav už nevydáva za automatické pokračovanie. Skontrolujte wrapper a chain-supervisor log."
          Write-Host ""
          Write-Host "Monitor skončil: failed" -ForegroundColor Yellow
          break
        }
        Write-Section "AUTOMATICKÉ POKRAČOVANIE"
        Write-Host "Presný ďalší krok je validovaný a Forge supervisor ho otvorí bez generického reštartu."
        Write-Host "Váš zásah ani manuálny Resume nie sú potrebné."
        Start-Sleep -Seconds $RefreshSeconds
        continue
      }
      if ($StopReasonCode -eq "chain_budget_exhausted") {
        $SupervisorConfirmedManualStop = (
          $SupervisorObservation.CurrentGeneration -and
          $SupervisorObservation.Valid -and
          $SupervisorObservation.IsTerminal -and
          [string]$SupervisorObservation.Status -eq "needs_continuation" -and
          [int64]$SupervisorObservation.ExitCode -eq 4
        )
        if (-not $SupervisorConfirmedManualStop) {
          if (
            $null -ne $HeartbeatAge -and
            $HeartbeatAge -gt $SupervisorGraceSeconds -and
            (
              -not $SupervisorObservation.CurrentGeneration -or
              (
                $SupervisorObservation.IsRunning -and
                $null -ne $SupervisorObservation.AgeSeconds -and
                $SupervisorObservation.AgeSeconds -gt $SupervisorGraceSeconds
              )
            )
          ) {
            Write-Section "SUPERVISOR NEPOTVRDIL MANUÁLNE POKRAČOVANIE"
            Write-Host "Child result uvádza chain budget stop, ale celý supervisor nepotvrdil terminálny exit code 4."
            Write-Host "Monitor nevytvára predčasný Resume príkaz."
            Write-Host "Monitor skončil: failed" -ForegroundColor Yellow
            break
          }
          Write-Section "ČAKÁM NA UKONČENIE SUPERVISORA"
          Write-Host "Child result je uložený, ale manuálny Resume sa zobrazí až po terminálnom exit code 4 celého chain supervisora."
          Start-Sleep -Seconds $RefreshSeconds
          continue
        }
        $ResumeRunId = if ($null -ne $MatchingResult -and $MatchingResult.run_id) {
          [string]$MatchingResult.run_id
        }
        else {
          [string]$Status.run_id
        }
        Write-Section "POKRAČOVANIE PO GLOBÁLNOM CHAIN LIMITE"
        Write-Host "Vyčerpal sa celý ohraničený chain budget, nie počet pokusov jedného packetu."
        Write-Host "Forge bezpečne uložil presnú ďalšiu úlohu. Nespúšťajte nový generický run."
        if ($ResumeMode -and $ChainResumeCandidate) {
          $WrapperPath = Join-Path $PSScriptRoot "Start-ForgeAutonomous.ps1"
          Write-Host "Resume príkaz:"
          Write-Host (
            "& {0} -ProjectPath {1} -ResumeRunId {2} -Mode {3}" -f `
              (Format-PowerShellLiteral $WrapperPath),
              (Format-PowerShellLiteral $ResolvedProject),
              (Format-PowerShellLiteral $ResumeRunId),
              (Format-PowerShellLiteral $ResumeMode)
          )
        }
        elseif (-not $ChainResumeCandidate) {
          Write-Host "Persistované počítadlá nepotvrdzujú bezpečne rozšíriteľný ne-prémiový budget tranche."
          Write-Host "Monitor preto nevytvára Resume príkaz; wrapper by takýto resume zamietol ešte pred workerom."
        }
        else {
          Write-Host "Matching source run nemá bezpečne rozpoznateľnú kombináciu config.mode/security_profile."
          Write-Host "Monitor preto nevytvára Resume príkaz; najprv skontrolujte alebo migrujte zdrojový run."
        }
      }
      else {
        Write-Section "FORGE SA BEZPEČNE ZASTAVIL"
        if ($StopReasonCode -eq "packet_attempts_exhausted") {
          Write-Host "Vyčerpal sa počet pokusov aktívneho packetu, nie globálny chain budget."
          Write-Host "Rovnaký ResumeRunId by sa zastavil na rovnakom limite, preto monitor nevytvára Resume príkaz."
          Write-Host "Potrebný je ohraničený recovery/repair packet alebo oprava attempt politiky."
        }
        else {
          Write-Host ("Dôvod: {0}" -f (Protect-Text $StopReasonCode))
          Write-Host "Tento štruktúrovaný dôvod nepovoľuje automatické pokračovanie a monitor nevytvára neoverený Resume príkaz."
        }
      }
    }
    Write-Host ""
    Write-Host ("Monitor skončil: {0}" -f $(if ($FinalStatus) { $FinalStatus } else { $Phase })) -ForegroundColor Yellow
    break
  }

  Start-Sleep -Seconds $RefreshSeconds
}
