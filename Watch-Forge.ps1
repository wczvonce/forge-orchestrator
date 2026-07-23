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

  [switch]$NoClear
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"
$env:PYTHONUTF8 = "1"
$env:PYTHONIOENCODING = "utf-8"
$Utf8 = New-Object System.Text.UTF8Encoding($false)
[Console]::OutputEncoding = $Utf8
$OutputEncoding = $Utf8

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
    [AllowNull()][object]$File
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
    [AllowNull()][string]$FinalStatus
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
    "needs_continuation" { return "Explicitné pokračovanie uloženým resume príkazom." }
    "subscription_limit" { return "Pokračovanie po obnovení limitu predplatného." }
    "blocked" { return "Rozhodnutie používateľa podľa poslednej správy." }
    "failed" { return "Kontrola technickej chyby podľa poslednej správy." }
    default { return "Ďalší bezpečný krok Forge cyklu." }
  }
}

function Get-UserAction {
  param(
    [AllowNull()][string]$Phase,
    [AllowNull()][string]$FinalStatus
  )

  $State = if ($FinalStatus) { $FinalStatus } else { $Phase }
  switch ($State) {
    "needs_continuation" { return "ÁNO – použite nižšie uvedený resume príkaz." }
    "subscription_limit" { return "ÁNO – obnovte neskôr predplatiteľský limit; nekupujte API kredity." }
    "blocked" { return "ÁNO – pozrite poslednú správu a rozhodnite o zablokovaní." }
    "failed" { return "ÁNO – pozrite poslednú správu s technickou chybou." }
    default { return "NIE JE POTREBNÝ" }
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
  $Status = Read-JsonFile $StatusPath
  if ($null -eq $Status) {
    Start-Sleep -Seconds $RefreshSeconds
    continue
  }
  $ProjectPlan = Read-JsonFile $PlanPath

  # New Forge versions keep immutable logs per run. Trust the status path only
  # when it resolves inside this project's .forge directory.
  $StatusLogs = ""
  $StatusLogsProperty = $Status.PSObject.Properties["logs_path"]
  if ($null -ne $StatusLogsProperty) {
    $StatusLogs = [string]$StatusLogsProperty.Value
  }
  if (-not [string]::IsNullOrWhiteSpace($StatusLogs)) {
    try {
      $CandidateLogs = [System.IO.Path]::GetFullPath($StatusLogs)
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
  $ClaudeActivity = Get-FriendlyClaudeActivity -Phase $Phase -Tool $Status.current_tool -File $Status.current_file
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
  Write-Host $(if ($NextAction) { $NextAction } else { Get-NextFriendlyStep -Phase $Phase -FinalStatus $FinalStatus })
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
  $HeartbeatAge = $null
  try {
    $HeartbeatAt = [DateTimeOffset]::Parse([string]$Status.heartbeat_at)
    $HeartbeatAge = ([DateTimeOffset]::UtcNow - $HeartbeatAt).TotalSeconds
  }
  catch { }
  if ($null -ne $HeartbeatAge -and $HeartbeatAge -gt 90) {
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
  Write-Host ("Váš zásah: {0}" -f (Get-UserAction -Phase $Phase -FinalStatus $FinalStatus)) -ForegroundColor Magenta

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
      $LatestResult = Read-JsonFile (Join-Path $ForgeDirectory "result.json")
      $ResumeRunId = if ($null -ne $LatestResult -and $LatestResult.run_id) {
        Protect-Text $LatestResult.run_id
      }
      else {
        Protect-Text $Status.run_id
      }
      Write-Section "POKRAČOVANIE"
      Write-Host "Forge bezpečne uložil presnú ďalšiu úlohu. Nespúšťaj nový generický run."
      Write-Host "Resume príkaz:"
      Write-Host ("& 'C:\AI-Tools\GPT-Claude-Forge\Start-ForgeAutonomous.ps1' -ProjectPath '{0}' -ResumeRunId '{1}'" -f (Protect-Text $ResolvedProject), $ResumeRunId)
    }
    Write-Host ""
    Write-Host ("Monitor skončil: {0}" -f $(if ($FinalStatus) { $FinalStatus } else { $Phase })) -ForegroundColor Yellow
    break
  }

  Start-Sleep -Seconds $RefreshSeconds
}
