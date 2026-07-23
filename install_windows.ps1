param(
  [switch]$InstallSandboxRuntime
)

$ErrorActionPreference = "Stop"
Set-Location $PSScriptRoot

function Need-Command([string]$Name, [string]$Message) {
  if (-not (Get-Command $Name -ErrorAction SilentlyContinue)) { throw $Message }
}

function Find-Python311 {
  $Candidates = @()
  $Python = Get-Command python.exe -ErrorAction SilentlyContinue | Select-Object -First 1
  if ($null -ne $Python) { $Candidates += [pscustomobject]@{ File=$Python.Source; Args=@() } }
  $Py = Get-Command py.exe -ErrorAction SilentlyContinue | Select-Object -First 1
  if ($null -ne $Py) { $Candidates += [pscustomobject]@{ File=$Py.Source; Args=@("-3.12") } }
  $Bundled = Join-Path $env:USERPROFILE ".cache\codex-runtimes\codex-primary-runtime\dependencies\python\python.exe"
  $Candidates += [pscustomobject]@{ File=$Bundled; Args=@() }
  foreach ($Candidate in $Candidates) {
    if (-not (Test-Path -LiteralPath $Candidate.File -PathType Leaf)) { continue }
    try {
      $CandidateArgs = @($Candidate.Args)
      & $Candidate.File @CandidateArgs -c "import sys; raise SystemExit(0 if sys.version_info >= (3,11) else 1)" *> $null
      if ($LASTEXITCODE -eq 0) { return $Candidate }
    }
    catch { continue }
  }
  throw "Nenašiel sa Python 3.11+. Nainštaluj Python alebo spusti Forge z Codex desktop prostredia s bundled runtime."
}

function Add-InstalledClaudeToPath {
  if (Get-Command claude.exe -ErrorAction SilentlyContinue) { return }
  $PackagesRoot = Join-Path $env:LOCALAPPDATA "Packages"
  if (-not (Test-Path -LiteralPath $PackagesRoot -PathType Container)) { return }
  $Candidate = Get-ChildItem -LiteralPath $PackagesRoot -Directory -Filter "Claude_*" -ErrorAction SilentlyContinue |
    ForEach-Object {
      $Root = Join-Path $_.FullName "LocalCache\Roaming\Claude\claude-code"
      if (Test-Path -LiteralPath $Root -PathType Container) {
        Get-ChildItem -LiteralPath $Root -Recurse -Filter "claude.exe" -File -ErrorAction SilentlyContinue
      }
    } |
    Sort-Object LastWriteTime -Descending |
    Select-Object -First 1
  if ($null -ne $Candidate) {
    $env:Path = (Split-Path -Parent $Candidate.FullName) + [IO.Path]::PathSeparator + $env:Path
  }
}

function Add-InstalledCodexToPath {
  if (Get-Command codex.exe -ErrorAction SilentlyContinue) { return }
  $Root = Join-Path $env:LOCALAPPDATA "OpenAI\Codex\bin"
  if (-not (Test-Path -LiteralPath $Root -PathType Container)) { return }
  $Candidate = Get-ChildItem -LiteralPath $Root -Recurse -Filter "codex.exe" -File -ErrorAction SilentlyContinue |
    Sort-Object LastWriteTime -Descending |
    Select-Object -First 1
  if ($null -ne $Candidate) {
    $env:Path = (Split-Path -Parent $Candidate.FullName) + [IO.Path]::PathSeparator + $env:Path
  }
}

Need-Command "git" "Git nebol nájdený. Nainštaluj Git for Windows."
$Python = Find-Python311
Add-InstalledClaudeToPath
Add-InstalledCodexToPath
Need-Command "claude" "Claude Code nebol nájdený. Nainštaluj alebo aktualizuj Claude desktop/Claude Code."

if (-not (Get-Command codex -ErrorAction SilentlyContinue)) {
  Write-Host "Inštalujem oficiálny Codex CLI..."
  powershell -ExecutionPolicy ByPass -c "irm https://chatgpt.com/codex/install.ps1 | iex"
  Add-InstalledCodexToPath
}
Need-Command "codex" "Codex CLI nebol nájdený ani po inštalácii."

if ($InstallSandboxRuntime) {
  Need-Command "npm" "Na inštaláciu Sandbox Runtime je potrebný Node.js/npm."
  Write-Host "Inštalujem Anthropic Sandbox Runtime..."
  npm install -g @anthropic-ai/sandbox-runtime
}

$PythonArgs = @($Python.Args)
& $Python.File @PythonArgs -m venv .venv --clear
& .\.venv\Scripts\python.exe -m pip install --upgrade pip
& .\.venv\Scripts\python.exe -m pip install -r requirements.txt

Write-Host ""
Write-Host "Kontrolujem prihlásenie a prostredie..."
& .\.venv\Scripts\python.exe forge.py doctor
if ($LASTEXITCODE -ne 0) {
  Write-Host ""
  Write-Host "Ak zlyhal Codex login, spusti: codex login"
  Write-Host "Ak zlyhal Claude login, spusti: claude auth login"
  Write-Host "Potom znova spusti tento skript alebo forge.py doctor."
  exit $LASTEXITCODE
}

Write-Host ""
Write-Host "Forge je pripravený. Predvolený úsporný režim:"
Write-Host ".\START_NEW_APP.ps1 -Mode EconomySafe"
