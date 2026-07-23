param(
  [string]$ProjectName,
  [string]$Goal,
  [string]$ProjectsRoot = "C:\AI-Projects",
  [ValidateSet("EconomySafe", "EconomyMax", "Android")]
  [string]$Mode = "EconomySafe",
  [switch]$Strict
)

$ErrorActionPreference = "Stop"
Set-Location $PSScriptRoot

if ([string]::IsNullOrWhiteSpace($ProjectName)) {
  $ProjectName = Read-Host "Krátky názov projektu, napr. rezervacie"
}
if ([string]::IsNullOrWhiteSpace($Goal)) {
  $Goal = Read-Host "Jednou alebo viacerými vetami opíš aplikáciu, ktorú chceš vytvoriť"
}
if ([string]::IsNullOrWhiteSpace($ProjectName) -or [string]::IsNullOrWhiteSpace($Goal)) {
  throw "Názov projektu aj zadanie sú povinné."
}

$SafeName = ($ProjectName -replace '[^a-zA-Z0-9._-]', '-')
$Project = Join-Path $ProjectsRoot $SafeName
New-Item -ItemType Directory -Force -Path $Project | Out-Null

$Spec = @"
# Product specification

## Hlavný cieľ
$Goal

## Povinné pravidlá kvality
- Najprv preskúmaj projekt a zvoľ primeraný stabilný technologický stack.
- Vytvor funkčnú lokálnu aplikáciu, nie iba maketu.
- Pridaj lint, type-check, automatické testy a production build.
- Pri UI pridaj aspoň jeden end-to-end test hlavného scenára, empty state a error state.
- Vytvor README s presným spustením.
- Nepushuj na GitHub, nenasadzuj do produkcie a nepoužívaj reálne tajomstvá ani produkčné dáta.
- Pokračuj, kým Codex výsledok neschváli alebo kým sa nedosiahne bezpečnostný/usage limit.
"@
Set-Content -Path (Join-Path $Project "SPEC.md") -Value $Spec -Encoding UTF8

$SelectedMode = if ($Strict) { "Strict" } else { $Mode }
$Wrapper = Join-Path $PSScriptRoot "Start-ForgeAutonomous.ps1"

Write-Host ""
Write-Host "Projekt: $Project"
Write-Host "Režim: $SelectedMode"
Write-Host ""
& $Wrapper -ProjectPath $Project -SpecPath (Join-Path $Project "SPEC.md") -Mode $SelectedMode
exit $LASTEXITCODE
