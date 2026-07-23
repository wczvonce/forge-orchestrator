# GPT–Claude Forge — úsporný hybridný režim

Forge používa existujúce ChatGPT a Claude.ai predplatné, nie API kľúče:

- **Codex** je architekt a nezávislý reviewer.
- **Claude Code** je implementačný pracovník.
- **Forge** je lokálna Python slučka, ktorá vyberá správny model podľa fázy, zbiera iba potrebné dôkazy, spúšťa kontroly a bezpečne zastavuje proces.
- **Live Monitor** je obyčajný lokálny PowerShell. Jeho obnovovanie nespotrebúva modelové tokeny.

## Predvolená modelová politika

Režim `EconomySafe` je predvolený:

| Fáza | Model / úsilie | Úloha |
|---|---|---|
| Úvodná architektúra | `gpt-5.6-sol` / `xhigh` | najdôležitejší plán a acceptance criteria |
| Bežná opravná kontrola | `gpt-5.6-terra` / `medium` | úsporná kontrola zlyhaní a inkrementálnych zmien |
| Dôležitá bezpečnostná/migračná úloha | `gpt-5.6-sol` / `high` | silnejší review pri rizikovom cieli |
| Dokončovací a finálny review | `gpt-5.6-sol` / `xhigh` | nezávislé schválenie výsledku |
| Economy worker | Claude `sonnet` / `low` | mechanické, explicitné a low-risk packety |
| Standard worker | Claude `sonnet` / `medium` | bežná funkcionalita a každodenné opravy |
| Complex worker | Claude `sonnet` / `high` | viacvrstvové, citlivé alebo high-risk zmeny |
| Frontier/rescue | allowlist `fable`/`opus`/`sonnet` fallback | iba pri odôvodnenej náročnosti alebo merateľnom zaseknutí |

Prémiový Claude sa spustí najviac raz za celý continuation chain, iba pri merateľnom zaseknutí: bez pokroku, pri opakovanom rovnakom zlyhaní alebo pri neúspešných povinných kontrolách. Samotný `error_max_turns` neaktivuje Opus, ak worker zmenil repozitár a povinné kontroly prešli. Počas subscription limitu sa Forge zastaví; neprepne sa na API ani platené kredity.

Aktuálne lokálne Claude Code 2.1.205 v `--help` neuvádza `--max-turns`. Forge preto nevymýšľa nepodporovaný parameter: turn budget eviduje ako packet/chain politiku a CLI flag odošle iba vtedy, keď ho bezmodelový capability preflight v konkrétnej verzii naozaj potvrdí. Model a effort parametre sa používajú iba po rovnakom overení.

## Úsporné režimy

### EconomySafe — odporúčané

- najviac dve štandardné implementačné iterácie,
- úvodný architekt, úsporný repair review a silný final review,
- najviac jedna cielená Claude eskalácia,
- vhodné ako bežný predvolený režim.

```powershell
& 'C:\AI-Tools\GPT-Claude-Forge\Start-ForgeAutonomous.ps1' `
  -ProjectPath 'C:\AI-Projects\moja-apka' `
  -SpecPath 'C:\AI-Projects\moja-apka\SPEC.md' `
  -Mode EconomySafe
```

### EconomyMax — maximálna úspora

- jedna veľká štandardná implementácia,
- potom silný finálny Codex review,
- záchranný Claude Opus sa použije iba pri neúspechu,
- nižšia spotreba pri hladkom priebehu, ale chyba sa môže odhaliť neskôr.

```powershell
& 'C:\AI-Tools\GPT-Claude-Forge\Start-ForgeAutonomous.ps1' `
  -ProjectPath 'C:\AI-Projects\moja-apka' `
  -SpecPath 'C:\AI-Projects\moja-apka\SPEC.md' `
  -Mode EconomyMax
```

Ďalšie režimy wrappera sú `Android` (povinné Gradle kontroly) a `Strict` (vyžaduje Sandbox Runtime).

## Ako adaptívny cyklus funguje

1. Forge inicializuje samostatný Git repozitár, stabilnú identitu projektu, content-addressed baseline a nemenný priečinok behu.
2. Preflight bez modelového volania overí, že Codex a Claude CLI podporujú potrebné stdin, streaming, JSON, model a effort voľby.
3. Architecture Codex vytvorí 4–12 koherentných, dependency-ordered pracovných balíkov v `.forge/project-plan.json`.
4. Python router vyberie logický Codex a Claude profil podľa aktívneho packetu, rizika, náročnosti, histórie zlyhaní a zostávajúceho chain budgetu.
5. Claude vykoná iba aktívny packet. Model ID nevyberá Codex; Python Forge ho preloží cez auditovaný allowlist a subscription-safe fallback.
6. Lokálny počítač spustí primeraný tier `smoke`, `targeted`, `milestone` alebo `release`. Model smie vyberať iba validované check IDs.
7. Codex dostane štruktúrovaný evidence index, zmenené súbory, hashe hunkov, rizikové oblasti, skrátené úspešné výsledky a podrobné chyby — nie celý opakovaný stream.
8. Dokončený packet sa uloží do plánu a už sa neopakuje. Python supervisor automaticky pokračuje iba presným continuation payloadom.
9. `done` je možné iba po čerstvej release suite s test counts/report validation a po silnom finálnom read-only Codex review.

Pôvodný cieľ zostáva v `.forge/run.json` a v run-scoped `goal.txt`. Pri ďalších Codex review aj Claude opravných cykloch sa opakuje iba kompaktná pripomienka. Worker summary má najviac 3 000 znakov; plný redigovaný worker stream ostáva iba v lokálnom run logu.

## Automatický chain supervisor a manuálny resume

Wrapper štandardne spúšťa jeden proces `forge.py run-chain`. Ak child run skončí `needs_continuation`, Python supervisor overí identitu projektu a plánu, presný `next_prompt`, fingerprint a hard budgety a vytvorí nový nemenný child run explicitným interným resume. Pôvodný všeobecný goal sa nikdy nepoužije ako generický reštart. Supervisor končí pri `done`, `blocked`, `subscription_limit`, `failed` alebo pri konečnom `needs_continuation` po vyčerpaní chain budgetu.

Manuálny resume zostáva dostupný:

```powershell
& 'C:\AI-Tools\GPT-Claude-Forge\Start-ForgeAutonomous.ps1' `
  -ProjectPath 'C:\AI-Projects\moja-apka' `
  -ResumeRunId '20260723-083000-123456'
```

Priamy CLI tvar:

```powershell
.\.venv\Scripts\python.exe .\forge.py run-chain `
  --project 'C:\AI-Projects\moja-apka' `
  --goal 'Dokonči aplikáciu podľa SPEC.md' `
  --config .\forge.config.json

.\.venv\Scripts\python.exe .\forge.py resume `
  --project 'C:\AI-Projects\moja-apka' `
  --run-id latest
```

Hard budget zahŕňa child runy, Codex calls, worker calls, elapsed time, full check suites, prémiové použitia a no-progress udalosti. Počítadlá sa resume procesom neresetujú.

Najnovší resumovateľný run možno vybrať aj pomocou `-ResumeLatest`. Pri priamom CLI je syntax:

```powershell
.\.venv\Scripts\python.exe .\forge.py resume `
  --project 'C:\AI-Projects\moja-apka' `
  --run-id latest
```

Resume zachová pôvodné logy, nastaví `parent_run_id` a `continuation_chain_id` a prenesie časové, worker, check aj prémiové počítadlá. Ak sa fingerprint nezmenil, pokračuje presným uloženým `next_prompt` bez nového všeobecného architecture auditu. Ak sa repozitár zmenil mimo Forge, najprv prebehne krátky read-only Codex consistency review pôvodného promptu, externých zmien a posledných kontrol.

Vonkajší Codex ani wrapper po stave `needs_continuation` nespúšťajú nový generický run. Jediný Python supervisor proces môže vykonať ďalší child run iba explicitným validovaným resume presného source runu. Keď sa vyčerpá chain budget, wrapper oznámi manuálny resume príkaz.

Stavový a exit-code model:

| Stav | Exit code | Význam |
|---|---:|---|
| `done` | 0 | reviewer schválil výsledok a povinné kontroly prešli |
| `failed` | 1 | technické zlyhanie Forge alebo runnera |
| `blocked` | 2 | bezpečné produktové, technické alebo bezpečnostné zablokovanie |
| `subscription_limit` | 3 | vyčerpaný subscription limit bez API fallbacku |
| `needs_continuation` | 4 | bezpečný continuation bod; supervisor pokračuje presným resume alebo sa po vyčerpaní budgetu zastaví |

Nové súbory obsahujú `schema_version: 3`. Staré `result.json` schema 1 a schema 2 zostávajú čitateľné. Starý alebo neúplný run bez bezpečného continuation payloadu sa odmietne s jasnou chybou; Forge nikdy nevymyslí náhradný prompt.

## Nemenné logy a Live Monitor

Každý beh má vlastnú cestu:

```text
projekt\.forge\runs\YYYYMMDD-HHMMSS-microseconds\
  run.json
  goal.txt
  preflight.json
  git-baseline.json
  project-plan.initial.json
  project-plan.result.json
  telemetry.json
  escalations.json          (iba ak nastala eskalácia)
  result.json
  logs\
```

`.forge\run.json`, `.forge\result.json` a `.forge\status.json` ukazujú posledný beh, ale staršie run-scoped logy sa už neprepisujú.

Wrapper automaticky otvorí Live Monitor. Predvolené zobrazenie je laická **Varianta 3 – Kontrolný zoznam projektu**:

- názov projektu a percento postupu,
- krátky kontrolný zoznam,
- počet a názvy dokončených packetov,
- aktívny packet a míľnik,
- `Codex zadal`,
- `Claude práve`,
- worker profil a stručný dôvod,
- check tier a zostávajúci chain budget,
- `Aktuálny krok`,
- `Posledný výsledok`,
- `Nasleduje`,
- `Váš zásah`.

Ak existuje ProjectPlan, percento sa počíta z dokončených packetov. Staršie projekty môžu použiť Markdown checkboxy v `SPEC.md`; až potom monitor použije odhad fázy. Lokálny heartbeat odlišuje aktívnu prácu, dlhý test, tichý subprocess a pravdepodobný hang bez modelového pollingu. Technické príkazy, Git diff a surový live denník sa v predvolenom zobrazení nezobrazujú.

Manuálny príkaz:

```powershell
& 'C:\AI-Tools\GPT-Claude-Forge\Watch-Forge.ps1' -Project 'C:\AI-Projects\moja-apka'
```

Voliteľná diagnostika:

```powershell
& 'C:\AI-Tools\GPT-Claude-Forge\Watch-Forge.ps1' `
  -Project 'C:\AI-Projects\moja-apka' `
  -ShowTechnicalDetails
```

Monitor číta `status.json`, `SPEC.md`, run-scoped logy a voliteľne lokálne Git metadata. Nevolá Codex ani Claude. Vonkajší Codex chat nemá stav kontrolovať opakovanými modelovými správami; po spustení má čakať na ukončenie jedného wrapper procesu a priebeh nechávať monitoru.

Každá worker iterácia vytvára redigované súbory `NN-claude-prompt.txt`, `NN-claude-stream.jsonl`, `NN-claude-live.log`, `NN-worker.json` a `NN-checks.json`. Eskalácia používa označenie napríklad `02E1-*`. Codex usage log obsahuje iba whitelisted model/usage počty a typy udalostí; raw Codex JSONL ani reasoning sa neukladá.

## Bezpečnostné pravidlá

- Codex musí byť prihlásený cez ChatGPT, Claude cez Claude.ai subscription.
- Forge odstraňuje z child prostredia API kľúče, tokeny, heslá a cloud credentials.
- Claude používa `--safe-mode`, strict MCP, obmedzené tools, redigované settings a vypnutú session persistence.
- Codex pracuje v read-only sandboxe a ignoruje používateľský config aj projektové rules.
- Zakázané zostávajú push, publish, deploy, produkčné migrácie, cloud CLI, platené nákupy a práca s produkčnými tajomstvami.
- Natívny Windows nemá plný Claude Bash sandbox. Pre najvyššiu izoláciu použi WSL2/Linux a režim `Strict`.

## Inštalácia a doctor

```powershell
Set-ExecutionPolicy -Scope Process RemoteSigned
.\install_windows.ps1
.\Start-ForgeAutonomous.ps1 `
  -ProjectPath 'C:\AI-Projects\bezpecny-test' `
  -Goal 'Doctor-only test' `
  -DoctorOnly
```

Nový projekt možno vytvoriť aj cez:

```powershell
.\START_NEW_APP.ps1 -ProjectName 'rezervacie' -Goal 'Vytvor lokálnu aplikáciu na správu rezervácií.' -Mode EconomySafe
```

## Overenie runnera bez reálneho AI projektu

```powershell
python -m py_compile .\forge.py
python -m unittest discover -s .\tests -v
```

Testy používajú falošné Codex a Claude CLI procesy. Sada pokrýva pôvodných 36 regresných scenárov aj adaptívne schémy, ProjectPlan, dependency packety, modelový router, check tiers, test count/report gate, evidence index, project identity, heartbeat, hard chain budgety a kompletný viac-child-run E2E až po čerstvú release suite a `done` — bez reálneho modelového volania.

## Limity

Forge znižuje opakovanie a počet review volaní, ale negarantuje pevnú spotrebu. Dokončený veľký projekt môže spotrebovať viac než nedokončený malý projekt. Najsilnejšie modely sa používajú selektívne a subscription účty musia mať vypnuté Auto top-up/extra usage, ak používateľ nechce dodatočné kredity.

Bezpečný check-cache kontrakt je implementovaný, ale cache zostáva v auditovaných profiloch vypnutá (`check_cache_enabled=false`), kým konkrétny stack neposkytne úplný input/toolchain/report fingerprint. Lokálny heartbeat a release gate sú aktívne a nevolajú modely.

Podrobný bezpečnostný verdikt a históriu zmien obsahuje `AUDIT.md`.
