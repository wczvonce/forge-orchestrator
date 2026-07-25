# Audit GPT–Claude Forge

Dátum auditu: 25. júl 2026

## Lean orchestration L1–L8 — 25. júl 2026

Údržba prebehla priamo maintainerom v izolovanej vetve
`feat/lean-orchestration`; Forge nebol spustený autonómne nad vlastnou
inštaláciou. Nový tok nemení subscription autentifikáciu, read-only Codex
review, Claude safe mode, shared subscription-safe router, check-contract
hash, continuation počítadlá ani finálny release gate.

1. **L1 — perzistentné zadania:** `WorkPacket` obsahuje `packet_type`,
   `worker_prompt` a `completed_by`. Lean architektúra musí pripraviť úplný
   worker prompt pre každý packet; má jeden ohraničený opravný pokus a ďalší
   packet sa vyberá deterministicky bez bežného Codex continue callu.
   Pokrytie:
   [`tests/test_adaptive.py`](tests/test_adaptive.py) —
   `test_lean_architecture_requires_every_worker_prompt`,
   `test_dependency_ready_packet_uses_persistent_plan_order`; a
   [`tests/test_adaptive_runtime.py`](tests/test_adaptive_runtime.py) —
   `test_lean_fake_cli_chain_skips_routine_codex_reviews`.
2. **L2 — zelené checky uzatvárajú rutinný packet:** lean `code`/`docs`
   packet s tierom `smoke` alebo `targeted` sa po zelených checks uzavrie ako
   `completed_by: "forge_checks"`. Míľnik, druhé po sebe idúce zlyhanie,
   zmena plánu/kontraktu a finál naďalej vyžadujú review. Pokrytie:
   `test_green_lean_packet_is_closed_and_next_is_activated`,
   `test_lean_packet_keeps_both_consecutive_check_failures_for_review` a
   päť-packetový fake-CLI E2E.
3. **L3 — voliteľný read-only Claude reviewer:** nový
   `routine_reviewer` povoľuje `none`, `claude` alebo `codex`.
   `claude_reviewer` používa spoločný router a iba Read/Glob/Grep, nie
   Write/Edit/Bash. Neschválenie povoľuje jeden repair a potom Codex; Claude
   reviewer nemôže vydať projektový `done`. Pokrytie:
   `test_read_only_claude_reviewer_uses_shared_router_without_write_tools` a
   `test_claude_reviewer_rejection_allows_one_repair_then_codex`.
4. **L4 — dávkovaný review kontrakt:** review žiada všetky podložené výhrady
   naraz, zakazuje sprísňovať SPEC a odlišuje technický transportný pád.
   Výhrada k nezmenenému hashovanému súboru sa uloží ako `late_finding`,
   prenesie sa aj cez resume a nespotrebuje packet attempt. Pokrytie:
   `test_second_review_issue_on_unchanged_file_is_late_without_attempt` a
   `test_normal_content_attempt_increments_and_technical_refund_restores_it`.
5. **L5 — kozmetická normalizácia:** kombinácia
   `approve_check_contract_drift=false` s nadbytočným reason sa normalizuje,
   prijme a zaloguje ako warning. Skutočné schválenie bez dôvodu, oslabenie
   kritérií a ostatné bezpečnostné invarianty zostávajú hard failure.
   Legacy decision-recovery provenance ostáva spätne čitateľná. Pokrytie:
   [`tests/test_decision_recovery.py`](tests/test_decision_recovery.py) —
   `test_native_false_reason_is_the_only_normalized_field`,
   `test_normalizer_never_coerces_or_weakens_true_approval` a
   `test_normalization_cannot_mask_an_additional_validation_error`.
6. **L6 — walking skeleton a mock-first:** prvý lean plán musí mať 4 až 12
   packetov, všetky s promptom, spustiteľný code packet mimo `docs/` najneskôr
   na tretej pozícii a najviac dva docs/process packety medzi prvými piatimi.
   Externé integrácie neblokujú lokálnu kostru so syntetickými dátami.
   Pokrytie: `test_lean_plan_rejects_document_heavy_start` a
   `test_lean_plan_accepts_walking_skeleton_in_packet_two`.
7. **L7 — ľahká dokumentácia:** lean docs packet vynucuje `smoke`, nepoužíva
   test-evidence gate ani modelový review a povoľuje iba `docs/`, `README.md`
   a explicitné `expected_paths`. Pokrytie:
   `test_docs_scope_allows_docs_readme_and_explicit_paths_only` a fake-CLI E2E
   s kontrolou run-scoped `02-checks.json`.
8. **L8 — dokumentácia a audit:** README vysvetľuje lean/classic, cieľ
   približne piatich Codex volaní na bežný projekt bez neovereného percenta,
   tabuľku vlastníctva rozhodnutí a pravidlá plánu. Shipped konfigurácie
   používajú lean; legacy konfigurácia bez kľúča zostáva classic kvôli spätnej
   kompatibilite.

Model-free acceptance scenár má päť packetov vrátane jedného docs a jedného
milestone packetu a dosiahne `done` s tromi Codex calls a piatimi Claude worker
calls. Routine packety nevynechávajú lokálne checks; iba sa odstraňuje
redundantný modelový review. Toto číslo je deterministický testovací výsledok,
nie všeobecná garancia úspory pre každý projekt.

## Packet recovery, bootstrap integrity a presný Windows runtime — 24. júl 2026

Táto maintainer údržba zavádza mechanizmy proti falošnému vyčerpaniu packetu,
slepému resume a zeleným kontrolám nad nevidenými novými súbormi. Nasledujúce
body opisujú implementovaný kontrakt.

1. Predvolený Windows režim `EconomySafe` aj explicitný `Strict` používajú
   WSL2 strict runtime. Natívny Windows worker nie je tichým fallbackom, ak
   strict preflight zlyhá.
2. Wrapper pred doctorom a workerom porovná SHA-256 súborov `forge.py`,
   `forge_adaptive.py`, `forge_reports.py` a `forge.strict.config.json` medzi
   Windows zdrojom a WSL mirrorom. Okrem verzie `srt` vykoná model-free
   funkčný canary; chyba zastaví beh ešte pred modelovým volaním.
3. Neplatný technický worker výsledok, napríklad transportná chyba alebo
   chýbajúci finálny event, vráti logický `packet.attempts`. Skutočne
   dispatchnutý worker call a uplynutý chain čas zostanú započítané, takže
   refund neopravňuje neobmedzené alebo bezplatné opakovanie.
4. Po čerstvých zelených kontrolách môže Python supervisor autorizovať najviac
   jeden ohraničený final-review recovery pokus pre packet. Autorizácia a jej
   použitie sú perzistentné v ProjectPlane; Claude ani text review ich
   nemôžu vytvoriť, obnoviť alebo resetovať.
5. `packet_attempts_exhausted` je lokálny limit packetu, nie
   `chain_budget_exhausted`. Zakazuje automatický resume a wrapper pri ňom
   neponúka slepý manuálny resume. Iba skutočné vyčerpanie chain budgetu môže
   skončiť presným používateľským `-ResumeRunId`.
6. Výsledok a atomický status odvodzujú `needs_human` z terminálneho dôvodu.
   Live Monitor číta `stop_reason_code` a `automatic_resume_allowed`,
   terminálny stav nevydáva za hang a pri packet limite žiada opravu príčiny
   alebo plánu namiesto opakovania rovnakého runu.
7. Auto-discovered check kontrakt obsahuje interný
   `forge internal bootstrap-integrity`. NUL-safe Git index zahŕňa untracked,
   unstaged aj staged cesty; kontroluje hranice projektu, ignoruje symlink
   úniky a má limity veľkosti aj počtu súborov.
8. Bootstrap scanner kontroluje textové zmeny na konfliktové markery, trailing
   whitespace, private-key hlavičky a bežné provider/credential vzory.
   Potenciálne tajomstvo nikdy nevypíše: evidence obsahuje iba kategóriu,
   relatívnu cestu a číslo riadku. Binárne a neplatné UTF-8 súbory sa
   nespracujú ako text.
9. Povinné `git diff --check` a `git diff --cached --check` pokrývajú pracovný
   strom aj staged index. Nový, odstránený alebo zmenený auto-discovered runner
   vytvorí contract drift; Forge dočasne povolí iba bootstrap/diff kontroly,
   vyžiada read-only Codex consistency review a až potom môže kontrakt znovu
   uzamknúť.
10. Gradle a Android checky objavujú relevantné root build vstupy a agregujú
    všetky čerstvé reporty. Chýbajúci, nulový, poškodený, starý, zlyhaný alebo
    cestou unikajúci report nemôže splniť gate.
11. Check-contract drift sa už nedá potvrdiť obyčajným `continue`. Codex musí
    vrátiť osobitné `approve_check_contract_drift=true`, neprázdny dôvod a
    schválenie sa viaže na presný redigovaný sémantický rozdiel. Forge rozdiel
    znovu vypočíta tesne pred zápisom a odmietne oslabenie runnera, required
    checku, test evidence, reportu, tieru, ciest alebo cache politiky.
12. Nové runy ukladajú presný kanonický `config.snapshot.json` a zhodný SHA-256
    v `run.json`, `result.json` aj continuation payload. Automatický child
    resume odmietne legacy konfiguráciu alebo nezhodu; explicitný resume musí
    prejsť model-free eligibility a trusted supervisor bezpečnostným obalom.
13. Explicitný resume po `chain_budget_exhausted` pridá najviac jeden základný
    tranche na jedno používateľské pokračovanie. Kumulatívne worker/Codex/time/
    check/no-progress počítadlá sa neresetujú a prémiový strop sa nezvyšuje.
    Interný automatický resume budget rozšíriť nesmie.
14. `resume-eligibility` je bezmodelový a nemutujúci CLI gate. Wrapper akceptuje
    iba strojovo validované akcie `bounded_final_review_recovery`,
    `extend_chain_budget_one_tranche` alebo `validated_exact_resume`, overí
    nulový počet modelových volaní, nulovú mutáciu a použitie trusted configu.
15. Bootstrap kontrola číta aj staged Git blob priamo z indexu, bezpečne
    odmieta gitlinky a nebezpečné symlinky a pri náleze JSON hesla alebo iného
    credential vzoru vypíše iba kategóriu, cestu a riadok.
16. Celý zapisujúci run drží jeden fail-fast projektový lock na Windows aj
    WSL/POSIX. Druhý Forge proces nemôže súbežne meniť ProjectPlan. Resume po
    dlhšom Git baseline znovu overí project ID, goal, plan ID/hash a
    check-contract hash tesne pred prvým perzistentným zápisom; konkurenčnú
    zmenu neprepíše.
17. Wrapper validuje bezpečnostné voľby a eligibility verdict podľa skutočných
    JSON typov, nie cez PowerShell coercion. `ResumeLatest` sa po bezmodelovom
    overení nahradí presným `source_run_id`, takže neskorší nový run nemôže
    zmeniť cieľ resume.
18. Live Monitor dostáva generačný čas konkrétneho wrapper spustenia a ignoruje
    staré status/result/supervisor súbory. Terminálny `chain-supervisor.json` je
    autoritatívny aj pri chýbajúcom alebo poškodenom `status.json`; mŕtvy alebo
    chýbajúci supervisor so stale heartbeat skončí fail-closed.
19. Manuálny resume príkaz sa zobrazí až po terminálnom supervisor stave
    `needs_continuation` s exit kódom 4. Vyčerpaný prémiový strop, neplatné
    budget typy alebo neextendovateľná tranche príkaz nevytvoria.
20. Supervisor pri vlastnej výnimke vždy zapíše terminálny stav. Neplatný rescue
    výsledok nespúšťa projektové kontroly ani aplikačné no-progress/escalation
    účtovanie, ale fyzický call, čas a prípadné prémiové použitie zostanú
    započítané.

Finálne model-free overenie po týchto opravách: 278/278 unit, integračných,
wrapperových, monitorových, bezpečnostných a fake-CLI E2E testov prešlo.
Zelené boli aj `py_compile`, štyri JSON konfigurácie, parser oboch PowerShell
skriptov, CLI help, `git diff --check` a bootstrap-integrity scan nad samotným
Forge repozitárom. Windows a WSL runtime súbory sa zhodovali podľa SHA-256.
Reálny `EconomySafe -DoctorOnly -NoMonitor` prešiel vo WSL2 strict vrátane
projektového SRT/DrvFS canary; WSL projektový lock a model-free eligibility
pôvodného zastaveného runu boli overené bez mutácie a bez Codex/Claude
modelového volania.

## EconomySafe a Strict používajú auditovaný WSL2 runtime — 24. júl 2026

1. Predvolený `Start-ForgeAutonomous.ps1 -Mode EconomySafe` ani explicitný
   `-Mode Strict` už na Windows nevyberajú natívny Python bez plného Claude
   Bash sandboxu.
2. Wrapper používa WSL distribúciu `Ubuntu-24.04`, používateľa `forge` a
   izolovaný Forge runtime v `/home/forge/GPT-Claude-Forge`.
3. Pred doctorom overuje SHA-256 zhodu `forge.py`, `forge_adaptive.py`,
   `forge_reports.py` a strict konfigurácie medzi Windows zdrojom a WSL
   mirrorom, Python 3.11+ s `pydantic`, `srt --version` a funkčný model-free
   Sandbox Runtime canary.
4. Windows cestu projektu prekladá iba z validnej lokálnej cesty s písmenom
   disku a existenciu cieľa overí vo WSL. UNC a nejednoznačné cesty bezpečne
   odmietne.
5. Wrapper následne spustí jeden WSL `run-chain`; Live Monitor zostáva
   read-only Windows proces nad rovnakým `.forge` stavom.
6. Pri chybe preflightu neexistuje fallback na natívny Windows worker,
   nesandboxovaný `run`, API billing ani generický reštart.

## Check safety, Android reports a structured supervisor — 24. júl 2026

Údržba vyšla z čistého `main` commit SHA
`15342ee2be5c034e094b4291fbe7fc9f520a6c46`. Pred úpravou nebežal aktívny
Forge run a vznikla úplná externá záloha 1 390 súborov so SHA-256 manifestom.
Forge nebol spustený autonómne nad vlastnou inštaláciou.

1. Schema 4 pridáva strict `ResultTermination`. Aktuálny supervisor používa
   iba `stop_reason_code` a `automatic_resume_allowed`; ľudský text nemá vplyv
   na routing. Schema 1–3 zostáva čitateľná v oddelenej legacy vetve.
2. Android unit/instrumentation report directories bezpečne agregujú čerstvé
   JUnit XML zo všetkých modulov. Stale, empty, zero-test, malformed, failed a
   mimoprojektové/symlink reporty blokujú gate.
3. Check child environment nemá SSH agent ani askpass kanály, používa prázdny
   global Git config, zakázaný system config, non-interactive credentials a
   vypnuté hooks. Drift `.git/config`, `.git/hooks` a `.gitmodules` blokuje gate.
4. `unattended_requires_sandbox=true` je predvolené vo všetkých profiloch.
   `run-chain` bez úspešného `srt --version` skončí pred prvým workerom.
   Manuálny nesandboxovaný `run` ostáva možný iba s výrazným varovaním.
5. Forge-owned `CheckContract` má kanonický hash, strict definitions, source,
   stacky, timestamp, justification a indirect source hashes. npm scripts,
   lockfiles, runner configy a Gradle build vstupy sa nedajú zmeniť potichu.
   Hash sa prenáša v pláne aj continuation a pri resume sa overuje.
6. Codex môže navrhnúť iba štruktúrovaný runner template; ľubovoľný shell
   string nie je povoleným návrhom. Required check a test-execution požiadavka
   sa nesmú oslabiť.
7. Mocha adapter podporuje JSON aj textové passing/failing/pending. Nula testov
   a malformed evidence zostávajú neplatné.
8. GitHub Actions používajú immutable SHA pre checkout v5.0.1 a setup-python
   v6.2.0; Dependabot sleduje GitHub Actions. Workflow nemá modelové/API volania,
   tajomstvá, deploy ani publish.
9. Model-free canaries pokrývajú pytest, Vitest, Playwright a multi-module
   Android unit reporty. Instrumentation s emulátorom zostáva manuálne.
10. Lokálna sada po implementácii obsahuje 188 testov a prešla bez reálnych
    Codex/Claude requestov. GitHub CI a presný nasadený `main` SHA sa overujú
    až v release postupe; tento odsek ich vopred netvrdí.

## Runtime routing, fallback a verification hardening — 24. júl 2026

Údržba prebehla priamo maintainerom na izolovanej Git vetve; Forge nebol
spustený autonómne nad vlastnou inštaláciou.

1. Všetky produkčné Claude calls používajú jediný subscription-safe router.
   Legacy rescue vetva už nečíta hardcoded Opus model/effort pri spustení.
2. Runtime výsledky rozlišujú success, max turns, unavailable/not included,
   credits/API-required, auth failure, subscription limit, rate limit, timeout,
   refusal, sandbox denial a všeobecný CLI failure.
3. Iba model-availability dôvody povoľujú candidate fallback. Rovnaký Decision,
   packet, acceptance criteria, chain counters a unavailable-model evidence sa
   zachovajú aj cez resume.
4. Premium limit platí pre celý continuation chain. Rescue po jeho vyčerpaní
   môže použiť povolený Sonnet, ale nikdy ďalší premium model.
5. Economy zostáva `sonnet`/`low`, pretože aktuálny bezmodelový CLI preflight
   nepotvrdil lacnejší subscription-included alias. Konfigurácia nevymýšľa
   model ID.
6. Routing evidence pravdivo ukladá requested turn budget, skutočné použitie
   `--max-turns`, efektívny timeout, packet-attempt limit a chain worker limit.
7. Test report adaptery podporujú pytest/unittest text, JUnit XML,
   Jest/Vitest, Playwright, Gradle/Android JUnit, TRX a Flutter JSON. Odmietajú
   0 vykonaných testov pri test checku, malformed, stale a mimo-projektové
   reporty. Build/lint/type-check count nevyžadujú.
8. ProjectPlan vykonáva deterministickú DFS validáciu celého DAG, vrátane
   cyklov vytvorených cez `plan_patch`, a kontroluje existenciu ready packetu.
9. Pôvodných 84 testov zostalo zachovaných. Pribudlo 46 explicitných scenárov;
   celá 130-testová fake-CLI sada a multi-packet fallback E2E prešli bez
   reálneho modelového requestu.
10. Bezpečnostné hranice zostali nezmenené: ChatGPT/Claude.ai subscription
    auth, žiadne API keys/billing/credits, read-only Codex, Claude safe mode,
    redakcia a žiadny push/deploy/publish z Forge runtime.

## Adaptive Autonomous Orchestration — 23. júl 2026

Táto údržba bola vykonaná priamo maintainerom nad lokálnymi zdrojmi, nie autonómnym Forge cyklom nad vlastnou inštaláciou. Pred prvou zmenou nebežal aktívny Forge proces, vznikla timestampovaná záloha so SHA-256 manifestom a baseline prešiel: Python syntax, 36 pôvodných fake-CLI testov, JSON konfigurácie aj wrapper `DoctorOnly`.

Implementovaný kontrakt:

1. Schema 3 pridáva strict Pydantic `ProjectPlan`, `WorkPacket`, `PlanPatch`, adaptívne Codex rozhodnutie, `CheckDefinition`, `EvidenceIndex`, chain budgety a routovacie záznamy s `additionalProperties: false`.
2. Stabilná identita projektu a plán sú v `.forge/project.json` a `.forge/project-plan.json`. Každý child run ukladá nemenné počiatočné, priebežné a výsledné snapshoty plánu.
3. Prvý adaptívny architecture call musí vytvoriť 4–12 koherentných packetov. Dependency, completion bez zelených checks, oslabenie acceptance criteria, strata dokončeného packetu a neznámy plan patch sa deterministicky odmietnu.
4. Python router rozhoduje podľa packet difficulty/risk, citlivosti, failure signature, progress a budgetu. Codex odporúča iba logický profil; nemôže zadať ľubovoľný model.
5. Claude profily sú `economy`, `standard`, `complex`, `frontier` a `rescue`. Fable je iba kandidát vyžadujúci explicitné potvrdenie zahrnutia v predplatnom; bez potvrdenia sa preskočí. Žiadny fallback nezapína API billing ani usage credits.
6. Aktuálny Claude Code 2.1.205 nepovažuje `--max-turns` za potvrdenú verejnú voľbu, preto Forge tento parameter neposiela. Packet turn budget ostáva auditovanou politikou a CLI flag sa zapne iba po pozitívnom bezmodelovom capability preflighte.
7. Check tiers `smoke`, `targeted`, `milestone` a `release` nahradili plnú sadu po každom workerovi. Check IDs a príkazy sú allowlisted a validované; test count alebo požadovaný report musí byť skutočne prítomný.
8. `done` vyžaduje čerstvú release suite v aktuálnom rune, dokončené packety a najsilnejší finálny read-only Codex review.
9. Evidence index ukladá zmenené/pridané/odstránené súbory, riadkové počty, hashe diff hunkov, rizikové oblasti a stručné check dôkazy. Úspešný raw output sa neopakuje.
10. Bezpečný cache-key kontrakt zahŕňa príkaz, vstupné hashe, lockfiles, toolchain, environment, config, generated sources a externé zmeny. Cache zostáva v aktívnych profiloch vypnutá; release, E2E a security evidence sa necachujú.
11. `forge.py run-chain` je jeden ohraničený supervisor proces. Automaticky vykoná iba explicitný resume presného validated continuation payloadu; nikdy nevytvorí generický run zo starého goalu.
12. Hard chain budgety pokrývajú child runy, Codex calls, worker calls, elapsed time, full suites, premium použitia a no-progress udalosti. Počítadlá sa cez resume neresetujú.
13. Resume schema 3 overuje project ID, plan ID a plan hash. Skopírovaný `.forge`, nejednoznačný `latest`, poškodený payload a externá zmena plánu sa bezpečne odmietnu.
14. Forge sa odmietne spustiť nad `C:\AI-Tools\GPT-Claude-Forge` alebo jeho podpriečinkom.
15. Variant 3 monitora zobrazuje ProjectPlan progress, dokončené a aktívne packety, konkrétne zadanie Codexu, aktivitu Claude, worker profil s dôvodom, check tier, zostávajúci budget a prémiové použitia.
16. Lokálny heartbeat je daemon thread zapisujúci iba atomický status. Nevolá Codex ani Claude a umožňuje rozlíšiť aktívnu prácu, dlhý test, tichý subprocess a pravdepodobný hang.
17. Run a chain telemetry obsahujú iba bezpečné počty profilov, suites, packetov, fallbackov, elapsed time a whitelisted token counters, ak ich CLI poskytne. Raw prompty, reasoning, tajomstvá a celé environmenty sa neukladajú.
18. Reprodukovateľný benchmark v `benchmarks/benchmark_adaptive.py` porovnáva deterministické fake policy počty. Neuvádza percentuálnu tokenovú ani časovú úsporu bez merania.
19. Pôvodné bezpečnostné hranice zostali: ChatGPT/Claude.ai subscription auth, read-only Codex, Claude safe mode, strict MCP, scrubbed env, redakcia, immutable logs, žiadny push/deploy/publish/produkčné dáta/platby/API fallback.
20. Finálna sada 84 unit, integračných, monitorových a viac-child-run E2E testov prešla. `py_compile`, všetky štyri JSON konfigurácie, oba PowerShell skripty, CLI help, globálna integrácia a wrapper `DoctorOnly` boli overené bez reálneho modelového volania.

## Fáza 1 bezpečnej kontinuity — 23. júl 2026

Implementovaná a fake-CLI testami overená údržba opravila kontinuitu behov bez spustenia Forge nad vlastným adresárom:

1. Finálny reviewer s rozhodnutím `continue` po vyčerpaní iterácií vytvára `needs_continuation`, nie generické technické `failed`.
2. Stabilný exit-code model je `done=0`, `failed=1`, `blocked=2`, `subscription_limit=3`, `needs_continuation=4`.
3. `result.json` schema 2 obsahuje presný continuation payload: source/chain identitu, `next_prompt`, acceptance criteria, riziká, posledné kontroly, repository fingerprint a manifest aj kumulatívne počítadlá.
4. `forge.py resume --project <path> --run-id <id|latest>` a wrapper parametre `-ResumeRunId`/`-ResumeLatest` vytvoria nový nemenný run s `parent_run_id`; zdrojové runy a logy nemenia.
5. Nezmenený fingerprint preskočí všeobecný architecture audit a použije presný zdedený prompt. Externá zmena fingerprintu vynúti krátky read-only Codex consistency review.
6. Resume prenáša čas, worker calls, full check suites, failed iterations, no-progress stav a počet prémiových eskalácií celého continuation chainu.
7. `error_max_turns` s merateľným pokrokom a zelenými kontrolami už sám neaktivuje Opus. Prémiová eskalácia je povolená iba bez pokroku, pri opakovanom rovnakom zlyhaní alebo pri neúspešných povinných kontrolách a najviac raz za celý chain.
8. Vtedajší wrapper spúšťal presne jeden Forge proces a po `needs_continuation` vypísal explicitný resume príkaz. Následná Adaptive Autonomous Orchestration toto správanie nahradila jedným ohraničeným `run-chain` supervisorom, ktorý pokračuje iba presným interným resume.
9. `MASTER_PROMPT_CODEX_DESKTOP.txt`, Live Monitor, globálna skill a globálny `AGENTS.md` dnes rešpektujú ohraničený `run-chain`; manuálny resume oznamujú až pri konečnom vyčerpaní chain budgetu.
10. Staré result súbory zostávajú čitateľné ako schema 1. Starý alebo neúplný run bez continuation údajov sa bezpečne odmietne a nevytvorí sa vymyslený prompt.
11. Kompletná sada 35 unit/integration testov s fake Codex a Claude CLI prešla bez reálneho modelového volania.

Toto obmedzenie platilo pre Fázu 1. Následná Adaptive Autonomous Orchestration pridala heartbeat, release gate a bezpečný cache-key kontrakt; samotné používanie cache zostáva zámerne vypnuté.

## Predvolený Live Monitor – Varianta 3

Na výslovnú voľbu používateľa je `Watch-Forge.ps1` nastavený na laický kontrolný zoznam projektu:

1. Zobrazuje názov projektu, percento, packet checklist, konkrétny aktívny packet a polia `Codex zadal`, `Claude práve`, worker profil s dôvodom, check tier, zostávajúci budget, `Aktuálny krok`, `Posledný výsledok`, `Nasleduje` a `Váš zásah`.
2. Primárnym zdrojom postupu je perzistentný ProjectPlan. Pri staršom projekte bez plánu používa Markdown checkboxy v `SPEC.md`; bez nich zobrazí označený odhad Forge cyklu.
3. Technické príkazy, Git stav, diff a live udalosti sú predvolene skryté. Sú dostupné iba explicitným `-ShowTechnicalDetails` alebo `-ShowFullCommands`.
4. Zobrazený text naďalej prechádza redakciou a monitor nikdy nezobrazuje hidden reasoning ani thinking bloky.
5. Monitor zostáva lokálny a bezmodelový; nevolá Codex ani Claude a nemení worker proces.
6. Fake-CLI testy overujú predvolenú Variant 3, požadované laické polia, skrytie technických detailov, redakciu a terminálny prechod medzi iteráciami.

## Aktualizácia po forenznom audite spotreby

Forge bol následne zosúladený s vlastnými streaming/status testami a prepracovaný na úspornú hybridnú politiku:

1. Úvodná architektúra a finálny review používajú `gpt-5.6-sol`; bežný repair review používa `gpt-5.6-terra`.
2. Reasoning je explicitne fázový: architektúra/final `xhigh`, bežný review `medium`, dôležitý rizikový review `high`.
3. Claude štandardne používa alias `sonnet` s effort `medium`; pri preukázanom zlyhaní môže Forge podľa celého chain budgetu použiť povolený `complex`, `frontier` alebo `rescue` profil. Aktuálny Claude Code 2.1.205 neinzeruje `--max-turns`, preto Forge tento CLI parameter neposiela a nevymýšľa ho.
4. Predvolený počet štandardných iterácií klesol z 10 na 2. Režim `EconomyMax` používa jednu iteráciu a jeden finálny review.
5. Dôkazy pre Codex sú po prvom review inkrementálne podľa lokálneho content manifestu. Diff je obmedzený na 18 000 znakov, untracked preview na 8 000 znakov, 12 súborov a 1 500 znakov na súbor.
6. Úspešný check poskytuje modelu najviac 300 znakov, neúspešný 4 000 a celý check blok 8 000. Worker summary je najviac 3 000 znakov.
7. Preflight kontroluje podporované CLI voľby bez modelového volania a zastaví beh ešte pred drahým review, ak je runner nekompatibilný.
8. Každý beh má nemenné logy v `.forge/runs/<run_id>/`; starší dôkaz sa už neprepisuje.
9. Codex `--json` výstup sa neukladá celý. Forge z neho uloží iba whitelisted model/usage počty a typy udalostí, nie reasoning ani tool payloady.
10. Live Monitor zostáva lokálny a bezmodelový. Globálna skill a AGENTS pokyny zakazujú modelové polling správy počas behu.
11. Claude používa `--safe-mode` namiesto `--bare`, aby sa zachovalo Claude.ai OAuth/keychain prihlásenie bez načítania používateľských customizations.
12. Python test suite pokrýva streaming, redakciu, status, monitor, stdin transport, fázové modely, inkrementálny kontext, context caps, run-scoped logy a ohraničenú eskaláciu.

Tieto zmeny znižujú opakované modelové volania a opakované posielanie rovnakého kontextu. Nejde o garantovanú percentuálnu úsporu: reálna spotreba závisí od rozsahu projektu, počtu zlyhaní a toho, či sa aktivuje prémiová eskalácia.

## Verdikt

Základný koncept je technicky správny a riadiaci cyklus funguje: Codex/GPT plánuje a kontroluje, Claude Code implementuje, Forge zbiera Git diff a výsledky kontrol a proces opakuje. Auditovaná verzia prešla syntaktickou kontrolou a simulovaným end-to-end testom s falošnými CLI klientmi.

Nie je však pravdivé tvrdiť, že ľubovoľnú aplikáciu vyrobí „dokonale“ a úplne bez človeka. Reálne externé prihlásenia, CAPTCHA, produktové rozhodnutia, produkčné tajomstvá, právne rozhodnutia, obchodné platby a finálne produkčné nasadenie musia zostať pod ľudskou kontrolou. Pri veľkých projektoch môže proces zastaviť aj limit mesačného predplatného.

## Opravy vykonané po audite

1. Codex reviewer používa read-only sandbox, štruktúrovaný JSON výstup a ignoruje používateľský config aj projektové `.rules`.
2. Claude Code beží v `--safe-mode`, so strict MCP konfiguráciou, bez session persistence a s obmedzenou sadou nástrojov. Safe mode zachováva Claude.ai prihlásenie, ale vypína používateľské customizations.
3. Forge overuje subscription login oboch nástrojov a odmieta zjavný API režim.
4. Z prostredia Codexu, Claude aj testov sa odstraňujú premenné pripomínajúce API kľúče, tokeny, heslá a cloudové credentials.
5. Testy používajú izolovaný HOME a TEMP. Ak je dostupný Anthropic Sandbox Runtime (`srt`), testy bežia aj v OS sandboxe.
6. Claude dostáva generované deny pravidlá pre push, publish, deploy, kubectl, terraform a cloudové CLI.
7. Po poslednej implementačnej iterácii sa vykoná ešte jeden záverečný Codex review; posledná zmena už nezostane bez kontroly.
8. Detekcia kontrol podporuje npm, pnpm, yarn a bun a hľadá lint, typecheck, test, E2E aj build skripty.
9. Pri UI Codex vyžaduje aspoň jeden automatizovaný hlavný E2E scenár, error state a empty state, ak je to technicky možné.
10. Claude worker používa jeden priebežný `Popen` proces so `stream-json`; stdout a stderr sa čítajú súbežne bez druhého Claude spustenia.
11. Stream parser zachová finálny result event, vytvára kompatibilný `WorkerResult` a pri chýbajúcom finálnom evente vráti neúspešný výsledok.
12. JSONL, ľudské logy, stav aj uložené Forge JSON výstupy prechádzajú redakciou zjavných tajomstiev. Thinking/reasoning bloky sa pred uložením vynechávajú.
13. `status.json` sa aktualizuje atomicky iba pri významných udalostiach a umožňuje read-only monitorovanie bez zásahu do worker procesu.
14. `Watch-Forge.ps1` číta iba projektové Forge logy a Git metadata, opakovane rediguje zobrazovaný text a podporuje cesty s medzerami.
15. Wrapper otvorí najviac jedno monitorovacie okno na beh; zlyhanie monitora nezastaví Forge a vypíše manuálny príkaz.

## Audit živého streamovania

Overovaná implementácia používa podporované Claude Code parametre `--output-format stream-json`, `--verbose` a `--include-partial-messages` spolu s `--safe-mode`, `--strict-mcp-config`, obmedzenými tools, auditovanými settings, permission mode, modelom, effort profilom a vypnutou session persistence. `--max-turns` sa po update Claude CLI 2.1.205 neposiela, pretože ho aktuálny `--help` nepotvrdzuje.

Viditeľné udalosti obsahujú iba assistant text, tool calls, redigované vstupy, názvy súborov, príkazy, skrátené výsledky a stav procesu. Neznáme udalosti sa po redakcii ukladajú do JSONL. Súkromné thinking/reasoning bloky sa neukladajú ani nezobrazujú.

Automatické testy používajú simulovaný Claude CLI a pokrývajú text, tool-use, tool-result, neznáme a neplatné udalosti, redakciu, atomický status, prompt log, finálny WorkerResult, timeout, non-zero exit, subscription limit a prechod monitora medzi iteráciami.

## Zvyšné obmedzenia

### Kvalita

- Dva modely znižujú počet chýb, ale negarantujú bezchybný produkt.
- Vizuálna kvalita závisí od existencie browser/E2E testov a od presnej špecifikácie.
- Automatické testy dokazujú iba to, čo pokrývajú.
- Codex aj Claude môžu opakovane voliť nesprávny smer; limit iterácií zabráni nekonečnej slučke, ale nemusí doručiť hotový výsledok.

### Bezpečnosť

- Natívny Windows nemá vstavaný Claude Bash sandbox. Najbezpečnejší bezobslužný režim je WSL2/Linux plus `forge.strict.config.json`.
- Anthropic Sandbox Runtime je doplnková vrstva a stále je označený ako research preview.
- Nové alebo kompromitované závislosti sú riziko aj v sandboxe.
- Projekt nemá dostať produkčné `.env`, SSH kľúče, cloudové admin credentials ani reálnu databázu.
- Redakcia je ochranná vrstva pre zjavné vzory, nie matematická záruka zachytenia ľubovoľne zakódovaného tajomstva. Do projektu preto naďalej nevkladaj produkčné tajomstvá.
- `--safe-mode` zámerne zachováva Claude.ai OAuth/keychain prihlásenie. Ak budúca verzia CLI zmení podporované voľby, bezmodelový runtime preflight beh zastaví ešte pred prvým review a nesmie sa prepnúť na API.

### Cena a limity

- Forge nepoužíva OpenAI ani Anthropic API kľúče.
- Ak má účet kúpené Codex kredity alebo zapnutý Auto top-up, po spotrebovaní zahrnutého limitu môžu byť použité platené kredity na úrovni účtu. Forge ich nevie zrušiť; musíš ich vypnúť v účte.
- To isté platí pre Claude usage credits. Forge sa snaží rozpoznať limitové hlásenia a zastaviť sa, ale nastavenie účtu je nadradené.

## Odporúčaný režim

- Rýchly a jednoduchý: Windows, `START_NEW_APP.ps1`, balanced config, iba nové vlastné projekty bez tajomstiev.
- Bezobslužný a bezpečnejší: WSL2, Claude sandbox, Sandbox Runtime pre testy, `forge.strict.config.json`.
- Produkcia: po autonómnom builde vždy manuálny audit, bezpečnostná kontrola a vedomé nasadenie.
