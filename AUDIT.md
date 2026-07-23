# Audit GPT–Claude Forge

Dátum auditu: 22. júl 2026

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
