#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")"

command -v git >/dev/null || { echo "Chýba git"; exit 1; }
command -v python3 >/dev/null || { echo "Chýba Python 3.11+"; exit 1; }
command -v claude >/dev/null || { echo "Chýba Claude Code"; exit 1; }
command -v codex >/dev/null || { echo "Chýba Codex CLI"; exit 1; }

python3 -m venv .venv
.venv/bin/python -m pip install --upgrade pip
.venv/bin/python -m pip install -r requirements.txt

if command -v npm >/dev/null && ! command -v srt >/dev/null; then
  echo "Inštalujem Anthropic Sandbox Runtime pre izolované testy..."
  npm install -g @anthropic-ai/sandbox-runtime
fi

.venv/bin/python forge.py doctor

echo "Forge je pripravený. Príklad:"
echo ".venv/bin/python forge.py run --project ~/AI-Projects/moja-apka --goal 'Vybuduj aplikáciu podľa SPEC.md' --config ./forge.strict.config.json"
