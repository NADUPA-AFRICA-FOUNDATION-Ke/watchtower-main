#!/usr/bin/env bash
# One-shot setup. Run:  bash setup.sh
#
# Creates a virtual environment in .venv. Modern Python (PEP 668) refuses
# system-wide pip installs, so a venv isn't optional here.
set -e

cd "$(dirname "$0")"

echo "==> Python"
python3 --version

# Check for the interpreter, not the directory. A half-built .venv — from an
# interrupted install, or a copied folder — passes a -d test and then fails
# confusingly two lines later.
if [ ! -x .venv/bin/python ]; then
  echo "==> Creating .venv"
  rm -rf .venv
  python3 -m venv .venv
fi

echo "==> Installing dependencies"
./.venv/bin/pip install --quiet --upgrade pip
./.venv/bin/pip install --quiet -r requirements.txt

echo "==> Running tests (no network or API key needed)"
fail=0
for t in smoke_test sweep_test web_test scamscan_test; do
  if ./.venv/bin/python "$t.py" > "/tmp/wt-$t.log" 2>&1; then
    printf "    %-12s %s\n" "$t" "$(grep -c PASS "/tmp/wt-$t.log") checks passed"
  else
    printf "    %-12s FAILED\n" "$t"
    grep FAIL "/tmp/wt-$t.log" || true
    fail=1
  fi
done

if [ "$fail" -ne 0 ]; then
  echo
  echo "Some tests failed. Fix those before running the app."
  exit 1
fi

cat <<'MSG'

Setup complete. Activate the environment, then run it:

  source .venv/bin/activate
  python run.py serve                     ->  http://127.0.0.1:8000
  python run.py sweep "your keywords"     ->  CLI

MSG

if [ -z "${ANTHROPIC_API_KEY:-}" ]; then
  cat <<'MSG'
ANTHROPIC_API_KEY is not set, so results will be ranked by keyword overlap
rather than scored by Claude. Everything still runs. To enable scoring:

  export ANTHROPIC_API_KEY=sk-...

MSG
fi
