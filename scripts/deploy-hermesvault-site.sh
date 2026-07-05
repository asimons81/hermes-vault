#!/usr/bin/env bash
set -euo pipefail

EXPECTED_PROJECT="hermesvault-site"
CUSTOM_DOMAIN="hermesvault.tonysimons.dev"
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SITE_DIR="$REPO_ROOT/site"
PROJECT_JSON="$SITE_DIR/.vercel/project.json"

cd "$SITE_DIR"

if [[ -f "$PROJECT_JSON" ]]; then
linked_project="$(python - <<'PY'
import json
from pathlib import Path
print(json.loads(Path('.vercel/project.json').read_text()).get('projectName', ''))
PY
)"

  if [[ "$linked_project" != "$EXPECTED_PROJECT" ]]; then
    cat >&2 <<EOF
Refusing to deploy: site/.vercel/project.json is linked to Vercel project '$linked_project', expected '$EXPECTED_PROJECT'.

Fix it with:
  cd site && vercel link --yes --project $EXPECTED_PROJECT

Then rerun:
  scripts/deploy-hermesvault-site.sh
EOF
    exit 2
  fi
else
  echo "No site/.vercel/project.json found; linking to $EXPECTED_PROJECT first."
  npx --yes vercel link --yes --project "$EXPECTED_PROJECT"
fi

echo "Deploying $EXPECTED_PROJECT from $SITE_DIR"
output="$(npx --yes vercel deploy --prod --yes --project "$EXPECTED_PROJECT")"
printf '%s\n' "$output"

deploy_url="$(printf '%s\n' "$output" | awk '/^https:\/\/hermesvault-site-[^[:space:]]+\.vercel\.app$/ { url=$0 } END { print url }')"

if [[ -z "$deploy_url" ]]; then
  echo "Could not identify the immutable hermesvault-site deployment URL from Vercel output." >&2
  exit 3
fi

echo "Aliasing $CUSTOM_DOMAIN -> $deploy_url"
npx --yes vercel alias set "$deploy_url" "$CUSTOM_DOMAIN"

echo "Done: $CUSTOM_DOMAIN"
