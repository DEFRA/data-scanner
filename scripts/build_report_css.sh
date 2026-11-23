#!/usr/bin/env bash
# Rebuild src/pii_scanner/static/report.min.css from scripts/report.scss (GOV.UK Frontend set in Arial,
# with Defra branding). Only needed when changing the stylesheet or upgrading GOV.UK Frontend; the
# compiled CSS is committed so building reports doesn't need Node.
set -euo pipefail

GOVUK_FRONTEND_VERSION="${GOVUK_FRONTEND_VERSION:-6.6.0}"
SASS_VERSION="${SASS_VERSION:-1.108.2}"

root="$(cd "$(dirname "$0")/.." && pwd)"
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT

cd "$work"
npm init -y >/dev/null
npm install --silent --no-audit --no-fund "govuk-frontend@${GOVUK_FRONTEND_VERSION}" "sass@${SASS_VERSION}"
mkdir -p "$root/src/pii_scanner/static"
npx sass --load-path="$work/node_modules" --no-source-map --style=compressed --quiet-deps --no-error-css \
  "$root/scripts/report.scss" "$root/src/pii_scanner/static/report.min.css"

if grep -q 'url(' "$root/src/pii_scanner/static/report.min.css"; then
  echo "report.min.css references external files; the report must stay self-contained" >&2
  exit 1
fi
echo "Built src/pii_scanner/static/report.min.css (govuk-frontend ${GOVUK_FRONTEND_VERSION})"
