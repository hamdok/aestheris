#!/usr/bin/env bash
# Audit de sécurité automatisé d'Aestheris, avec des outils open source reconnus.
# Localement : ./scripts/audit.sh (outils cherchés dans PATH, puis dans $AUDIT_TOOLS ou ../.devtools ;
# scripts/install-audit-tools.sh les installe).
# En CI : .github/workflows/security.yml installe les mêmes outils, versions épinglées.
#
#   cargo-deny   vulnérabilités connues (base RustSec), licences, sources des dépendances
#   osv-scanner  vulnérabilités connues (base OSV de Google) dans Cargo.lock
#   gitleaks     secrets dans tout l'historique git
#   trufflehog   secrets dans l'historique git (autre moteur, plus de 800 détecteurs)
#   semgrep      analyse statique : règles Rust, secrets, audit de sécurité
#   zizmor       failles des workflows GitHub Actions
#   aestheris    notre propre analyse (on mange notre cuisine)
#
# Toute erreur fait échouer le script. Un outil absent est signalé, et fait échouer en CI.
set -uo pipefail
cd "$(dirname "$0")/.."
DEV="${AUDIT_TOOLS:-$(cd .. && pwd)/.devtools}"
export PATH="$PATH:$DEV/bin:$DEV/py/bin"
[ -d "$DEV/py" ] && export PYTHONPATH="$DEV/py${PYTHONPATH:+:$PYTHONPATH}"

failed=()
missing=()
step() {
    local name=$1; shift
    if ! command -v "$1" >/dev/null 2>&1; then
        echo "━━━ $name : outil absent ($1)"; missing+=("$name"); return
    fi
    echo "━━━ $name"
    if "$@"; then echo "    ✓ $name"; else echo "    ✗ $name"; failed+=("$name"); fi
}

step "dépendances (cargo-deny)" cargo-deny check
step "vulnérabilités (osv-scanner)" osv-scanner scan source --lockfile Cargo.lock
# Historique de la branche courante seulement (celle qui est publiée), pas des branches locales.
step "secrets dans l'historique (gitleaks)" gitleaks git . --no-banner --redact -c .gitleaks.toml \
    --log-opts=HEAD
step "secrets dans l'historique (trufflehog)" trufflehog git "file://$PWD" --no-update --fail \
    --no-verification --exclude-paths=.trufflehog-exclude --branch "$(git rev-parse HEAD)"
step "analyse statique (semgrep)" semgrep scan --metrics=off --error --quiet \
    --config p/rust --config p/secrets --config p/security-audit \
    --exclude-rule rust.lang.security.unsafe-usage.unsafe-usage .
step "workflows GitHub (zizmor)" zizmor --offline .github
cargo build -q --bin aestheris && step "projet (aestheris scan)" ./target/debug/aestheris scan --no-home .

echo
[ ${#missing[@]} -gt 0 ] && echo "Outils absents : ${missing[*]}"
if [ ${#failed[@]} -gt 0 ]; then echo "Échecs : ${failed[*]}"; exit 1; fi
if [ ${#missing[@]} -gt 0 ] && [ -n "${CI:-}" ]; then exit 1; fi
echo "Audit automatisé : tout est vert."
