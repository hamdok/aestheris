#!/usr/bin/env bash
# Installe les outils de scripts/audit.sh dans un dossier, versions épinglées et empreintes
# SHA-256 inscrites ici : un binaire modifié à la source serait refusé.
#   scripts/install-audit-tools.sh <dossier>      (Linux x86_64 ou macOS arm64)
# Puis : AUDIT_TOOLS=<dossier> scripts/audit.sh
set -euo pipefail
DEST=${1:?"usage : $0 <dossier>"}
mkdir -p "$DEST/bin"

case "$(uname -s)-$(uname -m)" in
    Linux-x86_64)
        GL=gitleaks_8.30.1_linux_x64.tar.gz
        GL_SHA=551f6fc83ea457d62a0d98237cbad105af8d557003051f41f3e7ca7b3f2470eb
        TH=trufflehog_3.97.9_linux_amd64.tar.gz
        TH_SHA=40377e6572495412fb9ba0bc21c9401f73b72f1d2afd11b9931bc4a5ed622866
        OSV=osv-scanner_linux_amd64
        OSV_SHA=ca69b3d3cd08f889a49dc0a383122f71cc528b83803671df5fd874d97485b108
        ;;
    Darwin-arm64)
        GL=gitleaks_8.30.1_darwin_arm64.tar.gz
        GL_SHA=b40ab0ae55c505963e365f271a8d3846efbc170aa17f2607f13df610a9aeb6a5
        TH=trufflehog_3.97.9_darwin_arm64.tar.gz
        TH_SHA=3d25c178fe1a2563687b22547adcaebcf08cc8a607315c6741fe396c597951f7
        OSV=osv-scanner_darwin_arm64
        OSV_SHA=98c460dcd37de25819babd757d04542045b6243113e209edcd4d89fedb0256b4
        ;;
    *) echo "plateforme non prise en charge : $(uname -s)-$(uname -m)" >&2; exit 1 ;;
esac

sha256() { if command -v sha256sum >/dev/null; then sha256sum "$1"; else shasum -a 256 "$1"; fi | cut -d' ' -f1; }
fetch() { # url empreinte destination
    curl -fsSL --proto '=https' --tlsv1.2 -o "$3" "$1"
    local got; got=$(sha256 "$3")
    if [ "$got" != "$2" ]; then echo "empreinte inattendue pour $1 : $got" >&2; rm -f "$3"; exit 1; fi
}

tmp=$(mktemp -d); trap 'rm -rf "$tmp"' EXIT
fetch "https://github.com/gitleaks/gitleaks/releases/download/v8.30.1/$GL" "$GL_SHA" "$tmp/gl.tgz"
tar xzf "$tmp/gl.tgz" -C "$DEST/bin" gitleaks
fetch "https://github.com/trufflesecurity/trufflehog/releases/download/v3.97.9/$TH" "$TH_SHA" "$tmp/th.tgz"
tar xzf "$tmp/th.tgz" -C "$DEST/bin" trufflehog
fetch "https://github.com/google/osv-scanner/releases/download/v2.6.0/$OSV" "$OSV_SHA" "$DEST/bin/osv-scanner"
chmod +x "$DEST/bin/osv-scanner"
python3 -m pip install --quiet --disable-pip-version-check --target "$DEST/py" semgrep==1.178.0 zizmor==1.30.1
cargo install --locked --quiet --root "$DEST" cargo-deny --version 0.20.2
echo "outils installés dans $DEST"
