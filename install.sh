#!/bin/sh
# Installe la dernière version d'Aestheris (macOS, Linux ; x86_64 et arm64).
#   curl -fsSL https://raw.githubusercontent.com/hamdok/aestheris/main/install.sh | sh
# L'archive est vérifiée par son empreinte SHA-256 publiée avec la version. Avec la commande gh,
# la provenance l'est aussi : construite par la CI de ce dépôt, à partir de ce code (Sigstore).
# Dossier d'installation : $AESTHERIS_INSTALL_DIR, sinon ~/.local/bin.
set -eu
REPO=hamdok/aestheris
DIR=${AESTHERIS_INSTALL_DIR:-"$HOME/.local/bin"}

case "$(uname -s)-$(uname -m)" in
    Darwin-arm64) TARGET=aarch64-apple-darwin ;;
    Darwin-x86_64) TARGET=x86_64-apple-darwin ;;
    Linux-x86_64) TARGET=x86_64-unknown-linux-gnu ;;
    Linux-aarch64 | Linux-arm64) TARGET=aarch64-unknown-linux-gnu ;;
    *) echo "aestheris : plateforme non prise en charge ($(uname -s) $(uname -m))" >&2; exit 1 ;;
esac

TAG=$(curl -fsSL --proto '=https' "https://api.github.com/repos/$REPO/releases?per_page=1" \
    | sed -n 's/.*"tag_name": *"\([^"]*\)".*/\1/p' | head -n 1)
[ -n "$TAG" ] || { echo "aestheris : aucune version publiée" >&2; exit 1; }
FILE="aestheris-$TAG-$TARGET.tar.gz"
BASE="https://github.com/$REPO/releases/download/$TAG"

TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT
curl -fsSL --proto '=https' -o "$TMP/$FILE" "$BASE/$FILE"
curl -fsSL --proto '=https' -o "$TMP/SHA256SUMS" "$BASE/SHA256SUMS"
EXPECTED=$(grep " $FILE\$" "$TMP/SHA256SUMS" | cut -d' ' -f1)
if command -v sha256sum >/dev/null 2>&1; then GOT=$(sha256sum "$TMP/$FILE" | cut -d' ' -f1)
else GOT=$(shasum -a 256 "$TMP/$FILE" | cut -d' ' -f1); fi
if [ -z "$EXPECTED" ] || [ "$EXPECTED" != "$GOT" ]; then
    echo "aestheris : empreinte SHA-256 inattendue, installation annulée" >&2; exit 1
fi
if command -v gh >/dev/null 2>&1 && gh auth status >/dev/null 2>&1; then
    gh attestation verify "$TMP/$FILE" --repo "$REPO" >/dev/null \
        && echo "aestheris : provenance vérifiée (Sigstore)" \
        || { echo "aestheris : provenance non vérifiée, installation annulée" >&2; exit 1; }
fi

tar xzf "$TMP/$FILE" -C "$TMP"
mkdir -p "$DIR"
install -m 0755 "$TMP/aestheris-$TAG-$TARGET/aestheris" "$DIR/aestheris"
echo "aestheris $TAG installé dans $DIR/aestheris"
case ":$PATH:" in *":$DIR:"*) ;; *) echo "ajoutez $DIR à votre PATH" ;; esac
