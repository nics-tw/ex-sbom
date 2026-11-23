#!/bin/bash
set -euo pipefail

usage() {
  cat <<'USAGE'
Usage: scripts/prepare-tagged-pdf-assets.sh --from <asset-dir>

Prepare the embedded PDF bundle for the GOOS and GOARCH reported by go env.
Provide the Typst v0.15.1 archive for that target in <asset-dir>.

  darwin/arm64  typst-aarch64-apple-darwin.tar.xz
  linux/arm64   typst-aarch64-unknown-linux-musl.tar.xz
  linux/amd64   typst-x86_64-unknown-linux-musl.tar.xz

Every target also uses these inputs from <asset-dir>.
  NotoSansCJKtc-Regular.otf  Noto CJK Sans2.004
  NotoSansCJKtc-OFL.txt      LICENSE from the Sans2.004 repository root
  NotoEmoji.ttf            NotoEmoji[wght].ttf from Google Fonts
  NotoEmoji-OFL.txt        OFL.txt from the same Google Fonts revision
Google Fonts revision 06bfe0d62a98375cb09c942fa18e68bd32cff057

The script uses local files only. It checks SHA-256 digests before
generating internal/service/pdf/bundle/<GOOS>_<GOARCH>.
USAGE
}

fail() {
  printf '%s\n' "$*" >&2
  exit 1
}

if [[ $# -eq 1 && ( $1 == -h || $1 == --help ) ]]; then
  usage
  exit 0
fi
if [[ $# -ne 2 || $1 != --from ]]; then
  usage >&2
  exit 2
fi

goos=$(go env GOOS)
goarch=$(go env GOARCH)
# https://api.github.com/repos/typst/typst/releases/tags/v0.15.1
case "$goos/$goarch" in
  darwin/arm64)
    archive_dir=typst-aarch64-apple-darwin
    archive_sha256=48f62ed034aa3a7978309579ac6ca00045e2ef0da73114e8af27cfd8e74dc05a
    ;;
  linux/arm64)
    archive_dir=typst-aarch64-unknown-linux-musl
    archive_sha256=5aa8d74a3d906e60ea12a66ac2f37f8eef1b14cbad7182a745e393a10c23dcee
    ;;
  linux/amd64)
    archive_dir=typst-x86_64-unknown-linux-musl
    archive_sha256=a6d077d0a95eed5a2eba715b2dae06be954f624ccbf85758a03f389ded33118c
    ;;
  *)
    fail "Tagged PDF bundle unavailable for $goos/$goarch. Supported targets are darwin/arm64, linux/arm64, and linux/amd64."
    ;;
esac

input_dir=$(cd -- "$2" && pwd -P)
pdf_dir=$(cd -- "$(dirname -- "$0")/../internal/service/pdf" && pwd -P)
bundle_root="$pdf_dir/bundle"
bundle_dir="$bundle_root/${goos}_${goarch}"
[[ ! -L "$bundle_root" ]] || fail "Bundle directory is a symbolic link: $bundle_root"
[[ ! -L "$bundle_dir" ]] || fail "Bundle directory is a symbolic link: $bundle_dir"

stage=$(mktemp -d "$pdf_dir/.bundle.XXXXXXXX")
trap 'rm -rf -- "$stage"' EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
mkdir "$stage/bundle"

stage_input() {
  local name=$1 expected=$2 digest
  [[ -f "$input_dir/$name" ]] || fail "Missing input: $input_dir/$name"
  cp -- "$input_dir/$name" "$stage/$name"
  digest=$(shasum -a 256 < "$stage/$name")
  [[ "${digest%% *}" == "$expected" ]] || fail "SHA-256 mismatch: $input_dir/$name"
}

archive="$archive_dir.tar.xz"
stage_input "$archive" "$archive_sha256"
# https://github.com/notofonts/noto-cjk/blob/Sans2.004/Sans/OTF/TraditionalChinese/NotoSansCJKtc-Regular.otf
stage_input NotoSansCJKtc-Regular.otf dce08bd4fd91aa8aa76ed8fea4b694c2dfb8550f67871e326843212ddbeb88b4
# https://github.com/notofonts/noto-cjk/blob/Sans2.004/LICENSE
stage_input NotoSansCJKtc-OFL.txt 6a73f9541c2de74158c0e7cf6b0a58ef774f5a780bf191f2d7ec9cc53efe2bf2
# https://github.com/google/fonts/tree/06bfe0d62a98375cb09c942fa18e68bd32cff057/ofl/notoemoji
stage_input NotoEmoji.ttf de6c18832938afc99caf132b39d6a30a19bac7f2e812e28db2535b4608d27551
stage_input NotoEmoji-OFL.txt 500bb1ccf43df7bbb522112f9133a52b16e1c35e809632f5d8609b179152de5b

tar -xf "$stage/$archive" -C "$stage" "$archive_dir/typst" "$archive_dir/LICENSE" "$archive_dir/NOTICE"
gzip -cn9 "$stage/$archive_dir/typst" > "$stage/bundle/typst.gz"
gzip -cn9 "$stage/NotoSansCJKtc-Regular.otf" > "$stage/bundle/NotoSansCJKtc-Regular.otf.gz"
gzip -cn9 "$stage/NotoEmoji.ttf" > "$stage/bundle/NotoEmoji.ttf.gz"
cp -- "$stage/$archive_dir/LICENSE" "$stage/$archive_dir/NOTICE" \
  "$stage/NotoSansCJKtc-OFL.txt" "$stage/NotoEmoji-OFL.txt" "$stage/bundle/"

# Publish only after all inputs have been verified and all outputs generated.
for file in "$stage/bundle/"*; do
  destination="$bundle_dir/${file##*/}"
  if [[ -L "$destination" || ( -e "$destination" && ! -f "$destination" ) ]]; then
    fail "Invalid bundle destination: $destination"
  fi
done
mkdir -p -- "$bundle_dir"
for file in "$stage/bundle/"*; do
  destination="$bundle_dir/${file##*/}"
  if ! cmp -s -- "$file" "$destination"; then
    mv -f -- "$file" "$destination"
  fi
done
printf 'Prepared tagged PDF assets for %s/%s in %s\n' "$goos" "$goarch" "$bundle_dir"
