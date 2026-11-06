#!/bin/bash
# Zack-only operator provisioning. Verification never invokes this script.
set -euo pipefail
usage(){ cat >&2 <<'EOF'
Usage: sudo sandbox_runtime/provision.sh \
  --node-archive /absolute/path/node-v24.22.0-darwin-arm64.tar.gz \
  --node-archive-sha256 AUTHENTICATED_OFFICIAL_ARCHIVE_SHA256 \
  --receipt /absolute/root-protected/path/kernel-sandbox-bundle.json
EOF
 exit 2; }
[[ $(id -u) -eq 0 && $(uname -s) == Darwin ]] || { echo 'Zack-only provisioning requires root on macOS' >&2; exit 2; }
archive=''; archive_sha=''; receipt=''
while (($#)); do
 case "$1" in
  --node-archive) (($# >= 2)) || usage; archive=$2; shift 2 ;;
  --node-archive-sha256) (($# >= 2)) || usage; archive_sha=$2; shift 2 ;;
  --receipt) (($# >= 2)) || usage; receipt=$2; shift 2 ;;
  *) usage ;;
 esac
done
[[ -n "$archive" && "$archive" = /* && -f "$archive" ]] || usage
[[ "$archive_sha" =~ ^[0-9a-f]{64}$ ]] || usage
[[ -n "$receipt" && "$receipt" = /* && ! -e "$receipt" ]] || usage
repo_root=$(cd "$(dirname "$0")/.." && pwd -P)
receipt_parent=$(dirname "$receipt")
[[ -d "$receipt_parent" ]] || { echo 'receipt parent must already exist' >&2; exit 2; }
python3 -B - "$receipt_parent" <<'PY'
import stat,sys
from pathlib import Path
for p in [Path(sys.argv[1]),*Path(sys.argv[1]).parents]:
 s=p.lstat()
 if not stat.S_ISDIR(s.st_mode) or stat.S_ISLNK(s.st_mode) or s.st_uid != 0 or s.st_mode & 0o022:
  raise SystemExit('receipt ancestry must be root-owned, non-writable and symlink-free: '+str(p))
PY
[[ $(shasum -a 256 "$archive" | awk '{print $1}') == "$archive_sha" ]] || { echo 'official Node archive digest mismatch' >&2; exit 2; }
case "$(uname -m)" in arm64) node_arch=arm64;; x86_64) node_arch=x64;; *) echo 'unsupported macOS architecture' >&2; exit 2;; esac
node_root="node-v24.22.0-darwin-${node_arch}"
tmp_root='/Library/Application Support/KernelRuntime/kernel-sandbox'
base="$tmp_root/0.0.81"
for dir in '/Library/Application Support' '/Library/Application Support/KernelRuntime' "$tmp_root" "$base"; do
 if [[ ! -d "$dir" ]]; then mkdir "$dir"; chown root:wheel "$dir"; chmod 755 "$dir"; fi
 [[ -d "$dir" && ! -L "$dir" && $(stat -f '%u' "$dir") == 0 ]] || { echo "unsafe bundle ancestor: $dir" >&2; exit 2; }
 mode=$(stat -f '%Lp' "$dir"); (( (8#$mode & 0022) == 0 )) || { echo "writable bundle ancestor: $dir" >&2; exit 2; }
done
work=$(mktemp -d "$base/.provision.XXXXXX")
receipt_tmp="$receipt_parent/.sandbox-bundle-receipt.$$.json"
[[ ! -e "$receipt_tmp" ]] || { echo 'temporary receipt already exists' >&2; exit 2; }
cleanup(){ python3 -B - "$work" "$receipt_tmp" <<'PY'
import shutil,sys
from pathlib import Path
shutil.rmtree(Path(sys.argv[1]),ignore_errors=True)
Path(sys.argv[2]).unlink(missing_ok=True)
PY
}
trap cleanup EXIT
mkdir -p "$work/node-runtime/bin"
tar -xOf "$archive" "$node_root/bin/node" > "$work/node-runtime/bin/node"
tar -xf "$archive" -C "$work/node-runtime" "$node_root/lib"
mv "$work/node-runtime/$node_root/lib" "$work/node-runtime/lib"
chmod 755 "$work/node-runtime/bin/node"
[[ "$($work/node-runtime/bin/node --version)" == v24.22.0 ]] || { echo 'Node binary version mismatch' >&2; exit 2; }
# Assemble once at a fresh path; the digest covers these same bytes.
python3 -B "$repo_root/sandbox_runtime/assemble.py" \
 --node "$work/node-runtime/bin/node" --node-artifact-sha256 "$archive_sha" \
 --node-libdir "$work/node-runtime/lib" \
 --destination "$work/tree" --receipt "$receipt_tmp" > "$work/assembly.json"
bundle_digest=$(python3 -B -c 'import json,sys;print(json.load(open(sys.argv[1]))["bundle_digest"])' "$work/assembly.json")
final="$base/$bundle_digest"
[[ ! -e "$final" ]] || { echo "refusing to overwrite existing digest directory: $final" >&2; exit 2; }
chown -R root:wheel "$work/tree"
find "$work/tree" -type d -exec chmod 755 {} +
find "$work/tree" -type f -exec chmod go-w {} +
chmod -R +a 'everyone deny write,append,delete,delete_child,add_file,add_subdirectory,writeattr,writeextattr,writesecurity,chown' "$work/tree"
mv "$work/tree" "$final"
python3 -B - "$receipt_tmp" "$final" <<'PY'
import json,sys
from pathlib import Path
p=Path(sys.argv[1]); obj=json.loads(p.read_text()); obj['bundle_root']=sys.argv[2]
p.write_text(json.dumps(obj,sort_keys=True,indent=2)+'\n')
PY
chown root:wheel "$receipt_tmp"; chmod 444 "$receipt_tmp"
mv "$receipt_tmp" "$receipt"
shasum -a 256 "$receipt"
printf 'Provisioned immutable bundle: %s\nCaller-held receipt: %s\n' "$final" "$receipt"
