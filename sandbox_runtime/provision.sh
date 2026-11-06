#!/bin/bash
set -euo pipefail

usage() {
  cat >&2 <<'EOF'
Usage:
  sudo sandbox_runtime/provision.sh \
    --node-archive /absolute/path/node-v24.22.0-darwin-arm64.tar.gz \
    --node-archive-sha256 LOWERCASE_SHA256 \
    --receipt /absolute/path/to/caller-held-bundle-receipt.json

The Node archive digest must come from the authenticated official release
checksum. This script never overwrites an existing bundle digest or receipt.
EOF
  exit 2
}

[[ $(id -u) -eq 0 ]] || { echo 'run this provisioning script with sudo' >&2; exit 2; }
[[ $(uname -s) == Darwin ]] || { echo 'only macOS is qualified by this bundle' >&2; exit 2; }

archive=''
archive_sha=''
receipt=''
while (($#)); do
  case "$1" in
    --node-archive) (($# >= 2)) || usage; archive=$2; shift 2 ;;
    --node-archive-sha256) (($# >= 2)) || usage; archive_sha=$2; shift 2 ;;
    --receipt) (($# >= 2)) || usage; receipt=$2; shift 2 ;;
    *) usage ;;
  esac
done
[[ -n "$archive" && -f "$archive" && "$archive" = /* ]] || usage
[[ "$archive_sha" =~ ^[0-9a-f]{64}$ ]] || usage
[[ -n "$receipt" && "$receipt" = /* ]] || usage
receipt_parent=$(dirname "$receipt")
[[ -d "$receipt_parent" && ! -e "$receipt" ]] || { echo 'receipt parent must exist and receipt must not exist' >&2; exit 2; }

repo_root=$(cd "$(dirname "$0")/.." && pwd -P)
# Stop before touching /Library while the architecture gate is unresolved.
[[ -s "$repo_root/sandbox_supervisor.mjs" ]] || { echo 'BLOCKED: trusted supervisor source is not available; no bundle can be provisioned' >&2; exit 2; }
case "$receipt" in "$repo_root"/*) echo 'caller-held receipt must be outside the repository' >&2; exit 2;; esac
[[ "$(shasum -a 256 "$repo_root/sandbox.package-lock.json" | awk '{print $1}')" == '53908b1e23845bd0d452463f81a3df0f9b92bce76aa8c69c8f75c51a22600ec9' ]] || { echo 'frozen srt transitive lock mismatch' >&2; exit 2; }
python3 -B - "$receipt_parent" <<'PYTHON'
import os,stat,sys
from pathlib import Path
path=Path(sys.argv[1])
for parent in [path,*path.parents]:
    info=parent.lstat()
    if stat.S_ISLNK(info.st_mode) or not stat.S_ISDIR(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022:
        raise SystemExit('receipt ancestry must be root-owned, non-writable and free of symlinks: '+str(parent))
PYTHON

# Caller-held receipts must not be replaceable by the candidate identity.
[[ "$(stat -f '%Su' "$receipt_parent")" == root ]] || { echo 'receipt parent must be root-owned' >&2; exit 2; }
receipt_mode=$(stat -f '%Lp' "$receipt_parent")
(( (8#$receipt_mode & 0022) == 0 )) || { echo 'receipt parent must not be group/world writable' >&2; exit 2; }
actual_archive_sha=$(shasum -a 256 "$archive" | awk '{print $1}')
[[ "$actual_archive_sha" == "$archive_sha" ]] || { echo 'Node archive SHA-256 mismatch' >&2; exit 2; }

case "$(uname -m)" in
  arm64) node_arch=arm64 ;;
  x86_64) node_arch=x64 ;;
  *) echo 'unsupported macOS architecture' >&2; exit 2 ;;
esac
archive_root="node-v24.22.0-darwin-${node_arch}"
base='/Library/Application Support/KernelRuntime/kernel-sandbox/0.0.81'
# Establish a non-writable root-owned ancestry, creating only missing components.
for dir in '/Library/Application Support' '/Library/Application Support/KernelRuntime' '/Library/Application Support/KernelRuntime/kernel-sandbox' "$base"; do
  if [[ ! -d "$dir" ]]; then mkdir "$dir"; chown root:wheel "$dir"; chmod 755 "$dir"; fi
  [[ "$(stat -f '%Su' "$dir")" == root ]] || { echo "bundle ancestor is not root-owned: $dir" >&2; exit 2; }
  mode=$(stat -f '%Lp' "$dir")
  (( (8#$mode & 0022) == 0 )) || { echo "bundle ancestor is group/world writable: $dir" >&2; exit 2; }
done

work=$(mktemp -d "$base/.provision.XXXXXX")
cleanup() { rm -rf "$work"; }
trap cleanup EXIT
mkdir -p "$work/tree/node/bin" "$work/tree/node_modules"
# Extract only the exact executable; Node's archive may contain npm symlinks,
# which are neither needed by the verifier nor admitted into the trusted bundle.
tar -xOf "$archive" "$archive_root/bin/node" > "$work/tree/node/bin/node"
chmod 755 "$work/tree/node/bin/node"
[[ "$($work/tree/node/bin/node --version)" == 'v24.22.0' ]] || { echo 'Node executable version mismatch' >&2; exit 2; }
cp "$repo_root/sandbox.package.json" "$work/tree/package.json"
cp "$repo_root/sandbox.package-lock.json" "$work/tree/package-lock.json"
# This networked operator step installs only the frozen package graph. Checks
# themselves never run npm or resolve dependencies.
npm ci --prefix "$work/tree" --ignore-scripts --no-bin-links --no-audit --no-fund
cp "$repo_root/sandbox_supervisor.mjs" "$work/tree/supervisor.mjs"

# Final ownership/modes are established before inventory and digest calculation.
chown -R root:wheel "$work/tree"
find "$work/tree" -type d -exec chmod 755 {} +
find "$work/tree" -type f -exec chmod go-w {} +

bundle_json=$(python3 -B - "$work/tree" "$archive_sha" <<'PY'
import hashlib,json,stat,sys
from pathlib import Path
root=Path(sys.argv[1]); archive_sha=sys.argv[2]; manifest=[]; files=[]
for p in sorted(root.rglob('*'),key=lambda p:p.relative_to(root).as_posix()):
    rel=p.relative_to(root).as_posix(); mode=stat.S_IMODE(p.lstat().st_mode)
    if p.is_symlink(): raise SystemExit('bundle contains a symlink: '+rel)
    if p.is_dir(): manifest.append({'path':rel,'type':'directory','mode':mode})
    elif p.is_file():
        row={'path':rel,'type':'file','mode':mode,'sha256':hashlib.sha256(p.read_bytes()).hexdigest()}
        manifest.append(row); files.append(row)
    else: raise SystemExit('bundle contains an unsupported filesystem object: '+rel)
canonical=json.dumps(manifest,sort_keys=True,separators=(',',':')).encode()
digest=hashlib.sha256(canonical).hexdigest()
lock=hashlib.sha256((root/'package-lock.json').read_bytes()).hexdigest()
node_hash=hashlib.sha256((root/'node/bin/node').read_bytes()).hexdigest()
receipt={'schema':1,'bundle_root':'/Library/Application Support/KernelRuntime/kernel-sandbox/0.0.81/'+digest,'files':files,'node':{'executable':'node/bin/node','version':'v24.22.0','artifact_sha256':archive_sha,'executable_sha256':node_hash},'srt_version':'0.0.81','lock_sha256':lock,'bundle_digest':digest,'assurance':{'operator_provisioned':True,'sandbox_qualified':False,'os_logs_complete':False}}
print(json.dumps({'digest':digest,'receipt':receipt},sort_keys=True))
PY
)
bundle_digest=$(python3 -B -c 'import json,sys; print(json.loads(sys.argv[1])["digest"])' "$bundle_json")
final="$base/$bundle_digest"
[[ ! -e "$final" ]] || { echo "refusing to overwrite existing bundle digest $final" >&2; exit 2; }

# ACLs deny writes/deletion even if a later mode change is accidental.
chmod -R +a 'everyone deny write,append,delete,delete_child,add_file,add_subdirectory,writeattr,writeextattr,writesecurity,chown' "$work/tree"
mv "$work/tree" "$final"

receipt_tmp="$receipt.tmp.$$"
trap 'rm -rf "$work"; rm -f "$receipt_tmp"' EXIT
python3 -B - "$bundle_json" "$receipt_tmp" <<'PY'
import json,sys
from pathlib import Path
payload=json.loads(sys.argv[1])['receipt']
Path(sys.argv[2]).write_text(json.dumps(payload,sort_keys=True,indent=2)+'\n')
PY
chown root:wheel "$receipt_tmp"
chmod 444 "$receipt_tmp"
mv "$receipt_tmp" "$receipt"
shasum -a 256 "$receipt"
printf 'Provisioned immutable bundle: %s\nCaller-held receipt: %s\n' "$final" "$receipt"
