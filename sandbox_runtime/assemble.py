#!/usr/bin/env python3
"""Assemble a fresh, content-addressed kernel sandbox bundle.

This is an operator/build tool. Verification never invokes it. Development mode
uses a locally trusted Node executable and cannot produce a qualified receipt.
"""
from __future__ import annotations
import argparse, hashlib, json, os, shutil, stat, subprocess, sys, tempfile
from pathlib import Path

LOCK_SHA256 = '53908b1e23845bd0d452463f81a3df0f9b92bce76aa8c69c8f75c51a22600ec9'
PATCH_ID = 'kernel-srt-0.0.81-exact-tcp-v1'


def sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def run(argv: list[str], **kw) -> str:
    p = subprocess.run(argv, check=True, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, **kw)
    return p.stdout.strip()


def bundle_macos_runtime(node: Path, tree: Path) -> None:
    """Copy and relocate non-system dylibs for the unqualified local Homebrew Node."""
    libdir = tree/'node'/'lib'; libdir.mkdir(parents=True, exist_ok=True)
    queue = [node.resolve(strict=True)]; copied: dict[str,Path] = {}; rewrites = []
    while queue:
        binary = queue.pop(0)
        output = run(['otool','-L',str(binary)])
        rows = output.splitlines()[1:]
        for row in rows:
            raw = row.strip().split(' (compatibility version',1)[0]
            if not raw or raw.startswith(('/usr/lib/','/System/Library/')): continue
            if raw.startswith('@rpath/'):
                # For the supplied Homebrew Node, resolve its @rpath through the
                # recorded LC_RPATH entries; do not trust the eventual loader path.
                load = raw[len('@rpath/'):]
                rpaths = run(['otool','-l',str(binary)]).split('cmd LC_RPATH')[1:]
                candidates=[]
                for entry in rpaths:
                    match=__import__('re').search(r'path (\S+) \(offset',entry)
                    if match:
                        path=match.group(1).replace('@loader_path',str(binary.parent))
                        candidates.append(Path(path)/load)
                source=next((p.resolve() for p in candidates if p.exists()),None)
            elif raw.startswith('@loader_path/'):
                candidate=binary.parent/raw[len('@loader_path/'):]
                source=candidate.resolve() if candidate.exists() else None
            elif raw.startswith('@executable_path/'):
                candidate=node.resolve().parent/raw[len('@executable_path/'):]
                source=candidate.resolve() if candidate.exists() else None
            else:
                candidate=Path(raw)
                source=candidate.resolve() if candidate.exists() else None
            if source is None or not source.is_file():
                raise SystemExit(f'unresolved Node runtime dependency: {raw}')
            name=source.name; destination=libdir/name
            if name in copied:
                if hashlib.sha256(copied[name].read_bytes()).digest()!=hashlib.sha256(source.read_bytes()).digest():
                    raise SystemExit(f'conflicting dylib basename: {name}')
            else:
                shutil.copy2(source,destination); copied[name]=destination
                queue.append(source)
            rewrites.append((binary,raw,'@rpath/'+name))
    # The exact local Node executable is a Homebrew build. Relocate copied
    # dependencies only in the development tree; production retains archive bytes.
    for binary, old, new in rewrites:
        staged = tree/'node'/'bin'/'node' if binary == node.resolve() else libdir/binary.name
        run(['install_name_tool','-change',old,new,str(staged)])
    node_staged=tree/'node'/'bin'/'node'
    node_rpaths=run(['otool','-l',str(node_staged)])
    if 'path @loader_path/../lib ' not in node_rpaths:
        run(['install_name_tool','-add_rpath','@loader_path/../lib',str(node_staged)])
    for lib in copied.values():
        existing=run(['otool','-l',str(lib)])
        if 'path @loader_path ' not in existing:
            run(['install_name_tool','-add_rpath','@loader_path',str(lib)])
    # Load-command edits invalidate the Homebrew signature; ad-hoc signing the
    # disposable local executable/dylibs makes the copied development runtime
    # loadable without representing it as an authenticated release artifact.
    for image in [tree/'node'/'bin'/'node', *copied.values()]:
        run(['codesign','--force','--sign','-',str(image)])


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument('--dev', action='store_true', help='use local Node; emits dev_only receipt')
    ap.add_argument('--node', type=Path, help='exact Node executable (development mode only)')
    ap.add_argument('--npm', type=Path, help='operator npm executable used for clean staging')
    ap.add_argument('--node-libdir', type=Path, help='Node archive lib directory for production assembly')
    ap.add_argument('--destination', type=Path, help='fresh bundle directory')
    ap.add_argument('--receipt', type=Path, help='new receipt path outside bundle')
    ap.add_argument('--node-artifact-sha256', help='authenticated official archive digest (production)')
    args = ap.parse_args()
    repo = Path(__file__).resolve().parents[1]
    lock = repo / 'sandbox.package-lock.json'
    if sha(lock.read_bytes()) != LOCK_SHA256:
        raise SystemExit('frozen transitive lock SHA-256 mismatch')
    node = (args.node or Path.home()/'.local/bin/node').resolve(strict=True)
    npm = args.npm.resolve(strict=True) if args.npm else node.parent.parent/'bin'/'npm'
    if not npm.is_file():
        found = shutil.which('npm')
        if not found: raise SystemExit('npm executable required for operator assembly')
        npm = Path(found).resolve(strict=True)
    version = run([str(node), '--version'])
    if version != 'v24.22.0': raise SystemExit(f'unsupported Node version: {version}')
    if args.dev:
        if args.node_artifact_sha256: raise SystemExit('--dev must not claim an official archive digest')
        default = Path.home()/'.local/state/kernel/dev-bundle-v3'
    else:
        if not args.node_artifact_sha256 or len(args.node_artifact_sha256) != 64 or any(c not in '0123456789abcdef' for c in args.node_artifact_sha256):
            raise SystemExit('production assembly requires authenticated --node-artifact-sha256')
        default = None
    if not args.destination and default is None: raise SystemExit('production assembly requires --destination')
    dest = (args.destination or default).expanduser().absolute()
    receipt_path = args.receipt.expanduser().absolute() if args.receipt else dest.parent/(dest.name+'.receipt.json')
    if dest.exists() or receipt_path.exists(): raise SystemExit('refusing to overwrite bundle or receipt')
    required = ['sandbox_runtime/kernel-srt-0.0.81-exact-tcp-v1.patch', 'sandbox_runtime/patch-manifest.json', 'sandbox_runtime/apply_patch.py', 'sandbox_supervisor.mjs', 'kernel_profile.py']
    for rel in required:
        if not (repo/rel).is_file(): raise SystemExit(f'required reviewed assembly input missing: {rel}')
    if not (repo/'sandbox_runtime/apply_patch.py').is_file(): raise SystemExit('patch application helper missing')
    dest.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix='.kernel-sandbox-v3-', dir=dest.parent) as temp:
        root=Path(temp)/'tree'; root.mkdir()
        shutil.copy2(repo/'sandbox.package.json', root/'package.json')
        shutil.copy2(lock, root/'package-lock.json')
        (root/'sandbox_runtime').mkdir()
        shutil.copy2(repo/'sandbox_runtime/kernel-srt-0.0.81-exact-tcp-v1.patch',root/'sandbox_runtime/kernel-srt-0.0.81-exact-tcp-v1.patch')
        shutil.copy2(repo/'sandbox_runtime/patch-manifest.json',root/'sandbox_runtime/patch-manifest.json')
        shutil.copy2(repo/'sandbox_runtime/apply_patch.py',root/'sandbox_runtime/apply_patch.py')
        shutil.copy2(repo/'sandbox_supervisor.mjs',root/'supervisor.mjs')
        shutil.copy2(repo/'kernel_profile.py',root/'kernel_profile.py')
        (root/'node'/'bin').mkdir(parents=True)
        shutil.copy2(node, root/'node'/'bin'/'node'); os.chmod(root/'node'/'bin'/'node',0o755)
        if args.dev:
            bundle_macos_runtime(node, root)
        elif args.node_libdir:
            source_lib=args.node_libdir.resolve(strict=True)
            shutil.copytree(source_lib,root/'node'/'lib',symlinks=False)
        # Validate the copied executable and its loader closure before packaging.
        run([str(root/'node'/'bin'/'node'),'--version'])
        run([str(npm), 'ci', '--prefix', str(root), '--ignore-scripts','--no-bin-links','--no-audit','--no-fund'])
        srt=root/'node_modules/@anthropic-ai/sandbox-runtime'
        run([sys.executable, '-B', str(root/'sandbox_runtime/apply_patch.py'), str(root)])
        os.chmod(root/'node/bin/node',0o755)
        files=[]; inventory=[]
        for p in sorted(root.rglob('*'),key=lambda x:x.relative_to(root).as_posix()):
            rel=p.relative_to(root).as_posix(); mode=stat.S_IMODE(p.lstat().st_mode)
            if p.is_symlink(): raise SystemExit(f'bundle symlink rejected: {rel}')
            if p.is_dir(): inventory.append({'path':rel,'type':'directory','mode':mode})
            elif p.is_file():
                row={'path':rel,'sha256':sha(p.read_bytes()),'mode':mode}
                files.append(row); inventory.append({'path':rel,'type':'file','mode':mode,'sha256':row['sha256']})
            else: raise SystemExit(f'unsupported bundle object: {rel}')
        bundle_digest=sha(json.dumps(files,sort_keys=True,separators=(',',':')).encode())
        manifest=json.loads((root/'sandbox_runtime/patch-manifest.json').read_text())
        receipt={'schema':2,'bundle_root':str(dest),'files':files,
          'node':{'executable':'node/bin/node','version':version,'artifact_sha256':'UNQUALIFIED_LOCAL_EXECUTABLE' if args.dev else args.node_artifact_sha256,'executable_sha256':sha((root/'node/bin/node').read_bytes())},
          'srt_version':'0.0.81','lock_sha256':LOCK_SHA256,'bundle_digest':bundle_digest,
          'patch_file':'sandbox_runtime/kernel-srt-0.0.81-exact-tcp-v1.patch','patch_id':manifest['patch_id'],'patch_sha256':manifest['patch_sha256'],
          'patch_preimages':manifest['preimages'],'patch_postimages':manifest['postimages'],
          'dev_only':bool(args.dev),'qualification':'development-only' if args.dev else 'operator-provisioned-unqualified',
          'network_semantics':'srt-0.0.81-exact-tcp-v1',
          'network_exceptions':[
            {'id':'address_wildcard_declared_tcp_binding','detail':'Each declared TCP port allows wildcard bind/inbound and data exchange on accepted non-loopback connections; empty declarations grant none.'},
            {'id':'localhost_address_class_aliases','literal_spelling_enforced':False,'detail':'localhost is an OS address class, not a spelling or service identity check.'},
            {'id':'mapped_outbound_qualification','status':'unavailable','universal_compatibility':False,'detail':'Mapped/alias behavior requires qualification on this exact OS and runtime.'}],
          'assurance':{key:False for key in ('loopback_only_binding','literal_address_only','complete_logs','all_attempts_detected','transient_writes_detected','semantic_attestation','exhaustive_descendant_containment','sandbox_qualified')}}
        shutil.move(str(root),str(dest))
    receipt_path.parent.mkdir(parents=True,exist_ok=True)
    # O_EXCL avoids replacing a caller-held receipt after assembly.
    fd=os.open(receipt_path,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600)
    with os.fdopen(fd,'w') as f: f.write(json.dumps(receipt,sort_keys=True,indent=2)+'\n')
    print(json.dumps({'bundle_root':str(dest),'bundle_digest':bundle_digest,'receipt':str(receipt_path),'receipt_sha256':sha(receipt_path.read_bytes()),'dev_only':bool(args.dev)},sort_keys=True))
    return 0

if __name__=='__main__':
    try: raise SystemExit(main())
    except (OSError, subprocess.CalledProcessError, KeyError, ValueError) as exc:
        print(f'assemble: {exc}',file=sys.stderr); raise SystemExit(2)
