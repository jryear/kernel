"""Authenticate the external sandbox bundle before any bundle code is loaded.

Development-only receipts deliberately do not establish operator ownership or
Node archive provenance. They require an explicit trusted-caller opt-in.
"""
from __future__ import annotations
import hashlib
import json
import os
from pathlib import Path
import stat

PATCH_ID = 'kernel-srt-0.0.81-exact-tcp-v1'
LOCK_SHA256 = '53908b1e23845bd0d452463f81a3df0f9b92bce76aa8c69c8f75c51a22600ec9'


class AuthenticationError(ValueError):
    pass


class DependencyUnavailable(RuntimeError):
    pass


def sha256(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def canonical_digest(rows):
    return hashlib.sha256(json.dumps(rows, sort_keys=True, separators=(',', ':')).encode()).hexdigest()


def relative(value):
    if (not isinstance(value, str) or not value or Path(value).is_absolute() or
            any(part in ('', '.', '..') for part in value.split('/')) or '\\' in value):
        raise AuthenticationError('unsafe bundle path')
    return value


def authenticate(operator, repo):
    """Return receipt and absolute executables; ownership failures are unavailable."""
    receipt_path = Path(operator['bundle_receipt']).resolve(strict=True)
    if receipt_path == repo or repo in receipt_path.parents:
        raise AuthenticationError('operator receipt is inside caller repository')
    raw = receipt_path.read_bytes()
    receipt = json.loads(raw)
    dev = receipt.get('dev_only') is True
    if dev:
        if os.environ.get('KERNEL_SANDBOX_DEV') != '1':
            raise AuthenticationError('development bundle needs explicit KERNEL_SANDBOX_DEV=1')
    else:
        expected = os.environ.get('KERNEL_SANDBOX_BUNDLE_RECEIPT_SHA256')
        if not expected or hashlib.sha256(raw).hexdigest() != expected:
            raise AuthenticationError('caller-held operator receipt digest missing or wrong')
    root = Path(receipt['bundle_root']).absolute()
    if root.is_symlink():
        raise AuthenticationError('bundle root is a symlink')
    root = root.resolve(strict=True)
    if root == repo or repo in root.parents:
        raise AuthenticationError('bundle is inside caller repository')
    if receipt.get('srt_version') != '0.0.81' or receipt.get('patch_id') != PATCH_ID:
        raise AuthenticationError('unreviewed srt or patch identity')
    files = receipt.get('files')
    if not isinstance(files, list) or not files:
        raise AuthenticationError('bundle inventory absent')
    paths = set()
    for row in files:
        name = relative(row['path'])
        if name in paths:
            raise AuthenticationError('duplicate bundle inventory path')
        paths.add(name)
        path = root / name
        if any(parent.is_symlink() for parent in [path, *path.parents] if parent != root.parent):
            raise AuthenticationError('bundle path traverses symlink')
        info = path.lstat()
        if not stat.S_ISREG(info.st_mode) or sha256(path) != row['sha256']:
            raise AuthenticationError('bundle file authentication failed: ' + name)
        if stat.S_IMODE(info.st_mode) != row['mode']:
            raise AuthenticationError('bundle file mode mismatch: ' + name)
    actual = {p.relative_to(root).as_posix() for p in root.rglob('*') if p.is_file() or p.is_symlink()}
    if actual != paths:
        raise AuthenticationError('bundle has missing or uninventoried files')
    if canonical_digest(sorted(files, key=lambda row: row['path'])) != receipt.get('bundle_digest'):
        raise AuthenticationError('bundle inventory digest mismatch')
    if receipt.get('lock_sha256') != LOCK_SHA256 or sha256(root/'package-lock.json') != LOCK_SHA256:
        raise AuthenticationError('transitive dependency lock mismatch')
    patch = relative(receipt['patch_file'])
    if patch not in paths or sha256(root/patch) != receipt.get('patch_sha256'):
        raise AuthenticationError('patch file authentication failed')
    manifest = json.loads((root/Path(patch).parent/'patch-manifest.json').read_text())
    if (manifest.get('patch_id') != PATCH_ID or manifest.get('patch_sha256') != receipt['patch_sha256'] or
            manifest.get('preimages') != receipt.get('patch_preimages') or
            manifest.get('postimages') != receipt.get('patch_postimages')):
        raise AuthenticationError('patch pre/postimage binding mismatch')
    if not manifest.get('preimages') or {r['path'] for r in manifest['preimages']} != {r['path'] for r in manifest['postimages']}:
        raise AuthenticationError('patch changed-file identities incomplete')
    for row in manifest['postimages']:
        name = relative(row['path'])
        if name not in paths or sha256(root/name) != row['sha256']:
            raise AuthenticationError('patch postimage authentication failed')
    node = root / relative(receipt['node']['executable'])
    if receipt['node'].get('version') != 'v24.22.0' or str(node.relative_to(root)) not in paths:
        raise AuthenticationError('Node artifact identity missing')
    # Authenticate all bytes before assessing mutability or invoking Node --version.
    for path in [root, *root.rglob('*')]:
        info = path.lstat()
        if stat.S_IMODE(info.st_mode) & 0o022:
            raise DependencyUnavailable('bundle path is group/world writable')
        if not dev and info.st_uid != 0:
            raise DependencyUnavailable('bundle is not operator-owned')
    if not dev:
        for path in [*root.parents, receipt_path, *receipt_path.parents]:
            info = path.lstat()
            if info.st_uid != 0 or stat.S_IMODE(info.st_mode) & 0o022:
                raise DependencyUnavailable('bundle/receipt ancestry is replaceable')
    return {'receipt': receipt, 'root': root, 'node': str(node),
            'supervisor': str(root/'supervisor.mjs'), 'dev_only': dev,
            'receipt_sha256': hashlib.sha256(raw).hexdigest()}
