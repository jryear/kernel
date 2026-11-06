#!/usr/bin/env python3
"""Apply the authenticated, exact-position kernel srt patch during assembly only."""
import hashlib
import json
from pathlib import Path
import re
import sys

HERE = Path(__file__).resolve().parent
PATCH = HERE / 'kernel-srt-0.0.81-exact-tcp-v1.patch'
MANIFEST = HERE / 'patch-manifest.json'
PREFIX = 'node_modules/@anthropic-ai/sandbox-runtime/dist/sandbox/'

def digest(data):
    return hashlib.sha256(data).hexdigest()

def apply(root):
    root = Path(root).resolve(strict=True)
    manifest = json.loads(MANIFEST.read_text())
    patch = PATCH.read_bytes()
    if digest(patch) != manifest['patch_sha256'] or manifest['patch_id'] != 'kernel-srt-0.0.81-exact-tcp-v1':
        raise ValueError('patch identity mismatch')
    package = root / 'node_modules/@anthropic-ai/sandbox-runtime/package.json'
    if json.loads(package.read_text())['version'] != manifest['srt_version'] or manifest['srt_version'] != '0.0.81':
        raise ValueError('wrong srt version')
    pre = {x['path']: x['sha256'] for x in manifest['preimages']}
    post = {x['path']: x['sha256'] for x in manifest['postimages']}
    if not pre or len(pre) != len(manifest['preimages']) or len(post) != len(manifest['postimages']) or set(pre) != set(post):
        raise ValueError('invalid changed-file manifest')
    originals = {}
    for name, sha in pre.items():
        if not name.startswith(PREFIX) or '/' in name[len(PREFIX):]:
            raise ValueError('invalid patch path')
        target = root / name
        if target.is_symlink() or not target.is_file() or not target.resolve().is_relative_to(root):
            raise ValueError('unsafe patch target')
        data = target.read_bytes()
        if digest(data) != sha:
            raise ValueError('preimage mismatch: ' + name)
        originals[name] = data.decode('utf-8').splitlines(keepends=True)
    lines = patch.decode('utf-8').splitlines(keepends=True)
    output, i = {}, 0
    while i < len(lines):
        if not lines[i].startswith('diff -ruN orig/sandbox/'):
            raise ValueError('unexpected patch header')
        i += 1
        old = lines[i].split('\t', 1)[0].strip(); i += 1
        new = lines[i].split('\t', 1)[0].strip(); i += 1
        if not old.startswith('--- orig/sandbox/') or not new.startswith('+++ new/sandbox/'):
            raise ValueError('invalid patch paths')
        name = PREFIX + old.removeprefix('--- orig/sandbox/')
        if new.removeprefix('+++ new/sandbox/') != name[len(PREFIX):] or name not in originals or name in output:
            raise ValueError('unexpected changed file')
        source = originals[name]; result = []; pos = 0
        while i < len(lines) and lines[i].startswith('@@ '):
            match = re.match(r'@@ -(\d+)(?:,(\d+))? \+(\d+)(?:,(\d+))? @@', lines[i])
            if not match: raise ValueError('invalid hunk header')
            start = int(match[1]) - 1
            if start < pos: raise ValueError('overlapping hunks')
            result.extend(source[pos:start]); pos = start; i += 1
            old_count = new_count = 0
            while i < len(lines) and not lines[i].startswith(('@@ ', 'diff -ruN ')):
                row = lines[i]; i += 1
                if row[:1] in (' ', '-'):
                    if pos >= len(source) or source[pos] != row[1:]: raise ValueError('hunk mismatch: ' + name)
                    pos += 1; old_count += 1
                if row[:1] in (' ', '+'):
                    result.append(row[1:]); new_count += 1
                if row[:1] not in (' ', '-', '+'): raise ValueError('invalid patch line')
            if old_count != int(match[2] or 1) or new_count != int(match[4] or 1):
                raise ValueError('hunk length mismatch')
        result.extend(source[pos:]); data = ''.join(result).encode()
        if digest(data) != post[name]: raise ValueError('postimage mismatch: ' + name)
        output[name] = data
    if set(output) != set(pre): raise ValueError('incomplete patch')
    for name, data in output.items():
        (root / name).write_bytes(data)
    return manifest

if __name__ == '__main__':
    try:
        if len(sys.argv) != 2: raise ValueError('usage: apply_patch.py BUNDLE_ROOT')
        print(json.dumps(apply(sys.argv[1]), sort_keys=True))
    except (OSError, ValueError, KeyError, json.JSONDecodeError) as exc:
        print('patch refused: ' + str(exc), file=sys.stderr)
        sys.exit(1)
