"""Schema 2 fixed Git snapshots and observed source integrity boundaries.

Trusted frozen harness and external runtime correctness remain assumptions.
"""
from __future__ import annotations
import fnmatch
import hashlib
import json
import os
import re
import shutil
import stat
import subprocess
import tempfile
from pathlib import Path, PurePosixPath

ASSURANCE = 'schema2-evidence-validity'
RUNTIME = re.compile(r'(?:python|python3|python3\.[0-9]+|node|bash|sh)\Z')


def git_bytes(repo, *args):
    result = subprocess.run(['git', *args], cwd=repo, capture_output=True)
    if result.returncode:
        raise ValueError('git operation failed: ' + result.stderr.decode('utf-8', 'replace').strip())
    return result.stdout


def git_text(repo, *args):
    return git_bytes(repo, *args).decode('utf-8').strip()


def string(value, label):
    if not isinstance(value, str) or not value or value != value.strip():
        raise ValueError(label + ' must be a nonempty literal string without surrounding whitespace')
    return value


def strings(value, label, nonempty=False, unique=False):
    if not isinstance(value, list) or (nonempty and not value):
        raise ValueError(label + ' must be a string array')
    rows = [string(item, label) for item in value]
    if unique and len(rows) != len(set(rows)):
        raise ValueError(label + ' must be unique')
    return rows


def relative(value):
    string(value, 'repository path')
    p = PurePosixPath(value)
    if p.is_absolute() or any(part in ('', '.', '..') for part in value.split('/')) or any(c in value for c in '*?[') or '\\' in value:
        raise ValueError('unsupported repository path: ' + value)
    return value


def validate_spec(spec, legacy_validate):
    if type(spec.get('spec_version')) is not int or spec['spec_version'] != 2:
        raise ValueError('spec_version must be integer 2')
    # Reuse historical top/scope validation on a translated schema1 view, then
    # retain only structured schema2 fields; never execute translated commands.
    converted = dict(spec)
    converted['spec_version'] = 1
    if 'sandbox' in converted:
        from kernel_sandbox import validate_declaration
        validate_declaration(converted.pop('sandbox'))
    raw_checks = spec.get('checks', [])
    if not isinstance(raw_checks, list):
        raise ValueError('checks must be an array')
    converted['checks'] = []
    checks = []
    for raw in raw_checks:
        if not isinstance(raw, dict):
            raise ValueError('check must be a table')
        allowed = {'name', 'kind', 'timeout', 'argv', 'entry', 'chain', 'evidence', 'assertions', 'baseline_failures'}
        if set(raw) - allowed:
            raise ValueError('unknown schema2 check fields: ' + ', '.join(sorted(set(raw) - allowed)))
        name = string(raw.get('name'), 'name')
        kind = raw.get('kind')
        if kind not in ('acceptance', 'adversarial', 'regression'):
            raise ValueError('schema2 check kind required')
        timeout = raw.get('timeout')
        if type(timeout) is not int or timeout <= 0:
            raise ValueError('timeout must be a positive integer')
        argv = strings(raw.get('argv'), 'argv', nonempty=True)
        entry = relative(raw.get('entry'))
        chain = strings(raw.get('chain'), 'chain', nonempty=True, unique=True)
        for path in chain:
            relative(path)
        if entry not in chain:
            raise ValueError('entry must be in chain')
        if argv[0] in (entry, './' + entry):
            position = 0
        else:
            if not RUNTIME.fullmatch(Path(argv[0]).name):
                raise ValueError('unsupported runtime grammar')
            position = 2 if len(argv) > 1 and argv[1] == '--' else 1
            if len(argv) <= position or argv[position] != entry:
                raise ValueError('declared entry is not the executed script')
        evidence = strings(raw.get('evidence'), 'evidence', nonempty=True)
        if not any(fnmatch.fnmatch(entry, pattern) for pattern in evidence):
            raise ValueError('entry must belong to evidence')
        assertions = strings(raw.get('assertions'), 'assertions', nonempty=True, unique=True)
        failures = strings(raw.get('baseline_failures'), 'baseline_failures', unique=True)
        if not set(failures).issubset(assertions) or (kind == 'acceptance' and not failures) or (kind == 'regression' and failures):
            raise ValueError('invalid baseline failure set')
        check = {**raw, '_entry_position': position}
        checks.append(check)
        converted['checks'].append({'name': name, 'kind': kind, 'timeout': timeout,
                                    'cmd': 'structured-schema2-placeholder', 'evidence': evidence})
    worktree = spec.get('worktree', {})
    service = spec.get('service', {})
    if not isinstance(worktree, dict) or set(worktree) - {'link'}:
        raise ValueError('schema2 supports only worktree.link, no setup')
    if not isinstance(service, dict) or service:
        raise ValueError('schema2 service lifecycle is unsupported')
    for link in strings(worktree.get('link', []), 'worktree.link', unique=True):
        relative(link)
    _, policy = legacy_validate(converted)
    return checks, policy


def manifest(repo, commit):
    rows, objects = [], {}
    for item in git_bytes(repo, 'ls-tree', '-rz', commit).split(b'\0'):
        if not item:
            continue
        metadata, raw_path = item.split(b'\t', 1)
        mode, kind, oid = metadata.decode('ascii').split()
        path = raw_path.decode('utf-8')  # invalid UTF8 paths are unsupported
        if kind != 'blob' or mode not in ('100644', '100755', '120000'):
            raise ValueError('unsupported tracked type/gitlink: ' + path)
        blob = git_bytes(repo, 'cat-file', 'blob', oid)
        rows.append({'path': path, 'mode': mode, 'sha256': hashlib.sha256(blob).hexdigest()})
        objects[path] = (mode, oid)
    rows.sort(key=lambda row: row['path'])
    digest = hashlib.sha256(json.dumps(rows, sort_keys=True, separators=(',', ':'), ensure_ascii=False).encode('utf-8')).hexdigest()
    return {'commit': commit, 'tree': git_text(repo, 'rev-parse', commit + '^{tree}'), 'manifest_sha256': digest}, rows, objects


def clean(repo):
    return not git_bytes(repo, 'status', '--porcelain=v1', '-z', '--untracked-files=all')


def safe_regular(objects, path):
    if path not in objects or objects[path][0] not in ('100644', '100755'):
        raise ValueError('declared evidence/chain must be a tracked regular file: ' + path)
    parts = PurePosixPath(path).parts
    for i in range(1, len(parts)):
        if '/'.join(parts[:i]) in objects:
            raise ValueError('evidence/chain ancestor is not a directory')


def external_runtime(repo, argv0):
    if '/' in argv0 and not Path(argv0).is_absolute():
        raise ValueError('runtime cannot be a repository-relative executable')
    resolved = shutil.which(argv0)
    if resolved:
        try:
            Path(resolved).resolve().relative_to(repo.resolve())
        except ValueError:
            return str(Path(resolved).absolute())
        raise ValueError('runtime must be external to repository')
    # Availability is checked at execution and classified as harness failure.


def integrity(root, binding, rows, objects):
    try:
        if git_text(root, 'rev-parse', 'HEAD') != binding['commit']:
            return 'snapshot HEAD changed'
        expected_index = {path: (mode, oid) for path, (mode, oid) in objects.items()}
        index = {}
        for item in git_bytes(root, 'ls-files', '--stage', '-z').split(b'\0'):
            if not item:
                continue
            metadata, raw_path = item.split(b'\t', 1)
            mode, oid, stage = metadata.decode('ascii').split()
            if stage != '0':
                return 'snapshot index has conflicts'
            index[raw_path.decode('utf-8')] = (mode, oid)
        if index != expected_index:
            return 'snapshot index changed'
        for row in rows:
            path = root / row['path']
            for parent in path.parents:
                if parent == root:
                    break
                info_parent = parent.lstat()
                if not stat.S_ISDIR(info_parent.st_mode):
                    return 'tracked ancestor type changed: ' + row['path']
            info = path.lstat()
            if row['mode'] == '120000':
                if not stat.S_ISLNK(info.st_mode):
                    return 'tracked symlink type changed: ' + row['path']
                content = os.fsencode(os.readlink(path))
            else:
                if not stat.S_ISREG(info.st_mode):
                    return 'tracked type changed: ' + row['path']
                # Any execute bit changes the physical executable mode.
                mode = '100755' if info.st_mode & 0o111 else '100644'
                if mode != row['mode']:
                    return 'tracked executable mode changed: ' + row['path']
                content = path.read_bytes()
            if hashlib.sha256(content).hexdigest() != row['sha256']:
                return 'tracked content changed: ' + row['path']
        if not clean(root):
            return 'snapshot has dirty/untracked input'
    except (OSError, ValueError, UnicodeError) as error:
        return 'snapshot integrity unavailable: ' + str(error)
    return None


def snapshot(repo, commit, links, objects):
    parent = Path(tempfile.mkdtemp(prefix='verify-snapshot-'))
    root = parent / 'tree'
    try:
        git_bytes(repo, '-c', 'core.autocrlf=false', 'worktree', 'add', '--detach', str(root), commit)
        # Ensure fixed blob bytes independent of checkout attributes/filters.
        for path, (mode, oid) in objects.items():
            if mode in ('100644', '100755'):
                target = root / path
                target.write_bytes(git_bytes(repo, 'cat-file', 'blob', oid))
                target.chmod(0o755 if mode == '100755' else 0o644)
        for link in links:
            src, dst = repo / link, root / link
            if src.exists():
                if dst.exists() or dst.is_symlink():
                    raise ValueError('external link destination already exists')
                dst.parent.mkdir(parents=True, exist_ok=True)
                dst.symlink_to(src.resolve(), target_is_directory=src.is_dir())
        return root.resolve()
    except Exception:
        git_bytes(repo, 'worktree', 'remove', '--force', str(root)) if root.exists() else None
        shutil.rmtree(parent, ignore_errors=True)
        raise


def run_tree(root, phase, checks, binding, rows, objects, sandbox_context=None):
    from kernel_report import run_check
    results = []
    for check in checks:
        error = integrity(root, binding, rows, objects)
        if error:
            return results, error
        active = check if sandbox_context is None else {**check, '_sandbox_context': {**sandbox_context, 'tracked': objects}}
        result = run_check(root, active, phase)
        results.append(result)
        error = integrity(root, binding, rows, objects)
        if error:
            return results, error
    return results, integrity(root, binding, rows, objects)


def verify(args, repo, base, spec, raw_spec, spec_rel, api):
    from kernel_report import __file__ as report_file
    from kernel_process import __file__ as process_file
    component_paths = {'verify.py': Path(api['__file__']), 'kernel_runtime.py': Path(__file__), 'kernel_report.py': Path(report_file), 'kernel_process.py': Path(process_file)}
    component_digests = {name: hashlib.sha256(path.read_bytes()).hexdigest() for name, path in component_paths.items()}
    package_binding = {'components': component_digests, 'manifest_sha256': hashlib.sha256(json.dumps(component_digests, sort_keys=True, separators=(',', ':')).encode('utf-8')).hexdigest(), 'boundary': 'schema2-start-loaded-components'}
    checks, policy = validate_spec(spec, api['validate_spec_legacy'])
    review = api['load_review_metadata'](args.review_metadata)
    candidate = args._resolved_candidate
    base_binding, base_rows, base_objects = manifest(repo, base)
    candidate_binding, candidate_rows, candidate_objects = manifest(repo, candidate)
    protected = {spec_rel}
    for check in checks:
        for pattern in check['evidence']:
            found = [p for p in base_objects if fnmatch.fnmatch(p, pattern)]
            if not found:
                raise ValueError('declared evidence missing: ' + pattern)
            for path in found:
                safe_regular(base_objects, path)
            protected.update(found)
        for path in check['chain']:
            safe_regular(base_objects, path)
        protected.update(check['chain'])
        if check['_entry_position'] == 0 and base_objects[check['entry']][0] != '100755':
            raise ValueError('direct entry must be executable')
        if check['_entry_position']:
            check['_runtime_executable'] = external_runtime(repo, check['argv'][0])
    links = spec.get('worktree', {}).get('link', [])
    for link in links:
        if any(p == link or p.startswith(link + '/') or link.startswith(p + '/') for p in set(base_objects) | set(candidate_objects) | protected):
            raise ValueError('external link overlaps tracked source/evidence')
    log = args.log.resolve() if args.log else Path(tempfile.mkdtemp(prefix='verify-claims-')) / 'claims.jsonl'
    if api['repo_relative'](repo, log) is not None:
        raise ValueError('schema2 log must be outside caller repository')
    sandbox_context = None
    if os.environ.get('VERIFY_SANDBOX') == '1':
        from kernel_sandbox_runtime import load_context
        sandbox_context = load_context(spec, repo, log, candidate_objects, links)
        sandbox_context['contract_sha256'] = hashlib.sha256(raw_spec).hexdigest()
    if not clean(repo):
        state = 'BASELINE_NOT_READY' if args.baseline else 'UNVERIFIABLE'
        print(f'{state}  {spec["id"]}  assurance={ASSURANCE}: candidate input must be clean committed source')
        return 2
    caller_error = integrity(repo, candidate_binding, candidate_rows, candidate_objects)
    if caller_error:
        print(f'{"BASELINE_NOT_READY" if args.baseline else "UNVERIFIABLE"}  assurance={ASSURANCE}: {caller_error}')
        return 2
    changed = sorted(p.decode('utf-8') for p in git_bytes(repo, 'diff', '--name-only', '-z', base, candidate).split(b'\0') if p)
    verifier_rel = api['repo_relative'](repo, Path(api['__file__']).resolve())
    if verifier_rel:
        protected.add(verifier_rel)
    protected_hits = [p for p in changed if p in protected or api['matches'](p, policy['protected'])]
    out_of_scope = [p for p in changed if p not in protected_hits and (api['matches'](p, policy['exclude']) or not api['matches'](p, policy['include']))]
    mutable_tests = [p for p in changed if api['matches'](p, policy['test_files']) and p not in protected]
    bypasses = []
    for path in mutable_tests:
        diff = git_bytes(repo, 'diff', '-U0', base, candidate, '--', path).decode('utf-8', 'replace')
        for line in diff.splitlines():
            if line.startswith('+') and not line.startswith('+++') and api['BYPASS'].search(line[1:]):
                bypasses.append({'file': path, 'line': line[1:].strip()[:200]})
    roots = []
    base_results, candidate_results = [], []
    base_error = candidate_error = None
    try:
        root = snapshot(repo, base, links, base_objects)
        roots.append((root, 'base', base_binding, base_rows, base_objects))
        base_results, base_error = run_tree(root, 'base', checks, base_binding, base_rows, base_objects, sandbox_context)
        if not args.baseline:
            root = snapshot(repo, candidate, links, candidate_objects)
            roots.append((root, 'candidate', candidate_binding, candidate_rows, candidate_objects))
            candidate_results, candidate_error = run_tree(root, 'candidate', checks, candidate_binding, candidate_rows, candidate_objects, sandbox_context)
        caller_error = integrity(repo, candidate_binding, candidate_rows, candidate_objects)
    except (OSError, ValueError, subprocess.SubprocessError) as error:
        candidate_error = 'snapshot/check setup unavailable: ' + str(error)
    finally:
        for root, phase, binding, rows, objects in roots:
            final_error = integrity(root, binding, rows, objects)
            if final_error:
                if phase == 'base':
                    base_error = final_error
                else:
                    candidate_error = final_error
            if not args.keep_worktree:
                api['cleanup_worktree'](repo, root)
    baseline_reasons = []
    if base_error:
        baseline_reasons.append(base_error)
    by_name = {row['name']: row for row in base_results}
    for check in checks:
        row = by_name.get(check['name'])
        if row is None or row['harness_error']:
            baseline_reasons.append('base assertion evidence unavailable: ' + check['name'])
        elif set(row['failed_assertions']) != set(check['baseline_failures']):
            baseline_reasons.append('base failed assertion set differs from declared baseline: ' + check['name'])
    ready = not baseline_reasons and not candidate_error and not caller_error
    contradicted, unavailable, warnings = [], list(baseline_reasons), []
    if candidate_error:
        unavailable.append(candidate_error)
    if caller_error:
        unavailable.append('caller identity changed: ' + caller_error)
    if not args.baseline:
        for row in candidate_results:
            if row['harness_error']:
                unavailable.append('candidate assertion evidence unavailable: ' + row['name'])
            elif not row['passed'] and not candidate_error:
                contradicted.append('failed on candidate: ' + row['name'])
        if len(candidate_results) != len(checks):
            unavailable.append('candidate checks incomplete')
        if protected_hits:
            contradicted.append('protected evidence/path changed: ' + ', '.join(protected_hits))
        if out_of_scope:
            contradicted.append('out-of-scope changes: ' + ', '.join(out_of_scope))
        if bypasses:
            (contradicted if policy['bypass_policy'] == 'fail' else warnings).append('test bypass patterns added')
    if args.baseline:
        verdict = 'baseline_ready' if ready else 'baseline_not_ready'
        code = 0 if ready else 2
    else:
        # Incomplete evidence (including cleanup) cannot certify or contradict.
        # Deterministic source/scope violations remain recorded in reasons.
        verdict = 'unverifiable' if unavailable else 'contradicted' if contradicted else 'supported'
        if sandbox_context is not None:
            from kernel_sandbox import classify_sandbox_evidence
            typed = [fact for row in candidate_results
                     for fact in row.get('sandbox_receipt', {}).get('decision', {}).get('facts', [])]
            decision = classify_sandbox_evidence({
                'schema': 1, 'integrity': {'available': True, 'changes': typed},
                'execution': {'complete': not unavailable},
                'cleanup': {'complete': not unavailable, 'survivors': []},
                'assertions': {'complete': not unavailable, 'failed': contradicted},
                'diagnostics': {'mode': 'disabled', 'state': 'disabled', 'semantics': 'advisory-one-directional-v1'}})
            verdict = decision['verdict']
        code = {'supported': 0, 'contradicted': 1, 'unverifiable': 2}[verdict]
    raw_claim = args.raw_claim_file.read_text(encoding='utf-8') if args.raw_claim_file else None
    record = {'schema': 2, 'at': api['now_utc'](), 'verifier_version': api['VERIFIER_VERSION'],
              'verifier_sha256': component_digests['verify.py'], 'verifier_package_binding': package_binding,
              'assurance': ASSURANCE, 'task_id': spec['id'], 'project': spec['project'], 'goal': spec['goal'],
              'spec_path': str(repo / spec_rel), 'spec_source': 'base', 'spec_sha256': hashlib.sha256(raw_spec).hexdigest(),
              'base_ref': args.base, 'merge_base': base, 'head': candidate, 'dirty_before_log': False,
              'claim': args.claim or raw_claim or '', 'raw_claim': raw_claim,
              'raw_claim_captured_at': api['now_utc']() if raw_claim is not None else None,
              'implementer_model': args.implementer_model, 'verifier_access': args.verifier_access,
              'verifier_inspection_reported': args.verifier_inspection_reported, 'contract_review': review,
              'source_binding': {'base': base_binding, 'candidate': candidate_binding, 'candidate_snapshot': not args.baseline,
                                 'clean_before': True, 'unchanged_after': not (base_error or candidate_error or caller_error)},
              'external_inputs': [{'path': p, 'target': str((repo / p).resolve())} for p in links],
              'runtime_inputs': [{'check': c['name'], 'declared': c['argv'][0], 'resolved': c.get('_runtime_executable')} for c in checks if c['_entry_position']],
              'changed_files': changed, 'protected_changes': protected_hits, 'out_of_scope': out_of_scope,
              'mutable_test_changes': mutable_tests, 'bypasses': bypasses, 'base_checks': base_results,
              'candidate_checks': candidate_results, 'verdict': verdict, 'reasons': contradicted + unavailable, 'warnings': warnings,
              'sandbox_receipt_corrections': (sandbox_context or {}).get('diagnostic_corrections', [])}
    log.parent.mkdir(parents=True, exist_ok=True)
    with log.open('a', encoding='utf-8') as handle:
        handle.write(json.dumps(record, ensure_ascii=False) + '\n')
    state = {'baseline_ready': 'BASELINE_READY', 'baseline_not_ready': 'BASELINE_NOT_READY'}.get(verdict, verdict.upper())
    print(f'{state}  {spec["id"]}  assurance={ASSURANCE}')
    api['print_results']('base', base_results)
    api['print_results']('candidate', candidate_results)
    for reason in record['reasons']:
        print('  - ' + reason)
    print('  logged -> ' + str(log))
    return code
