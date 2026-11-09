"""Observed POSIX process-group cleanup, not hostile-process containment.

A private inherited marker supplements descendant sampling for reparented exits.
A hostile descendant can erase that marker and escape between observations;
only sandbox/OS containment can close that boundary. ps failures fail closed.
"""
from __future__ import annotations
import os
import ctypes
import hashlib
import sys
from pathlib import Path
import signal
import subprocess
import tempfile
import time
import uuid


def process_table(marker):
    # Never retain command/environments in receipts: they can contain secrets.
    result = subprocess.run(['ps', 'eww', '-axo', 'pid=,ppid=,pgid=,stat=,lstart=,command='],
                            capture_output=True, text=True, timeout=3)
    if result.returncode:
        raise RuntimeError('process observation failed (ps exit ' + str(result.returncode) + ')')
    table = {}
    for line in result.stdout.splitlines():
        fields = line.split(None, 9)
        if len(fields) < 9:
            raise RuntimeError('incomplete process observation')
        pid, ppid, pgid = map(int, fields[:3])
        table[pid] = {'pid':pid, 'ppid':ppid, 'pgid':pgid, 'state':fields[3],
                      'started':' '.join(fields[4:9]),
                      '_marked':len(fields) > 9 and marker in fields[9].split()}
    if not table:
        raise RuntimeError('empty process observation')
    return table


def executable_path(pid):
    """Best-effort macOS process executable path, never argv/environment."""
    if sys.platform != 'darwin':
        return None
    try:
        lib = ctypes.CDLL('/usr/lib/libproc.dylib', use_errno=True)
        lib.proc_pidpath.argtypes = [ctypes.c_int, ctypes.c_void_p, ctypes.c_uint32]
        lib.proc_pidpath.restype = ctypes.c_int
        buffer = ctypes.create_string_buffer(4096)
        count = lib.proc_pidpath(pid, buffer, len(buffer))
        if count <= 0:
            return None
        path = Path(os.fsdecode(buffer.value)).resolve(strict=True)
        return str(path) if path.is_absolute() else None
    except (OSError, ValueError):
        return None


def executable_identity(pid, started, path=None):
    """Record a sampled path/digest only when PID start identity still agrees."""
    try:
        path = path or executable_path(pid)
        if not path:
            return None
        check = subprocess.run(['/bin/ps', '-p', str(pid), '-o', 'lstart='],
                               capture_output=True, text=True, timeout=2)
        if check.returncode or ' '.join(check.stdout.split()) != ' '.join(started.split()):
            return None
        return {'path': path, 'sha256': hashlib.sha256(Path(path).read_bytes()).hexdigest(),
                'sampling': 'observed-process-not-execution-attestation'}
    except (OSError, subprocess.SubprocessError):
        return None


def public(row):
    return {key:value for key,value in row.items() if not key.startswith('_')}


def execute(argv, root, env, timeout):
    errors, known, executable_cache = [], {}, {}
    timed_out = False
    marker = 'VERIFY_PROCESS_TOKEN=' + uuid.uuid4().hex
    env = {**env, 'VERIFY_PROCESS_TOKEN': marker.split('=',1)[1]}
    proc = None
    survivors = []
    observed = []

    def observe():
        table = process_table(marker)
        family = {proc.pid}
        while True:
            more = {pid for pid,row in table.items() if row['ppid'] in family}
            if more.issubset(family): break
            family.update(more)
        for pid,row in table.items():
            if pid in family or row['pgid'] == proc.pid or row['_marked']:
                key = (pid, row['started'])
                prior = known.get(key)
                identities = list(prior.get('executables', [])) if prior else []
                path = executable_path(pid)
                cache_key = (pid, row['started'], path)
                if path and cache_key not in executable_cache:
                    executable_cache[cache_key] = executable_identity(pid, row['started'], path)
                identity = executable_cache.get(cache_key)
                if identity and identity not in identities:
                    identities.append(identity)
                row['executables'] = identities
                known[key] = row
        return table

    with tempfile.TemporaryFile() as stdout, tempfile.TemporaryFile() as stderr:
        try:
            proc = subprocess.Popen(argv, shell=False, cwd=root, env=env,
                                    stdout=stdout, stderr=stderr, start_new_session=True)
            deadline = time.monotonic() + timeout
            while True:
                try: observe()
                except (OSError, ValueError, RuntimeError, subprocess.SubprocessError) as error:
                    errors.append(str(error))
                    break
                if proc.poll() is not None: break
                if time.monotonic() >= deadline:
                    timed_out = True
                    break
                time.sleep(.02)
        finally:
            if proc is not None:
                try:
                    before = observe()
                    # These descendants survived outside the group boundary. Even
                    # if remediation kills them, their escape invalidates evidence.
                    for (pid, started), row in known.items():
                        current = before.get(pid)
                        if (current and current['started'] == started and not current['state'].startswith('Z')
                                and current['pgid'] != proc.pid):
                            survivors.append({**public(current), 'reason':'escaped process group'})
                except (OSError, ValueError, RuntimeError, subprocess.SubprocessError) as error:
                    errors.append('cleanup observation: ' + str(error))
                try: os.killpg(proc.pid, signal.SIGKILL)
                except ProcessLookupError: pass
                except OSError as error: errors.append('kill process group: ' + str(error))
                try: proc.wait(timeout=2)
                except subprocess.TimeoutExpired: errors.append('check leader did not exit after cleanup')
                try:
                    after = observe()
                    end = time.monotonic() + .5
                    while any(r['pgid'] == proc.pid and not r['state'].startswith('Z') for r in after.values()) and time.monotonic() < end:
                        time.sleep(.02)
                        after = observe()
                    for (pid, started), row in known.items():
                        current = after.get(pid)
                        if current and current['started'] == started and not current['state'].startswith('Z'):
                            if not any(s['pid']==pid and s['started']==started for s in survivors):
                                survivors.append({**public(current), 'reason':'alive after group cleanup'})
                    observed = [public(row) for row in known.values()]
                    # Best-effort remediation of identified escaped processes only.
                    for survivor in survivors:
                        current = after.get(survivor['pid'])
                        if current and current['started'] == survivor['started'] and current['pgid'] != proc.pid:
                            try: os.kill(current['pid'], signal.SIGKILL)
                            except ProcessLookupError: pass
                            except OSError as error: errors.append('kill escaped process: ' + str(error))
                except (OSError, ValueError, RuntimeError, subprocess.SubprocessError) as error:
                    errors.append('post-cleanup observation: ' + str(error))
        stdout.seek(0)
        stderr.seek(0)
        output = (stdout.read() + stderr.read()).decode('utf-8', 'replace')
    cleanup = {'pgid':proc.pid, 'complete':not errors and not survivors,
               'timed_out':timed_out, 'survivors':survivors, 'errors':errors,
               'observed':observed, 'boundary':'observed POSIX group and attributed descendants'}
    return (99 if timed_out else proc.returncode), output, cleanup
