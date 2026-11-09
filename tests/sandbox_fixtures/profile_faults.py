"""Reviewed input faults for the future read-only profile validator.

These functions mutate test input only. They neither validate a profile nor
change product policy, and no mutated profile is launched by this fixture.
The disposable adapter calls the production validator on the altered bytes.
"""
import re

FAULTS = (
    'missing_rule', 'additional_rule', 'duplicate_rule', 'malformed_rule',
    'broadened_host', 'ip_transport', 'wildcard_port', 'local_outbound',
    'unaccounted_proxy', 'unix_socket', 'unexpected_default',
    'inspection_failure', 'inspection_unavailable', 'unknown_syntax',
    'include', 'macro', 'operation_wildcard', 'outside_network_section',
    'nonnetwork_template',
)


def alter_profile(profile, fault, port=12345):
    if fault not in FAULTS or not isinstance(profile, str):
        raise RuntimeError('frozen profile fault input unavailable')
    outbound = re.compile(r'\(allow\s+network-outbound\s+\(remote\s+tcp\s+"localhost:' + str(port) + r'"\)\s*\)')
    match = outbound.search(profile)
    if not match:
        raise RuntimeError('declared TCP rule absent before fault injection')
    rule = match.group()
    used = {int(value) for value in re.findall(r':([0-9]+)"', profile)}
    other = next(value for value in range(65535, 0, -1) if value not in used)
    suffix = {
        'additional_rule': f'(allow network-bind (local tcp "*:{other}"))',
        'unaccounted_proxy': f'(allow network-outbound (remote tcp "localhost:{other}"))',
        'unix_socket': '(allow network-outbound (remote unix-socket (path-regex #"^/")))',
        'unknown_syntax': '(kernel-unknown-network-rule "synthetic")',
        'include': '(include "system.sb")',
        'macro': '(define kernel_fixture_network (remote tcp "localhost:12345"))',
        'operation_wildcard': '(allow network*)',
        'outside_network_section': f'; after all generated sections\n(allow network-outbound (remote tcp "localhost:{other}"))',
        'nonnetwork_template': '(allow file-read* (subpath "/synthetic-unreviewed-template"))',
    }
    if fault in suffix:
        return profile + '\n' + suffix[fault] + '\n'
    if fault in ('inspection_failure', 'inspection_unavailable'):
        return profile  # The adapter raises a real inspection error instead.
    if fault == 'unexpected_default':
        changed, count = re.subn(r'\(deny\s+default\b', '(allow default', profile, count=1)
        if count != 1:
            raise RuntimeError('default-deny expression absent before fault injection')
        return changed
    replacement = {
        'missing_rule': '',
        'duplicate_rule': rule + '\n' + rule,
        'malformed_rule': rule[:-1],
        'broadened_host': rule.replace('localhost:', '*:'),
        'ip_transport': re.sub(r'\btcp\b', 'ip', rule),
        'wildcard_port': rule.replace(':' + str(port) + '"', ':*"'),
        'local_outbound': re.sub(r'\bremote\b', 'local', rule),
    }[fault]
    return profile[:match.start()] + replacement + profile[match.end():]
