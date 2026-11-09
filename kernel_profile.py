"""Fail-closed, read-only inspection of a pinned srt macOS profile.

The caller must supply a reference generated independently by the authenticated
pinned generator with the same validated filesystem policy, command identity and
verified proxies, but with application ports empty. It is unsafe to derive the
reference from the profile being inspected.
"""
from __future__ import annotations
import hashlib
import re

VALIDATOR_ID = 'kernel-srt-profile-validator-v1'
GENERATOR_SHA256 = '9da44b6ea3c1bb3f90052118b237d328dd38c2d0ce2a70ef6160dd81a1d95400'
_RULE = re.compile(r'^\(allow (network-bind|network-inbound|network-outbound) \((local|remote) tcp "(\*|localhost):([1-9][0-9]*)"\)\)$')

def _expressions(source):
    """Parse every top-level expression, preserving source spans and strings."""
    result = []
    stack = []
    start = None
    string = False
    escape = False
    comment = False
    for i, char in enumerate(source):
        if comment:
            if char == '\n': comment = False
            continue
        if string:
            if escape: escape = False
            elif char == '\\': escape = True
            elif char == '"': string = False
            continue
        if char == ';': comment = True
        elif char == '"': string = True
        elif char == '(':
            if not stack: start = i
            stack.append(i)
        elif char == ')':
            if not stack: raise ValueError('unmatched closing parenthesis')
            stack.pop()
            if not stack:
                result.append((start, i + 1, source[start:i + 1]))
        elif not stack and not char.isspace():
            raise ValueError('unrecognized top-level syntax')
    if stack or string: raise ValueError('unterminated expression or string')
    return result

def _expected(context):
    ports = context['localhost_ports']
    proxies = context['proxies']
    if not isinstance(ports, list) or ports != sorted(set(ports)) or any(type(p) is not int or not 1 <= p <= 65535 for p in ports):
        raise ValueError('invalid declared ports')
    proxy_ports = []
    if not isinstance(proxies, list): raise ValueError('invalid proxy identities')
    roles = set()
    for proxy in proxies:
        if not isinstance(proxy, dict) or set(proxy) != {'role','host','port','transport','pid','started','ready','ownership_verified'}:
            raise ValueError('invalid proxy identity')
        port = proxy['port']
        if (proxy['role'] not in ('http','socks') or proxy['role'] in roles or
            proxy['host'] not in ('127.0.0.1','::1') or proxy['transport'] != 'tcp' or
            type(port) is not int or not 1 <= port <= 65535 or port in ports or
            type(proxy['pid']) is not int or proxy['pid'] <= 0 or not proxy['started'] or
            proxy['ready'] is not True or proxy['ownership_verified'] is not True):
            raise ValueError('unverified or overlapping proxy')
        roles.add(proxy['role']); proxy_ports.append(port)
    rules = []
    for port in ports:
        rules += [('network-bind','local','tcp','*',port), ('network-inbound','local','tcp','*',port), ('network-outbound','remote','tcp','localhost',port)]
    for port in sorted(set(proxy_ports)):
        rules.append(('network-outbound','remote','tcp','localhost',port))
    return rules

def _inspect(profile, expected):
    expressions = _expressions(profile)
    grants = []; spans = []; defaults = []; sockets = []
    for start, end, expression in expressions:
        head = re.match(r'^\(\s*([^\s()]+)', expression)
        if not head: raise ValueError('invalid expression')
        name = head.group(1)
        if name in ('include','define') or name not in ('version','allow','deny'):
            raise ValueError('unknown or forbidden profile expression: ' + name)
        if re.match(r'^\(\s*(allow|deny)\s+default\b', expression): defaults.append(expression)
        if re.search(r'\bsystem-socket(?:[-*]|\b)', expression): sockets.append(expression)
        if re.search(r'\bnetwork(?:[-*]|\b)', expression):
            match = _RULE.fullmatch(expression)
            if not match: raise ValueError('unrecognized network expression')
            grants.append((match[1],match[2],'tcp',match[3],int(match[4])))
            if start and profile[start-1] != '\n': raise ValueError('network grant not on its own line')
            if end < len(profile) and profile[end] != '\n': raise ValueError('network grant not on its own line')
            spans.append((start, end + (end < len(profile))))
    if sockets != ['(allow system-socket (require-all (socket-domain AF_SYSTEM) (socket-protocol 2)))']:
        raise ValueError('unexpected system socket authority')
    if len(defaults) != 1 or not re.match(r'^\(deny\s+default(?:\s|\))', defaults[0]):
        raise ValueError('default deny missing or ambiguous')
    if sorted(grants) != sorted(expected): raise ValueError('network grants differ from declaration and verified proxies')
    parts = []; cursor = 0
    for start, end in spans: parts.append(profile[cursor:start]); cursor = end
    parts.append(profile[cursor:])
    return grants, ''.join(parts)

def validate_generated_profile(profile, context):
    result = {'validator_id': VALIDATOR_ID, 'exact_match': False, 'inspected_profile': profile, 'errors': []}
    try:
        if not isinstance(profile, str) or not isinstance(context, dict): raise ValueError('profile or context unavailable')
        if context.get('generator_sha256') != GENERATOR_SHA256: raise ValueError('unrecognized generator postimage')
        reference = context.get('reference_profile')
        if not isinstance(reference, str): raise ValueError('independent reference profile unavailable')
        expected = _expected(context)
        proxy_only = _expected({'localhost_ports': [], 'proxies': context['proxies']})
        grants, actual_template = _inspect(profile, expected)
        _, reference_template = _inspect(reference, proxy_only)
        if actual_template != reference_template: raise ValueError('complete non-network template mismatch')
        result['effective_network_rules'] = [dict(zip(('operation','selector','transport','host','port'), rule)) for rule in grants]
        result['exact_match'] = True
    except (ValueError, KeyError, TypeError, UnicodeError) as error:
        result['errors'].append(str(error))
    return result
