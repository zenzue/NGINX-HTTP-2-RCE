#!/usr/bin/env -S uv run --script
# /// script
# requires-python = ">=3.9"
# dependencies = []
# ///
"""Non-destructive assessment for CVE-2026-123007 and CVE-2026-123633.
Only performs one TLS handshake per target; optionally reads local NGINX/Docker metadata.
Run with uv (Python >=3.9). No third-party libraries.
"""
import argparse
import concurrent.futures
import datetime
import json
import re
import shutil
import socket
import ssl
import subprocess
import sys
from urllib.parse import urlsplit

CVES = {'CVE-2026-123007': (1, 9, 5), 'CVE-2026-123633': (1, 19, 7)}
SOURCES = [
    'https://nginx.org/en/security_advisories.html',
    'https://www.wiz.io/blog/nginx-http2-rce-vulnerabilities',
    'https://github.com/sfewer-r7/CVE-2026-123007',
]

def run(cmd, timeout=8):
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, check=False)
        return {'ok': p.returncode == 0, 'text': (p.stdout + '\n' + p.stderr).strip()[:300000]}
    except (OSError, subprocess.TimeoutExpired) as e:
        return {'ok': False, 'text': str(e)}

def parse_target(text):
    text = text.strip()
    if not text or text.startswith('#'):
        return None
    if '://' not in text:
        text = 'https://' + text
    u = urlsplit(text)
    if u.scheme != 'https' or not u.hostname or u.username or u.password:
        raise ValueError('only HTTPS hostnames/IPs are supported')
    if u.path not in ('', '/') or u.query or u.fragment:
        raise ValueError('supply only host and optional port, no paths/query')
    port = u.port or 443
    if not 1 <= port <= 65535:
        raise ValueError('invalid port')
    return {'target': text, 'hostname': u.hostname, 'port': port}

def remote_check(target, timeout, insecure=False):
    res = dict(target)
    res.update({'mode': 'remote', 'status': 'UNKNOWN', 'alpn': None,
                'cves': {k: 'UNKNOWN' for k in CVES},
                'notes': ['Remote ALPN alone cannot establish the origin NGINX version or patch status.']})
    try:
        ctx = ssl.create_default_context()
        if insecure:
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
        ctx.set_alpn_protocols(['h2', 'http/1.1'])
        with socket.create_connection((target['hostname'], target['port']), timeout=timeout) as sock:
            sock.settimeout(timeout)
            with ctx.wrap_socket(sock, server_hostname=target['hostname']) as tls:
                res['alpn'] = tls.selected_alpn_protocol()
                res['tls_version'] = tls.version()
        if res['alpn'] == 'h2':
            res['status'] = 'EXPOSED_H2_VERSION_UNKNOWN'
            res['notes'].append('The tested TLS endpoint negotiates h2; inspect the serving binary and its patched package.')
        else:
            res['status'] = 'NO_H2_ON_TESTED_TLS_ENDPOINT'
            res['notes'].append('No h2 negotiated at this endpoint. Other hosts/listeners/origin routes may differ.')
    except Exception as e:
        res['status'] = 'CHECK_FAILED'
        res['error'] = '{}: {}'.format(type(e).__name__, e)
    return res

def nginx_version(text):
    # Includes 'nginx version: openresty/1.27.1.2' and 'nginx/1.30.6'.
    m = re.search(r'(?:nginx|openresty|tengine|angie)[/ ](\d+)\.(\d+)\.(\d+)(?:\.(\d+))?', text, re.I)
    if not m:
        return None
    return {'full': m.group(0), 'numbers': [int(x) for x in m.group(1, 2, 3)],
            'flavor': m.group(0).split('/')[0].split(' ')[0].lower()}

def evaluate_version(info, vendor_patched=False):
    if not info:
        return {c: 'UNKNOWN_VERSION' for c in CVES}
    if vendor_patched:
        return {c: 'VENDOR_PATCH_CONFIRMED_BY_OPERATOR' for c in CVES}
    version = tuple(info['numbers'])
    if info['flavor'] != 'nginx':
        return {c: 'FORK_REQUIRES_VENDOR_ADVISORY' for c in CVES}
    # Upstream fixes are only assured on supported fixed branches; older unsupported
    # versions remain affected, even when numerically below 1.30.7.
    fixed = (version[0:2] == (1, 30) and version >= (1, 30, 7)) or (version[0:2] == (1, 31) and version >= (1, 31, 9)) or version >= (1, 32, 0)
    return {c: ('FIXED_UPSTREAM' if fixed else 'AFFECTED_UPSTREAM_VERSION' if version >= start else 'OUTSIDE_KNOWN_RANGE') for c, start in CVES.items()}

def config_flags(config):
    # Lightweight signals, not a full parser of nested/included NGINX configuration.
    lines = re.sub(r'#[^\n]*', '', config)
    return {
        'http2_listen': bool(re.search(r'\blisten\s+[^;\n]*\bhttp2\b', lines)),
        'http2_on': bool(re.search(r'\bhttp2\s+on\s*;', lines)),
        'http2_off': bool(re.search(r'\bhttp2\s+off\s*;', lines)),
        'proxying': bool(re.search(r'\b(?:proxy_pass|grpc_pass|fastcgi_pass|uwsgi_pass|scgi_pass)\s+', lines)),
        'http3': bool(re.search(r'\b(?:http3\s+on|listen\s+[^;\n]*\bquic\b)', lines)),
    }

def local_result(label, binary_output, config_output, vendor_patched=False, product=None):
    version = nginx_version(binary_output)
    checks = evaluate_version(version, vendor_patched)
    cfg = config_flags(config_output) if config_output else None
    notes = []
    if product:
        notes.append('Container identity is inferred from its image/name; verify manually.')
    if version and version['flavor'] != 'nginx':
        notes.append('OpenResty/NGINX forks require a vendor-specific patch assessment. Embedded NGINX version may differ.')
    if cfg is None:
        notes.append('Effective NGINX configuration unavailable; HTTP/2 and proxy status unknown.')
    elif cfg['http2_on'] or cfg['http2_listen']:
        notes.append('HTTP/2 directives detected. NGINX may expose HTTP/2 on one or more listeners; inspect per-server context.')
    else:
        notes.append('No explicit enabling directives detected in captured config; verify loaded includes, defaults, and exposed listeners.')
    if cfg and cfg['http2_off']:
        notes.append('http2 off appears in configuration but might apply only to specific server blocks.')
    if cfg and cfg['proxying']:
        notes.append('Proxy directives detected, which are relevant to CVE-2026-123633; connection-pressure precondition not tested.')
    status = 'REVIEW_REQUIRED'
    if all(v == 'FIXED_UPSTREAM' for v in checks.values()):
        status = 'FIXED_UPSTREAM_VERSION'
    elif all(v == 'VENDOR_PATCH_CONFIRMED_BY_OPERATOR' for v in checks.values()):
        status = 'VENDOR_PATCH_ATTESTED'
    elif any(v == 'AFFECTED_UPSTREAM_VERSION' for v in checks.values()):
        status = 'AFFECTED_VERSION' if cfg and (cfg['http2_on'] or cfg['http2_listen']) else 'AFFECTED_VERSION_H2_UNCONFIRMED'
    return {'mode': 'local', 'target': label, 'product_hint': product, 'version': version, 'config_signals': cfg,
            'cves': checks, 'status': status, 'notes': notes}

def scan_local(vendor_patched=False):
    findings = []
    if shutil.which('nginx'):
        version = run(['nginx', '-v'])
        conf = run(['nginx', '-T'])
        findings.append(local_result('host nginx', version['text'], conf['text'] if conf['ok'] else '', vendor_patched))
    if shutil.which('openresty') and not shutil.which('nginx'):
        version = run(['openresty', '-v'])
        conf = run(['openresty', '-T'])
        findings.append(local_result('host openresty', version['text'], conf['text'] if conf['ok'] else '', vendor_patched))
    if shutil.which('docker'):
        containers = run(['docker', 'ps', '--format', '{{.ID}}\t{{.Names}}\t{{.Image}}'])
        if containers['ok']:
            for line in containers['text'].splitlines():
                pieces = line.split('\t')
                if len(pieces) != 3:
                    continue
                cid, name, image = pieces
                hint = name + ' / ' + image
                if re.search(r'(?i)nginx|openresty|proxy.manager|nginx-ui|pangolin|traefik|gerbil|npm', hint):
                    if re.search(r'(?i)pangolin|traefik|gerbil', hint) and not re.search(r'(?i)nginx|openresty', hint):
                        findings.append({'mode':'local', 'target':hint, 'status':'NOT_NGINX_PRODUCT',
                                         'cves':{c:'NOT_APPLICABLE_TO_TRAEFIK_GERBIL' for c in CVES},
                                         'notes':['This container is not identified as NGINX. Check any additional NGINX origin.']})
                        continue
                    # No shell required: invoke nginx directly. May fail in unusual images.
                    v = run(['docker', 'exec', cid, 'nginx', '-v'])
                    c = run(['docker', 'exec', cid, 'nginx', '-T'])
                    if not v['ok'] and not c['ok']:
                        v = run(['docker', 'exec', cid, 'openresty', '-v'])
                        c = run(['docker', 'exec', cid, 'openresty', '-T'])
                    findings.append(local_result(hint, v['text'], c['text'] if c['ok'] else '', vendor_patched,
                                                 'NPM' if re.search(r'(?i)nginx-proxy-manager|jc21/nginx-proxy-manager', hint) else 'nginx-ui' if re.search(r'(?i)nginx-ui', hint) else None))
        else:
            findings.append({'mode':'local','target':'docker discovery','status':'CHECK_FAILED','error':containers['text']})
    if not findings:
        findings.append({'mode':'local','target':'host','status':'NO_NGINX_FOUND','notes':['No NGINX process/image detected by these checks.']})
    return findings

def main():
    ap = argparse.ArgumentParser(description='Read-only NGINX HTTP/2 CVE exposure inventory (no exploit payloads).')
    ap.add_argument('--target', action='append', default=[], help='HTTPS host or host:port; repeatable')
    ap.add_argument('--targets-file', help='one HTTPS host or host:port per line')
    ap.add_argument('--local', action='store_true', help='check host nginx and local running Docker containers')
    ap.add_argument('--timeout', type=float, default=4, help='connection timeout seconds (default 4)')
    ap.add_argument('--workers', type=int, default=8, help='parallel remote TLS handshakes (max 16)')
    ap.add_argument('--insecure', action='store_true', help='allow self-signed TLS certs; does not alter the server')
    ap.add_argument('--vendor-patched', action='store_true', help='operator attests local binaries are vendor-patched')
    ap.add_argument('--json', dest='json_path', help='save JSON report (use - for stdout only)')
    args = ap.parse_args()
    if args.timeout <= 0 or not 1 <= args.workers <= 16:
        ap.error('timeout must be positive and workers must be between 1 and 16')
    entries = list(args.target)
    if args.targets_file:
        try:
            with open(args.targets_file, encoding='utf-8') as f:
                entries.extend(f.readlines())
        except OSError as e:
            ap.error(str(e))
    if not entries and not args.local:
        ap.error('provide --target, --targets-file or --local')
    targets = []
    for entry in entries:
        try:
            target = parse_target(entry)
            if target:
                targets.append(target)
        except (ValueError, UnicodeError) as e:
            ap.error('invalid target {!r}: {}'.format(entry.strip(), e))
    results = []
    if targets:
        with concurrent.futures.ThreadPoolExecutor(max_workers=args.workers) as pool:
            results.extend(pool.map(lambda t: remote_check(t, args.timeout, args.insecure), targets))
    if args.local:
        results.extend(scan_local(args.vendor_patched))
    report = {'scanner': 'nginx2root-readonly', 'timestamp_utc': datetime.datetime.now(datetime.timezone.utc).isoformat(),
              'scope': 'CVE-2026-123007 and CVE-2026-123633', 'method': 'Passive metadata + non-exploit ALPN TLS check',
              'disclaimer': 'Not an RCE proof. No verification of backported patches without operator/vendor input. Check each listener and origin.',
              'sources': SOURCES, 'results': results}
    if args.json_path:
        body = json.dumps(report, indent=2)
        if args.json_path == '-':
            print(body)
        else:
            with open(args.json_path, 'w', encoding='utf-8') as f:
                f.write(body + '\n')
    if args.json_path != '-':
        for r in results:
            print('[{}] {}'.format(r['status'], r['target']))
            if r.get('version'):
                print('  version:', r['version']['full'])
            if 'alpn' in r:
                print('  negotiated ALPN:', r['alpn'] or '(none)')
            for cve, status in r.get('cves', {}).items():
                print(' ', cve + ':', status)
            if r.get('error'):
                print('  error:', r['error'])
            for note in r.get('notes', []):
                print('  note:', note)
        if args.json_path:
            print('JSON report:', args.json_path)
    return 0

if __name__ == '__main__':
    sys.exit(main())
