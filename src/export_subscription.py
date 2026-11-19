#!/usr/bin/env python3
"""Export proxy nodes from a Mihomo YAML config into a plain subscription URI list."""
import sys
import yaml
from urllib.parse import urlencode, quote

IN = sys.argv[1] if len(sys.argv) > 1 else 'publish/mihomo.yaml'
OUT = sys.argv[2] if len(sys.argv) > 2 else 'publish/subscription.txt'

def vless_uri(p):
    q = {}
    if p.get('encryption'):
        q['encryption'] = p['encryption']
    if p.get('flow'):
        q['flow'] = p['flow']
    ro = p.get('reality-opts') or {}
    if ro:
        q['security'] = 'reality'
        if ro.get('public-key'):
            q['pbk'] = ro['public-key']
        if ro.get('short-id'):
            q['sid'] = ro['short-id']
    elif p.get('tls'):
        q['security'] = 'tls'
    if p.get('servername'):
        q['sni'] = p['servername']
    if p.get('client-fingerprint'):
        q['fp'] = p['client-fingerprint']
    net = str(p.get('network') or 'tcp').lower()
    if net and net != 'tcp':
        q['type'] = net
    ws = p.get('ws-opts') or {}
    if ws.get('path'):
        q['path'] = ws['path']
    headers = ws.get('headers') or {}
    host = headers.get('Host') or headers.get('host')
    if host:
        q['host'] = host
    grpc = p.get('grpc-opts') or {}
    if grpc.get('grpc-service-name'):
        q['serviceName'] = grpc['grpc-service-name']
    name = quote(str(p.get('name') or 'node'), safe='')
    return 'vless://%s@%s:%s?%s#%s' % (p['uuid'], p['server'], p['port'], urlencode(q), name)

def hy2_uri(p):
    q = {}
    if p.get('sni'):
        q['sni'] = p['sni']
    if p.get('obfs'):
        q['obfs'] = p['obfs']
        if p.get('obfs-password'):
            q['obfs-password'] = p['obfs-password']
    name = quote(str(p.get('name') or 'node'), safe='')
    return 'hysteria2://%s@%s:%s?%s#%s' % (p.get('password', ''), p['server'], p['port'], urlencode(q), name)

def trojan_uri(p):
    q = {}
    if p.get('sni'):
        q['sni'] = p['sni']
    if p.get('skip-cert-verify'):
        q['allowInsecure'] = '1'
    name = quote(str(p.get('name') or 'node'), safe='')
    return 'trojan://%s@%s:%s?%s#%s' % (p.get('password', ''), p['server'], p['port'], urlencode(q), name)

def main():
    d = yaml.safe_load(open(IN, encoding='utf-8'))
    lines = []
    skipped = {}
    for p in d.get('proxies', []):
        t = str(p.get('type', '')).lower()
        try:
            if t == 'vless':
                lines.append(vless_uri(p))
            elif t in ('hysteria2', 'hy2'):
                lines.append(hy2_uri(p))
            elif t == 'trojan':
                lines.append(trojan_uri(p))
            else:
                skipped[t] = skipped.get(t, 0) + 1
        except Exception as e:
            skipped[t + ':error'] = skipped.get(t + ':error', 0) + 1
    with open(OUT, 'w', encoding='utf-8') as f:
        f.write('\n'.join(lines) + '\n')
    print('subscription exported:', len(lines), 'URIs ->', OUT)
    if skipped:
        print('skipped:', skipped)

if __name__ == '__main__':
    main()
