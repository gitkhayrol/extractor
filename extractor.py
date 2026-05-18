#!/usr/bin/env python3
"""
extractor - IOC extractor for IPs, domains, emails, URLs, hashes
Supports files, stdin (pipe), and binary files

Usage:
  extractor [file] [flags]
  curl https://example.com | extractor --domain
  extractor malware.apk --ip --verbose
  extractor dump.txt --all --dedup --output results.txt
"""

import re
import sys
import os
import argparse
import ipaddress
import hashlib
import json
from pathlib import Path

# ─── ANSI colors ────────────────────────────────────────────────
class C:
    RESET  = "\033[0m"
    BOLD   = "\033[1m"
    DIM    = "\033[2m"
    RED    = "\033[91m"
    GREEN  = "\033[92m"
    YELLOW = "\033[93m"
    BLUE   = "\033[94m"
    PURPLE = "\033[95m"
    CYAN   = "\033[96m"
    WHITE  = "\033[97m"
    GRAY   = "\033[90m"

def no_color():
    for attr in vars(C):
        if not attr.startswith('_'):
            setattr(C, attr, '')

# ─── REGEX PATTERNS ─────────────────────────────────────────────
IPV4_RE = re.compile(
    r'\b(?:(?:25[0-5]|2[0-4]\d|1\d{2}|[1-9]\d|\d)\.){3}'
    r'(?:25[0-5]|2[0-4]\d|1\d{2}|[1-9]\d|\d)\b'
)

IPV6_RE = re.compile(
    r'(?:'
    r'(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}|'
    r'(?:[0-9a-fA-F]{1,4}:){1,7}:|'
    r':(?::[0-9a-fA-F]{1,4}){1,7}|'
    r'::(?:ffff(?::0{1,4})?:)?(?:25[0-5]|2[0-4]\d|1?\d\d?)'
    r'(?:\.(?:25[0-5]|2[0-4]\d|1?\d\d?)){3}|'
    r'(?:[0-9a-fA-F]{1,4}:){1,4}:(?:25[0-5]|2[0-4]\d|1?\d\d?)'
    r'(?:\.(?:25[0-5]|2[0-4]\d|1?\d\d?)){3}|'
    r'::1|::'
    r')',
    re.IGNORECASE
)

EMAIL_RE = re.compile(
    r'\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b'
)

URL_RE = re.compile(
    r'https?://[^\s"\'<>\])\}\\]+'
)

DOMAIN_RE = re.compile(
    r'\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+(?:'
    r'com|net|org|io|co|gov|edu|mil|int|info|biz|tv|me|app|dev|tech|ai|'
    r'xyz|top|pro|cloud|store|online|site|web|blog|news|media|live|link|'
    r'uk|us|de|fr|ru|cn|jp|br|au|in|ca|nl|se|no|fi|dk|es|it|pl|pt|ch|at|'
    r'be|nz|za|mx|ar|tr|sg|hk|th|vn|id|my|ph|pk|bd|ng|ke|tz|ug|gh|'
    r'ly|tn|dz|ma|local|internal|onion'
    r')\b',
    re.IGNORECASE
)

MD5_RE    = re.compile(r'\b[a-fA-F0-9]{32}\b')
SHA1_RE   = re.compile(r'\b[a-fA-F0-9]{40}\b')
SHA256_RE = re.compile(r'\b[a-fA-F0-9]{64}\b')
SHA512_RE = re.compile(r'\b[a-fA-F0-9]{128}\b')

BITCOIN_RE = re.compile(r'\b[13][a-km-zA-HJ-NP-Z1-9]{25,34}\b|bc1[a-z0-9]{39,59}\b')

CVE_RE = re.compile(r'\bCVE-\d{4}-\d{4,7}\b', re.IGNORECASE)

# ─── PRIVATE / SPECIAL IP RANGES ───────────────────────────────
PRIVATE_RANGES = [
    ipaddress.ip_network('10.0.0.0/8'),
    ipaddress.ip_network('172.16.0.0/12'),
    ipaddress.ip_network('192.168.0.0/16'),
    ipaddress.ip_network('127.0.0.0/8'),
    ipaddress.ip_network('169.254.0.0/16'),
    ipaddress.ip_network('0.0.0.0/8'),
    ipaddress.ip_network('255.255.255.255/32'),
    ipaddress.ip_network('100.64.0.0/10'),
]

def classify_ip(ip_str):
    try:
        ip = ipaddress.ip_address(ip_str)
        for net in PRIVATE_RANGES:
            if ip in net:
                return 'private'
        return 'public'
    except ValueError:
        return 'unknown'

# ─── EXTRACT ────────────────────────────────────────────────────
def extract_all(text):
    results = {}

    ips = IPV4_RE.findall(text)
    results['ipv4'] = [(ip, classify_ip(ip)) for ip in ips]

    ipv6s = IPV6_RE.findall(text)
    # ipv6 regex groups — flatten
    results['ipv6'] = [g if isinstance(g, str) else next((x for x in g if x), '') for g in ipv6s]
    results['ipv6'] = [x for x in results['ipv6'] if x]

    emails = EMAIL_RE.findall(text)
    results['email'] = emails

    urls_raw = URL_RE.findall(text)
    results['url'] = [u.rstrip('.,;:\'")}]>') for u in urls_raw]

    # domains — exclude those already in emails/urls
    domains_raw = DOMAIN_RE.findall(text)
    results['domain'] = domains_raw

    results['md5']    = MD5_RE.findall(text)
    results['sha1']   = SHA1_RE.findall(text)
    results['sha256'] = SHA256_RE.findall(text)
    results['sha512'] = SHA512_RE.findall(text)
    results['bitcoin'] = BITCOIN_RE.findall(text)
    results['cve']    = CVE_RE.findall(text)

    return results

def dedup(items):
    seen = set()
    out = []
    for item in items:
        key = item[0] if isinstance(item, tuple) else item
        if key not in seen:
            seen.add(key)
            out.append(item)
    return out

# ─── READ FILE / STDIN ──────────────────────────────────────────
def read_input(path=None):
    """Read file or stdin, return (text, raw_bytes, filename)"""
    if path:
        p = Path(path)
        if not p.exists():
            print(f"{C.RED}error: file not found: {path}{C.RESET}", file=sys.stderr)
            sys.exit(1)
        raw = p.read_bytes()
        filename = p.name
        size = p.stat().st_size
    else:
        raw = sys.stdin.buffer.read()
        filename = '<stdin>'
        size = len(raw)

    # try utf-8, then latin-1, then binary decode
    for enc in ('utf-8', 'latin-1', 'ascii'):
        try:
            text = raw.decode(enc, errors='strict')
            break
        except (UnicodeDecodeError, ValueError):
            continue
    else:
        # binary: keep printable bytes + spaces
        text = ''.join(
            chr(b) if (32 <= b < 127 or b in (9, 10, 13)) else ' '
            for b in raw
        )

    return text, raw, filename, size

# ─── OUTPUT FORMATTING ──────────────────────────────────────────
def tag(label, color):
    return f"{color}[{label}]{C.RESET}"

def print_section(label, items, color, verbose=False, label_fn=None):
    if not items:
        if verbose:
            print(f"  {C.GRAY}[{label}] no results{C.RESET}")
        return

    count = len(items)
    print(f"\n{C.BOLD}{color}◆ {label.upper()}{C.RESET} {C.GRAY}({count} found){C.RESET}")
    print(f"  {C.GRAY}{'─'*50}{C.RESET}")

    for item in items:
        if isinstance(item, tuple):
            value, meta = item
        else:
            value, meta = item, None

        extra = ''
        if label_fn:
            extra = label_fn(value, meta)
        elif meta:
            extra = f" {C.GRAY}[{meta}]{C.RESET}"

        print(f"  {color}{value}{C.RESET}{extra}")

def format_size(size):
    if size < 1024: return f"{size}B"
    if size < 1048576: return f"{size/1024:.1f}KB"
    return f"{size/1048576:.1f}MB"

def print_file_info(filename, size, raw, text):
    print(f"\n{C.BOLD}{C.CYAN}◆ FILE INFO{C.RESET}")
    print(f"  {C.GRAY}{'─'*50}{C.RESET}")
    print(f"  {C.GRAY}name   :{C.RESET} {filename}")
    print(f"  {C.GRAY}size   :{C.RESET} {format_size(size)} ({size} bytes)")
    print(f"  {C.GRAY}chars  :{C.RESET} {len(text)}")
    print(f"  {C.GRAY}lines  :{C.RESET} {text.count(chr(10))}")
    md5_h = hashlib.md5(raw).hexdigest()
    sha1_h = hashlib.sha1(raw).hexdigest()
    sha256_h = hashlib.sha256(raw).hexdigest()
    print(f"  {C.GRAY}md5    :{C.RESET} {md5_h}")
    print(f"  {C.GRAY}sha1   :{C.RESET} {sha1_h}")
    print(f"  {C.GRAY}sha256 :{C.RESET} {sha256_h}")
    if raw:
        hex_prev = ' '.join(f'{b:02x}' for b in raw[:32])
        print(f"  {C.GRAY}hex[0:32]:{C.RESET} {C.DIM}{hex_prev}{C.RESET}")

def print_banner():
    print(f"{C.BOLD}{C.CYAN}")
    print(r"  _____      _                  _             ")
    print(r" | ____|_  _| |_ _ __ __ _  ___| |_ ___  _ _ ")
    print(r" |  _| \ \/ / __| '__/ _` |/ __| __/ _ \| '_|")
    print(r" | |___ >  <| |_| | | (_| | (__| || (_) | |  ")
    print(r" |_____/_/\_\\__|_|  \__,_|\___|\__\___/|_|  ")
    print(f"{C.RESET}{C.GRAY}  IOC Extractor @DevidLuice — github.com/gitkhayrol/extractor{C.RESET}\n")

# ─── JSON OUTPUT ────────────────────────────────────────────────
def to_json(results, active_flags, filename, size):
    out = {'file': filename, 'size': size, 'results': {}}
    for key in active_flags:
        if key in results:
            items = results[key]
            if items and isinstance(items[0], tuple):
                out['results'][key] = [{'value': v, 'meta': m} for v,m in items]
            else:
                out['results'][key] = items
    return json.dumps(out, indent=2)

# ─── MAIN ───────────────────────────────────────────────────────
def main():
    parser = argparse.ArgumentParser(
        prog='extractor',
        description='Extract IPs, domains, emails, URLs, hashes from any file or stdin',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
examples:
  extractor file.txt --ip --domain
  extractor dump.bin --all --verbose
  extractor log.txt --ip --dedup --output out.txt
  curl https://example.com | extractor --domain --url
  cat malware.apk | extractor --all --json
  extractor file.txt --ip --no-private
        """
    )

    parser.add_argument('file', nargs='?', help='input file (or omit for stdin)')

    # extraction flags
    g = parser.add_argument_group('extraction flags')
    g.add_argument('--ip',      action='store_true', help='extract IPv4 addresses')
    g.add_argument('--ipv6',    action='store_true', help='extract IPv6 addresses')
    g.add_argument('--domain',  action='store_true', help='extract domain names')
    g.add_argument('--email',   action='store_true', help='extract email addresses')
    g.add_argument('--url',     action='store_true', help='extract URLs (http/https)')
    g.add_argument('--hash',    action='store_true', help='extract md5/sha1/sha256/sha512 hashes')
    g.add_argument('--bitcoin', action='store_true', help='extract Bitcoin addresses')
    g.add_argument('--cve',     action='store_true', help='extract CVE identifiers')
    g.add_argument('--all',     action='store_true', help='extract everything')

    # filters
    f = parser.add_argument_group('filters')
    f.add_argument('--no-private', action='store_true', help='exclude private/reserved IPs')
    f.add_argument('--only-private', action='store_true', help='show only private IPs')
    f.add_argument('--dedup',   action='store_true', help='deduplicate results')

    # output
    o = parser.add_argument_group('output')
    o.add_argument('--verbose', '-v', action='store_true', help='show file info and extra details')
    o.add_argument('--quiet',   '-q', action='store_true', help='no colors, no headers (raw values only)')
    o.add_argument('--json',    action='store_true', help='output as JSON')
    o.add_argument('--output',  '-o', metavar='FILE', help='write output to file')
    o.add_argument('--no-color', action='store_true', help='disable ANSI colors')
    o.add_argument('--count',   action='store_true', help='only print counts per category')

    args = parser.parse_args()

    # disable color if piped or requested
    if args.no_color or args.quiet or not sys.stdout.isatty():
        no_color()

    # determine what to extract
    extract_ip      = args.all or args.ip
    extract_ipv6    = args.all or args.ipv6
    extract_domain  = args.all or args.domain
    extract_email   = args.all or args.email
    extract_url     = args.all or args.url
    extract_hash    = args.all or args.hash
    extract_bitcoin = args.all or args.bitcoin
    extract_cve     = args.all or args.cve

    nothing_selected = not any([extract_ip, extract_ipv6, extract_domain,
                                 extract_email, extract_url, extract_hash,
                                 extract_bitcoin, extract_cve])

    if nothing_selected:
        # default: extract everything
        extract_ip = extract_domain = extract_email = extract_url = True

    # read input
    text, raw, filename, size = read_input(args.file)

    # extract
    results = extract_all(text)

    # apply dedup
    if args.dedup:
        for k in results:
            results[k] = dedup(results[k])

    # ip filters
    if extract_ip:
        ips = results['ipv4']
        if args.no_private:
            ips = [(ip, m) for ip, m in ips if m != 'private']
        if args.only_private:
            ips = [(ip, m) for ip, m in ips if m == 'private']
        results['ipv4'] = ips

    # ── output ──────────────────────────────────────────────────
    out_lines = []

    def emit(s=''):
        out_lines.append(s)
        if not args.output:
            print(s)

    if args.json:
        active = []
        if extract_ip:     active.append('ipv4')
        if extract_ipv6:   active.append('ipv6')
        if extract_domain: active.append('domain')
        if extract_email:  active.append('email')
        if extract_url:    active.append('url')
        if extract_hash:   active += ['md5','sha1','sha256','sha512']
        if extract_bitcoin: active.append('bitcoin')
        if extract_cve:    active.append('cve')
        j = to_json(results, active, filename, size)
        if args.output:
            Path(args.output).write_text(j)
        else:
            print(j)
        return

    if args.quiet:
        # raw values only, no decoration
        def raw_print(items):
            for item in items:
                v = item[0] if isinstance(item, tuple) else item
                emit(v)
        if extract_ip:     raw_print(results['ipv4'])
        if extract_ipv6:   raw_print([(x,'') for x in results['ipv6']])
        if extract_domain: raw_print(results['domain'])
        if extract_email:  raw_print(results['email'])
        if extract_url:    raw_print(results['url'])
        if extract_hash:
            for k in ('md5','sha1','sha256','sha512'):
                raw_print(results[k])
        if extract_bitcoin: raw_print(results['bitcoin'])
        if extract_cve:    raw_print(results['cve'])
        if args.output:
            Path(args.output).write_text('\n'.join(out_lines))
        return

    # styled output — capture via redirect
    import io
    old_stdout = sys.stdout
    buf = io.StringIO()
    if args.output:
        sys.stdout = buf

    if not args.quiet and sys.stdout.isatty():
        print_banner()

    if args.verbose:
        print_file_info(filename, size, raw, text)

    if args.count:
        print(f"\n{C.BOLD}counts:{C.RESET}")
        pairs = []
        if extract_ip:     pairs.append(('ipv4', len(results['ipv4'])))
        if extract_ipv6:   pairs.append(('ipv6', len(results['ipv6'])))
        if extract_domain: pairs.append(('domain', len(results['domain'])))
        if extract_email:  pairs.append(('email', len(results['email'])))
        if extract_url:    pairs.append(('url', len(results['url'])))
        if extract_hash:
            for k in ('md5','sha1','sha256','sha512'):
                pairs.append((k, len(results[k])))
        if extract_bitcoin: pairs.append(('bitcoin', len(results['bitcoin'])))
        if extract_cve:    pairs.append(('cve', len(results['cve'])))
        for k, v in pairs:
            print(f"  {C.CYAN}{k:<12}{C.RESET} {C.BOLD}{v}{C.RESET}")

    else:
        if extract_ip:
            def ip_label(v, meta):
                color = C.GREEN if meta == 'private' else C.RED
                return f"  {color}[{meta}]{C.RESET}"
            print_section('ipv4', results['ipv4'], C.YELLOW,
                          verbose=args.verbose, label_fn=ip_label)

        if extract_ipv6:
            print_section('ipv6', [(x, 'ipv6') for x in results['ipv6']],
                          C.PURPLE, verbose=args.verbose)

        if extract_email:
            def email_label(v, meta):
                domain = v.split('@')[-1] if '@' in v else ''
                return f"  {C.GRAY}[{domain}]{C.RESET}"
            print_section('email', results['email'], C.CYAN,
                          verbose=args.verbose, label_fn=email_label)

        if extract_url:
            def url_label(v, meta):
                proto = 'https' if v.startswith('https') else 'http'
                color = C.GREEN if proto == 'https' else C.YELLOW
                return f"  {color}[{proto}]{C.RESET}"
            print_section('url', results['url'], C.BLUE,
                          verbose=args.verbose, label_fn=url_label)

        if extract_domain:
            print_section('domain', results['domain'], C.PURPLE,
                          verbose=args.verbose)

        if extract_hash:
            for k, color in [('md5', C.RED), ('sha1', C.YELLOW),
                              ('sha256', C.GREEN), ('sha512', C.CYAN)]:
                if results[k]:
                    print_section(k, results[k], color, verbose=args.verbose)

        if extract_bitcoin:
            print_section('bitcoin', results['bitcoin'], C.YELLOW,
                          verbose=args.verbose)

        if extract_cve:
            print_section('cve', results['cve'], C.RED, verbose=args.verbose)

    # summary line
    total = 0
    parts = []
    cats = []
    if extract_ip:     cats.append(('ipv4', results['ipv4']))
    if extract_ipv6:   cats.append(('ipv6', [(x,) for x in results['ipv6']]))
    if extract_email:  cats.append(('email', results['email']))
    if extract_url:    cats.append(('url', results['url']))
    if extract_domain: cats.append(('domain', results['domain']))
    if extract_hash:
        for k in ('md5','sha1','sha256','sha512'):
            cats.append((k, results[k]))
    if extract_bitcoin: cats.append(('bitcoin', results['bitcoin']))
    if extract_cve:    cats.append(('cve', results['cve']))

    for name, items in cats:
        n = len(items)
        if n:
            parts.append(f"{C.BOLD}{n}{C.RESET} {name}")
        total += n

    if not args.count:
        print(f"\n{C.GRAY}{'─'*52}{C.RESET}")
        if parts:
            print(f"  {C.GRAY}found:{C.RESET} {', '.join(parts)}")
        else:
            print(f"  {C.GRAY}no results{C.RESET}")
        print()

    if args.output:
        sys.stdout = old_stdout
        # strip ANSI for file output
        ansi_escape = re.compile(r'\x1b\[[0-9;]*m')
        clean = ansi_escape.sub('', buf.getvalue())
        Path(args.output).write_text(clean)
        print(f"{C.GREEN}output written to:{C.RESET} {args.output}")

if __name__ == '__main__':
    main()
