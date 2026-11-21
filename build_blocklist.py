
import re
import sys, os, math, urllib.request

HASH_BYTES = 5                          # 40-bit hashes -- must match firmware
MASK = (1 << (HASH_BYTES * 8)) - 1
FNV_OFFSET = 0xcbf29ce484222325
FNV_PRIME  = 0x100000001b3
U64 = (1 << 64) - 1

DEFAULT_SOURCES = [
    'https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts',            # base: ads + malware
    'https://raw.githubusercontent.com/hagezi/dns-blocklists/main/wildcard/light-onlydomains.txt',  # Hagezi Light (wildcard = domain + subdomains)
    'https://cdn.jsdelivr.net/gh/jerryn70/GoodbyeAds@master/Formats/GoodbyeAds-AdBlock-Filter.txt',  # GoodbyeAds
    'https://adguardteam.github.io/AdGuardSDNSFilter/Filters/filter.txt',  # AdGuardSDNSFilter
    'https://raw.githubusercontent.com/AdAway/adaway.github.io/master/hosts.txt',  # AdAway
]

# ||domain^  or  @@||domain^  optionally followed by $modifiers
ADG = re.compile(r'^(@@)?\|\|([a-z0-9._-]+)\^?(\$.*)?$', re.I)

def fnv(b: bytes) -> int:
    h = FNV_OFFSET
    for c in b:
        h = ((h ^ c) * FNV_PRIME) & U64
    return h & MASK                      # truncate to HASH_BYTES

def norm(d: str) -> str:
    d = d.strip().lower().lstrip('*').lstrip('.').rstrip('.')
    return d[4:] if d.startswith('www.') else d

def read_source(src: str) -> str:
    if os.path.exists(src):
        return open(src, errors='ignore').read()
    print(f'  downloading {src} ...', file=sys.stderr)
    return urllib.request.urlopen(src, timeout=180).read().decode('utf-8', 'ignore')

def build(out: str | None = None, sources: list[str] | None = None,
          allow_missing: bool = False) -> dict:
    # Không truyền out -> mặc định ghi vào <repo>/data/blocklist.bin
    if out is None:
        out = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'data', 'blocklist.bin')
    sources = sources or DEFAULT_SOURCES

    domains, allow = set(), set()
    skipped = 0
    for src in sources:
        try:
            data = read_source(src)
        except Exception as e:
            # Fail loudly: silently dropping a source shrinks the list without anyone noticing
            # (happened when Hagezi retired domains/light.txt). Pass --allow-missing to continue.
            print(f'  !! FAILED to read {src}: {e}', file=sys.stderr)
            if not allow_missing:
                raise RuntimeError(f'cannot read source: {src}')
            continue
        for line in data.splitlines():
            s = line.strip()
            if s.startswith(('||', '@@')):
                line = s                   # AdGuard/ABP syntax: never treat as hosts comment
            elif not s.startswith('#') and ('##' in s or '#@#' in s or '#?#' in s or '#%#' in s):
                skipped += 1; continue    # cosmetic rule (baidu.com##div.ad) — the old
                                          # split('#') heuristic ate '##' and added the
                                          # bare domain (baidu.com!) to the blocklist
            else:
                line = s.split('#', 1)[0].strip()
            if not line or line[0] in '!/[':
                continue
            # AdGuard / ABP basic rules: ||example.com^  and allow rules @@||example.com^
            m = ADG.match(line)
            if m:
                if m.group(3):            # has $modifiers (client/dnstype/etc.) -> can't express, skip
                    skipped += 1; continue
                (allow if m.group(1) else domains).add(norm(m.group(2)))
                continue
            if line.startswith(('||', '@@', '|')) or any(c in line for c in '^$*'):
                skipped += 1; continue    # other adblock syntax (regex, wildcards, cosmetic) -> skip
            parts = line.split()
            if parts[0] in ('0.0.0.0','127.0.0.1','::1','::'):
                entries = parts[1:]
            else:
                entries = parts if len(parts) == 1 else []
            for d in entries:
                d = norm(d)
                if '.' in d and ' ' not in d:
                    domains.add(d)
    if allow:
        before = len(domains); domains -= allow
        print(f'allowlisted      : {before - len(domains):,} removed ({len(allow):,} @@ rules)', file=sys.stderr)
    if skipped:
        print(f'skipped rules    : {skipped:,} (adblock syntax that a DNS hash list cannot express)', file=sys.stderr)

    hashes = sorted(fnv(d.encode()) for d in domains)
    collisions = len(hashes) - len(set(hashes))
    uniq = sorted(set(hashes))                       # one entry per distinct hash
    os.makedirs(os.path.dirname(os.path.abspath(out)), exist_ok=True)
    with open(out, 'wb') as f:
        for h in uniq:
            f.write(h.to_bytes(HASH_BYTES, 'little'))

    n, size = len(uniq), len(uniq) * HASH_BYTES
    return {
        'out': out,
        'domains': len(domains),
        'entries': n,
        'collisions': collisions,
        'bytes': size,
        'lookup_reads': math.ceil(math.log2(max(n, 2))),
    }


def main():
    args = [a for a in sys.argv[1:] if a != '--allow-missing']
    allow_missing = '--allow-missing' in sys.argv[1:]
    out = args[0] if args else None
    sources = args[1:] if len(args) > 1 else None
    try:
        s = build(out, sources, allow_missing)
    except RuntimeError as e:
        print(f'  !! {e}', file=sys.stderr)
        sys.exit(1)
    print(f'source domains   : {s["domains"]:,}')
    print(f'hash entries     : {s["entries"]:,}  ({HASH_BYTES}-byte / {HASH_BYTES*8}-bit)')
    print(f'collisions       : {s["collisions"]}  (domains sharing a hash -> over-block)')
    print(f'flash blob       : {s["bytes"]:,} bytes  ({s["bytes"]/1024/1024:.2f} MB)  -> {s["out"]}')
    print(f'lookup           : ~{s["lookup_reads"]} reads/query')

if __name__ == '__main__':
    main()
