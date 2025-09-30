#!/usr/bin/env python3
"""
clean-directory-wordlist.py

Prepare directory wordlists for ffuf when ffuf uses /FUZZ/ (so we DO NOT add trailing-slash by default).

Behavior summary:
- Remove comments (#...), empty lines
- Strip scheme/host (https://), strip query (?q=abc) /fragment
- Trim leading/trailing slashes (ffuf provides them)
- Collapse multiple slashes (//a/// -> a)
- Unicode normalize (NFKC) + map common Cyrillic homoglyphs -> Latin
- Remove control/format chars (zero-width, NUL, BOM...)
- Lowercase by default (use --iis to preserve case)
- Drop file-like entries (ending with .ext 1-6 chars) EXCEPT version folders like v1, v1.2, v3.5
- Keep ALL lines that start with '.' (dotfiles / hidden folders) — these bypass file/LFI drops
- Percent-encode unsafe chars (space -> %20), preserve '/'
- Deduplicate (preserve input order unless --sorted)
- Default: do NOT add trailing-slash variants (use --add-trailing-variant to enable)
"""
import argparse, re, sys, unicodedata, urllib.parse

# ---------- Args ----------
p = argparse.ArgumentParser(description="Process wordlist for ffuf (assumes /FUZZ/).")
p.add_argument("infile", help="input raw wordlist (plain text)")
p.add_argument("--iis", action="store_true", help="preserve case (IIS/Windows targets)")
p.add_argument("--maxlen", type=int, default=200, help="max length of output entry (after encoding)")
p.add_argument("--add-trailing-variant", action="store_true",
               help="also emit trailing-slash variants (enabled only if you want them)")
p.add_argument("--sorted", action="store_true", help="output sorted (alphabetical)")
p.add_argument("--verbose", action="store_true", help="print drop reasons to stderr")
args = p.parse_args()

# ---------- Patterns ----------
URL_SCHEME_HOST_RE = re.compile(r'^[a-zA-Z][a-zA-Z0-9+\-.]*://[^/]+', re.I)
QUERY_FRAGMENT_RE = re.compile(r'[\?#].*$')
COMMENT_RE = re.compile(r'^\s*#')
MULTI_SLASH_RE = re.compile(r'/+')
FILE_LIKE_RE = re.compile(r'(^|/)[^/]+\.[A-Za-z0-9]{1,6}$')  # ends with .ext (1-6 alnum)
VERSION_RE = re.compile(r'^v\d+(\.\d+)*$', re.I)  # v1 or v1.2 or v1.2.3 (allow v1)
LFI_INDICATORS = re.compile(r'(^|/)\.\.?($|/)')  # any .. or ./ or ../ segments

# ---------- Simple Cyrillic -> Latin mapping ----------
HOMOGLYPH_MAP = {
    ord('\u0430'): 'a', ord('\u0410'): 'A',
    ord('\u0435'): 'e', ord('\u0415'): 'E',
    ord('\u043E'): 'o', ord('\u041E'): 'O',
    ord('\u0441'): 'c', ord('\u0421'): 'C',
    ord('\u0440'): 'p', ord('\u0420'): 'P',
    ord('\u0445'): 'x', ord('\u0425'): 'X',
    ord('\u0456'): 'i', ord('\u0406'): 'I',
    ord('\u043D'): 'n', ord('\u041D'): 'N',
}

# ---------- Helpers ----------
def normalize_and_map(s: str) -> str:
    # 1) Unicode normalize (NFKC)
    s = unicodedata.normalize("NFKC", s)
    # 2) map common homoglyphs
    s = s.translate(HOMOGLYPH_MAP)
    # 3) remove control/format chars (category starting with 'C')
    s = ''.join(ch for ch in s if not unicodedata.category(ch).startswith('C'))
    return s

def collapse_slashes(s: str) -> str:
    return MULTI_SLASH_RE.sub('/', s)

def percent_encode_keep_slash(s: str) -> str:
    # keep slash and RFC3986 unreserved minus others
    return urllib.parse.quote(s, safe="/-._~")

# ---------- Main ----------
seen = set()
out_order = []

with open(args.infile, 'r', encoding='utf-8', errors='ignore') as fin:
    for lineno, raw in enumerate(fin, 1):
        line = raw.rstrip("\n\r")
        # skip empty quickly
        if not line:
            continue

        # skip comment lines (start with # after optional leading spaces)
        if COMMENT_RE.match(line.lstrip()):
            continue

        s = line.strip()

        # strip scheme+host if present (keep only path)
        s = URL_SCHEME_HOST_RE.sub("", s)

        # remove query and fragment parts
        s = QUERY_FRAGMENT_RE.sub("", s)

        # trim again and drop if empty
        s = s.strip()
        if not s:
            continue

        # remove surrounding slashes (ffuf will provide them)
        s = re.sub(r'^/+', '', s)
        s = re.sub(r'/+$', '', s)
        if not s:
            continue

        # collapse internal multi-slashes
        s = collapse_slashes(s)

        # Normalize unicode, map homoglyphs, remove control chars
        s = normalize_and_map(s)
        if not s:
            continue

        # At this point, if the PATH STARTS WITH '.' we MUST keep it (user request).
        # That means: bypass LFI checks and file-like drops for these entries.
        if s.startswith('.'):
            # case handling
            if not args.iis:
                s_proc = s.lower()
            else:
                s_proc = s
            # percent-encode but preserve slash
            encoded = percent_encode_keep_slash(s_proc)
            if len(encoded) > args.maxlen:
                if args.verbose:
                    print(f"[drop too-long dotfile] len={len(encoded)} {line}", file=sys.stderr)
                continue
            if encoded not in seen:
                seen.add(encoded)
                out_order.append(encoded)
            # do NOT add trailing variant for dotfiles by default
            continue

        # Non-dot entries: drop LFI-like entries
        if '..' in s or './' in s or LFI_INDICATORS.search(s):
            if args.verbose:
                print(f"[drop LFI] {line}", file=sys.stderr)
            continue

        # case handling (lowercase by default)
        if not args.iis:
            s = s.lower()

        # last segment to test file-like or version folder
        last = s.split('/')[-1]

        # drop file-like entries (index.php etc.) EXCEPT allow version folders like v1 or v1.2
        if FILE_LIKE_RE.search('/' + last):
            if VERSION_RE.match(last):
                # keep (it's a version-like dir)
                pass
            else:
                if args.verbose:
                    print(f"[drop file-like] {line}", file=sys.stderr)
                continue

        # percent-encode (spaces -> %20 etc.), preserve '/'
        encoded = percent_encode_keep_slash(s)

        # enforce max length
        if len(encoded) > args.maxlen:
            if args.verbose:
                print(f"[drop too-long] len={len(encoded)} {line}", file=sys.stderr)
            continue

        # variants: default DO NOT add trailing slash (since ffuf uses /FUZZ/)
        variants = [encoded]
        if args.add_trailing_variant and not encoded.startswith('.') and not encoded.endswith('/'):
            variants.append(encoded + '/')

        for v in variants:
            if v not in seen:
                seen.add(v)
                out_order.append(v)

# final output
if args.sorted:
    for item in sorted(out_order):
        sys.stdout.write(item + "\n")
else:
    for item in out_order:
        sys.stdout.write(item + "\n")
