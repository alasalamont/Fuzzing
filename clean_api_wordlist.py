#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
normalize_endpoints.py

Normalize API endpoint wordlist for fuzzing (e.g. ffuf).
Default behavior:
 - strip comments (# or //) and blank lines
 - remove BOM, trim whitespace
 - collapse repeated slashes
 - remove trailing slash at end
 - deduplicate preserving order

Flags:
 -i / --input            : input filename (required)
 -o / --output           : output filename (if omitted prints to stdout)
 --leading-slash / -ls   : ensure each line starts with a single leading slash ("/foo")
 --no-leading-slash / -nls : remove all leading slashes (produce "foo")
 (these two are mutually exclusive)
 --lower                 : lowercase entries
 --percent               : percent-encode unsafe chars (preserve '/')
 --add-trailing-variant  : also emit a trailing-slash variant for each entry (e.g. "foo" and "foo/")
 --strip-comments        : strip comments (enabled by default)
 --collapse-slashes      : collapse multiple slashes into one (enabled by default)
 --verbose / -v          : print basic processing stats to stderr

Examples:
  python3 normalize_endpoints.py -i raw.txt -o clean.txt --no-leading-slash --lower
  python3 normalize_endpoints.py -i raw.txt -ls --add-trailing-variant

"""
import argparse
import sys
import unicodedata
import re
from urllib.parse import quote

# ----------------- helpers -----------------
COMMENT_RE = re.compile(r'^\s*(#|//)')
INLINE_COMMENT_PATTERNS = [r' #', r' //']  # remove inline comment if preceded by whitespace
MULTI_SLASH_RE = re.compile(r'/+')
BOM = '\ufeff'

def strip_comment(line: str) -> str:
    # remove BOM
    line = line.lstrip(BOM)
    # full-line comment
    if COMMENT_RE.match(line):
        return ''
    # remove inline comments only when there is preceding whitespace (so http:// unaffected)
    for seq in INLINE_COMMENT_PATTERNS:
        idx = line.find(seq)
        if idx != -1:
            return line[:idx]
    return line

def collapse_slashes(s: str) -> str:
    return MULTI_SLASH_RE.sub('/', s)

def remove_trailing_slash(s: str) -> str:
    # remove trailing slash(es) but keep root "/" as special case?
    if s == '/':
        return s  # keep root if it appears
    return re.sub(r'/+$', '', s)

def percent_encode_keep_slash(s: str) -> str:
    # preserve slash and common unreserved chars
    return quote(s, safe="/-._~")

# ----------------- main -----------------
def process_lines(lines, opts):
    seen = {}
    out = []

    for raw in lines:
        # remove newline chars
        line = raw.rstrip('\r\n')
        if line == '':
            continue
        # strip comments / inline comments
        if opts.strip_comments:
            line = strip_comment(line)
            if not line:
                continue
        # trim whitespace
        line = line.strip()
        if not line:
            continue
        # unicode normalize
        line = unicodedata.normalize("NFKC", line)
        # collapse internal multi-slashes if requested
        if opts.collapse_slashes:
            line = collapse_slashes(line)
        # remove trailing slash by default
        line = remove_trailing_slash(line)
        # apply leading slash rules
        if opts.leading_slash:
            # ensure exactly one leading slash
            if not line.startswith('/'):
                line = '/' + line
            else:
                # collapse any multiple leading slashes to single
                line = re.sub(r'^/+', '/', line)
        elif opts.no_leading_slash:
            # remove all leading slashes
            line = re.sub(r'^/+', '', line)
        # apply lowercase if requested
        if opts.lower:
            line = line.lower()
        # percent-encode if requested
        if opts.percent:
            line = percent_encode_keep_slash(line)
        # final trim
        line = line.strip()
        if not line:
            continue
        # dedupe preserving first occurrence
        if line in seen:
            continue
        seen[line] = True
        out.append(line)
        # add trailing variant if requested (do not add for root-only '.' or empty)
        if opts.add_trailing_variant:
            # only add variant if not already endswith '/'
            if not line.endswith('/'):
                var = line + '/'
                if var not in seen:
                    seen[var] = True
                    out.append(var)
    return out

def main():
    p = argparse.ArgumentParser(description="Normalize API endpoint wordlist.")
    p.add_argument("-i", "--input", required=True, help="Input wordlist file")
    p.add_argument("-o", "--output", help="Output file (if omitted prints to stdout)")
    group = p.add_mutually_exclusive_group()
    group.add_argument("-ls", "--leading-slash", dest="leading_slash", action="store_true",
                       help="Ensure each line starts with a leading slash ('/foo').")
    group.add_argument("-nls", "--no-leading-slash", dest="no_leading_slash", action="store_true",
                       help="Remove leading slashes from each line (suitable for ffuf's /FUZZ/).")
    p.add_argument("--lower", action="store_true", help="Lowercase all entries")
    p.add_argument("--percent", action="store_true", help="Percent-encode unsafe chars (preserve '/')")
    p.add_argument("--add-trailing-variant", action="store_true",
                   help="Also emit trailing-slash variant for each entry (e.g. 'foo' and 'foo/').")
    # options to control defaults (enabled by default)
    p.add_argument("--no-strip-comments", dest="strip_comments", action="store_false",
                   help="Do NOT strip comments/blank lines (disabled by default).")
    p.add_argument("--no-collapse-slashes", dest="collapse_slashes", action="store_false",
                   help="Do NOT collapse multiple internal slashes (enabled by default).")
    p.add_argument("--verbose", "-v", action="store_true", help="Verbose output to stderr")
    args = p.parse_args()

    class Opts: pass
    opts = Opts()
    opts.leading_slash = getattr(args, "leading_slash", False)
    opts.no_leading_slash = getattr(args, "no_leading_slash", False)
    opts.lower = args.lower
    opts.percent = args.percent
    opts.add_trailing_variant = args.add_trailing_variant
    opts.strip_comments = getattr(args, "strip_comments", True)
    opts.collapse_slashes = getattr(args, "collapse_slashes", True)
    opts.verbose = args.verbose

    # read input
    try:
        with open(args.input, 'r', encoding='utf-8', errors='ignore') as f:
            lines = f.readlines()
    except Exception as e:
        print(f"[ERROR] cannot read input file: {e}", file=sys.stderr)
        sys.exit(2)

    processed = process_lines(lines, opts)

    # write output
    if args.output:
        try:
            with open(args.output, 'w', encoding='utf-8') as fo:
                for l in processed:
                    fo.write(l + "\n")
        except Exception as e:
            print(f"[ERROR] cannot write output file: {e}", file=sys.stderr)
            sys.exit(3)
    else:
        for l in processed:
            print(l)

    # verbose stats
    if opts.verbose:
        print(f"[info] input_lines={len(lines)} output_lines={len(processed)}", file=sys.stderr)

if __name__ == "__main__":
    main()
