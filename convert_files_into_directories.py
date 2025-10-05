#!/usr/bin/env python3
"""
files-to-dirs.py
Convert a wordlist of filenames into directory-like entries:
  - strip comments / blank lines
  - remove file extensions (supports multi-extensions like .tar.gz)
  - dedupe while preserving order
  - options: lowercase, basename-only, add-trailing-slash
Usage:
  python3 files-to-dirs.py -i files.txt -o dirs.txt --basename --slash --lower
"""
import argparse
import re
from pathlib import PurePosixPath
from collections import OrderedDict
import sys

# Default extensions to strip (common web/dev backup/archive/db/etc)
DEFAULT_EXTS = [
    "tar.gz", "tar.bz2", "tar.xz", "tar", "tgz", "tbz2",
    "zip", "rar", "7z", "gz", "bz2", "xz",
    "sql", "sql.gz", "db", "bak", "old", "orig", "save",
    "php", "php5", "phtml", "asp", "aspx", "jsp",
    "html", "htm", "shtml", "xhtml",
    "js", "css", "json", "xml", "yml", "yaml",
    "txt", "md", "csv", "log",
    "conf", "cfg", "ini", "env",
    "pem", "key", "crt", "cer",
    "exe", "bin", "dll",
    "img", "iso",
    "pdf", "doc", "docx", "xls", "xlsx", "ppt", "pptx",
]

# Build regex to match one or more of these extensions at the end of string
# We sort by length descending so that multi-part extensions like tar.gz are matched before gz
def build_ext_regex(ext_list):
    sorted_exts = sorted(set(ext_list), key=lambda s: -len(s))
    # escape dots for regex, and allow optional leading dot
    alt = "|".join(re.escape(e) for e in sorted_exts)
    # match one or more of (.ext) sequences at end: (?:\.(?:tar\.gz|zip|...))+
    pattern = re.compile(r"(?:\.(?:" + alt + r"))+$", flags=re.IGNORECASE)
    return pattern

EXT_RE = build_ext_regex(DEFAULT_EXTS)

# Remove comments - supports lines starting with # or // and inline comments (after whitespace)
def strip_comment(line):
    # remove BOM first
    line = line.lstrip("\ufeff")
    # if line starts with # or // -> whole line comment
    stripped = line.strip()
    if stripped.startswith("#"):
        return ""
    if stripped.startswith("//"):
        return ""
    # remove inline comment if preceded by whitespace (so URLs like http:// are safe)
    # we will split on ' #' or ' //' patterns
    # first handle ' #' style
    for seq in [" #", " //"]:
        idx = line.find(seq)
        if idx != -1:
            return line[:idx]
    return line

def remove_extensions(name, ext_re=EXT_RE):
    """
    Remove trailing extensions like .php or .tar.gz. Works on the final path component.
    If there is no extension match, returns original.
    """
    if not name:
        return name
    # if path-like, work on last segment only
    p = PurePosixPath(name)
    stem = p.name  # only filename part
    # apply regex on stem
    new_stem = ext_re.sub("", stem)
    if new_stem == stem:
        # nothing changed
        return str(p)  # preserve original path format (posix)
    # rebuild path with parent / new_stem
    parent = str(p.parent)
    if parent in (".", ""):
        return new_stem
    else:
        # ensure posix slash
        return "/".join([parent, new_stem])

def normalize(line, lower=False):
    # collapse repeated whitespace inward (not removing internal spaces, but trim)
    s = line.strip()
    # optionally collapse multiple slashes to single (useful)
    s = re.sub(r"/{2,}", "/", s)
    if lower:
        s = s.lower()
    return s

def process_file(input_path, basename_only=False, add_trailing_slash=False,
                 lower=False, ext_list=None, keep_markers=False):
    ext_re = build_ext_regex(ext_list or DEFAULT_EXTS)
    seen = OrderedDict()
    with open(input_path, "r", encoding="utf-8", errors="ignore") as fh:
        for raw in fh:
            # strip newline + comments + BOM
            line = strip_comment(raw)
            if not line:
                continue
            line = line.strip()
            if not line:
                continue
            # ignore lines that are pure whitespace or look like markers we want to skip
            # if keep_markers False and line begins with '!' or similar, skip it
            if not keep_markers and re.match(r"^[!@#\$%]", line):
                # skip marker-like entries by default
                continue
            # normalize
            line = normalize(line, lower=lower)
            if basename_only:
                # choose basename first, then remove extensions
                candidate = PurePosixPath(line).name
                candidate = ext_re.sub("", candidate)
            else:
                # remove extensions from the final component while preserving path
                candidate = remove_extensions(line, ext_re)
            candidate = candidate.strip()
            if not candidate:
                continue
            # optionally ensure no leading './'
            candidate = re.sub(r"^\./+", "", candidate)
            # optionally add trailing slash if not present and if it is not a file-like with dot
            if add_trailing_slash:
                # avoid adding slash if candidate already ends with slash
                if not candidate.endswith("/"):
                    candidate = candidate + "/"
            # dedupe preserving order
            if candidate not in seen:
                seen[candidate] = True
    return list(seen.keys())

def main():
    parser = argparse.ArgumentParser(description="Convert filename wordlist -> directory-like wordlist")
    parser.add_argument("-i", "--input", required=True, help="Input wordlist file (one entry per line)")
    parser.add_argument("-o", "--output", help="Output file (if omitted, prints to stdout)")
    parser.add_argument("--basename", action="store_true",
                        help="Use only the filename's basename (strip path parts) before removing extensions")
    parser.add_argument("--slash", action="store_true",
                        help="Add trailing slash to each entry (useful for directory fuzzing)")
    parser.add_argument("--lower", action="store_true", help="Lowercase all entries")
    parser.add_argument("--keep-markers", action="store_true",
                        help="Keep entries starting with marker characters like '!' (default: skip them)")
    parser.add_argument("--ext", nargs="+", default=None,
                        help="Extra extensions to consider (space-separated). Will be appended to defaults.")
    args = parser.parse_args()

    ext_list = None
    if args.ext:
        ext_list = DEFAULT_EXTS + args.ext

    out = process_file(args.input,
                       basename_only=args.basename,
                       add_trailing_slash=args.slash,
                       lower=args.lower,
                       ext_list=ext_list,
                       keep_markers=args.keep_markers)

    if args.output:
        with open(args.output, "w", encoding="utf-8") as of:
            for line in out:
                of.write(line + "\n")
        print(f"[+] Wrote {len(out)} entries to {args.output}")
    else:
        for line in out:
            print(line)

if __name__ == "__main__":
    main()
