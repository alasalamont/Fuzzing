#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
clean-directory-wordlist.py
===========================

Mục đích
--------
Chuẩn hoá và làm sạch một wordlist 'directory-like' để dùng với công cụ fuzzing (ví dụ ffuf với /FUZZ/).
Script này chuyển các entry thô thành các đường dẫn hợp lệ (không có scheme/host, không có query/fragment),
loại bỏ các dòng rỗng/nhận xét, chuẩn hoá Unicode, xử lý các trường hợp dot-files / domain-like, và loại bỏ
các entry mang dạng file (ví dụ `index.php`) trừ khi đó là folder version như `v1` hoặc `v1.2`.

Tính năng (mặc định)
--------------------
- Xoá comment (dòng bắt đầu bằng `#`) và dòng rỗng.
- Strip scheme+host (ví dụ `https://example.com/foo` → `foo`).
- Remove query string và fragment (bỏ phần sau `?` hoặc `#`).
- Trim leading / trailing slashes (ffuf sẽ thêm `/` khi dùng `/FUZZ/`).
- Collapse nhiều slash liên tiếp (ví dụ `//a///b` → `a/b`).
- Unicode normalize theo NFKC và map một số Cyrillic homoglyphs sang Latin.
- Loại bỏ các ký tự control/format (BOM, ZWJ, NUL...).
- Chuyển về lowercase **mặc định** (dùng `--iis` để preserve case cho targets Windows/IIS).
- Loại bỏ các entry "file-like" (kết thúc bằng `.ext` với ext 1-6 ký tự) — trừ khi final segment là version folder `v1`, `v1.2`,...
- Xử lý đặc biệt cho **dot-leading entries** (bắt đầu bằng `.`):
  - Mặc định: **emit cả hai biến thể**: có dấu chấm (`.name`) và không dấu (`name`).
  - Mặc định: strip trailing dot-extensions (ví dụ `.example.com` → `.example`).
  - Tuỳ chọn `--no-strip-dot-extensions` để **không** strip `.tld` (giữ `.example.com`).
  - Tuỳ chọn `--drop-leading-dot` để chỉ **emit no-dot variant** (chỉ `name`, không `.name`).
- Percent-encode các kí tự không an toàn (space → `%20`), giữ nguyên `/`.
- Dedupe (giữ thứ tự gốc trừ khi bạn dùng `--sorted`).
- Tuỳ chọn để thêm trailing slash variant (`--add-trailing-variant`).
- Kiểm tra độ dài (mặc định 200 ký tự sau khi encode) và drop khi vượt `--maxlen`.

Các tuỳ chọn CLI (tóm tắt)
--------------------------
--iis                          : preserve case (không lowercase).
--maxlen N                     : độ dài tối đa sau khi percent-encode (mặc định 200).
--add-trailing-variant         : emit thêm biến thể có trailing slash (`entry/`).
--sorted                       : xuất ra theo thứ tự alphabet.
--verbose                      : in lý do drop vào stderr (để debug).
--no-strip-dot-extensions      : KHÔNG strip phần .tld cho các entry bắt đầu bằng dot.
--drop-leading-dot             : KHÔNG emit biến thể có dấu chấm; emit chỉ no-dot variant.

Ví dụ sử dụng
-------------
# cơ bản (mặc định: lowercase, strip dot-ext, emit both dot/no-dot variants)
python3 clean_directory_wordlist.py all_directory_wordlist.txt > final_directory_wordlist.txt

# preserve case (IIS) và thêm trailing slash variants
python3 clean_directory_wordlist.py --iis --add-trailing-variant all_directory_wordlist.txt > final_iis.txt

# chỉ emit no-dot variants (không có .git)
python3 clean_directory_wordlist.py --drop-leading-dot test.txt > final_no_dot.txt

# giữ nguyên dot-extensions (ví dụ .example.com)
python3 clean_directory_wordlist.py --no-strip-dot-extensions test.txt > final_keep_tld.txt

# verbose để xem lý do các dòng bị drop
python3 clean_directory_wordlist.py --verbose all_directory_wordlist.txt > /dev/null 2> drops.log

Ghi chú
------
- Mặc định script sẽ **emit cả `.name` và `name`** cho entry bắt đầu bằng dấu chấm (ví dụ `.git` → `.git` + `git`).
  Nếu bạn muốn chỉ một trong hai, dùng `--drop-leading-dot` để chỉ lấy no-dot variant.
- Nếu bạn cần strip theo Public Suffix List (PSL) chính xác thay vì regex thô (để xử lý tld đặc thù),
  mình có thể tích hợp thư viện `publicsuffix2` — hiện tại script dùng regex đơn giản phù hợp với hầu hết mục đích pentest.
- Script giả định input dùng slash `/` (POSIX). Nếu wordlist chứa backslash `\` (Windows paths), hãy convert trước
  hoặc cho mình biết để mình thêm pre-convert.
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
# Dot-leading behavior:
p.add_argument("--no-strip-dot-extensions", dest="strip_dot_ext", action="store_false",
               help="do NOT strip trailing extensions from leading-dot entries (default: strip them)")
p.add_argument("--drop-leading-dot", dest="drop_leading_dot", action="store_true",
               help="do NOT emit dot-prefixed variant; emit only the no-dot variant")
args = p.parse_args()

# ---------- Patterns ----------
URL_SCHEME_HOST_RE = re.compile(r'^[a-zA-Z][a-zA-Z0-9+\-.]*://[^/]+', re.I)
QUERY_FRAGMENT_RE = re.compile(r'[\?#].*$')
COMMENT_RE = re.compile(r'^\s*#')
MULTI_SLASH_RE = re.compile(r'/+')
FILE_LIKE_RE = re.compile(r'(^|/)[^/]+\.[A-Za-z0-9]{1,6}$')  # ends with .ext (1-6 alnum)
VERSION_RE = re.compile(r'^v\d+(\.\d+)*$', re.I)  # v1 or v1.2 or v1.2.3 (allow v1)
LFI_INDICATORS = re.compile(r'(^|/)\.\.?($|/)')  # any .. or ./ or ../ segments

# strip trailing dot-extensions regex (applies to the part AFTER leading dot)
DOT_EXT_RE = re.compile(r'(?:\.[A-Za-z0-9\-]{1,63})+$')

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

        # --- DOT-LEADING ENTRIES (enhanced handling) ---
        if s.startswith('.'):
            core = s[1:]
            if not core:
                continue

            # case handling
            if not args.iis:
                core = core.lower()

            # optionally strip trailing dot-extensions (e.g. .example.com -> .example)
            if args.strip_dot_ext:
                core = DOT_EXT_RE.sub('', core)

            if not core:
                # nothing left after stripping, skip
                if args.verbose:
                    print(f"[drop dot-empty] {line}", file=sys.stderr)
                continue

            # Build list of variants to emit.
            # Default behavior: emit both ".core" and "core" (dot-prefixed + no-dot)
            variants = []
            if not args.drop_leading_dot:
                variants.append('.' + core)
            # Always emit no-dot variant as well
            variants.append(core)

            # Percent-encode and length-check each variant, then add
            for s_proc in variants:
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
