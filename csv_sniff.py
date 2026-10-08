#!/usr/bin/env python3
"""
csv-sniff - work out HOW to read a CSV/TSV that will not load cleanly.

Zero dependencies (Python 3.8+ standard library only).

It answers the questions that break a first import:

    · encoding      utf-8? utf-8-sig? cp1252? GBK? (byte evidence, not a guess list)
    · delimiter     , ; tab | ^ (scored by field-count consistency, not by a hunch)
    · quotechar     '"' or none, and whether "" doubling is used
    · line endings  LF / CRLF / CR / mixed
    · header row    yes/no, with a reason
    · ragged rows   rows whose field count differs from the rest
    · decimal comma "," used as decimal separator inside fields

and prints a ready-to-paste reader snippet (pandas and stdlib).

Usage:
    csv-sniff data.csv
    csv-sniff data.csv --json
    csv-sniff data.csv --rows 500
    cat data.csv | csv-sniff -

Why: csv-peek tells you WHAT is inside a file. csv-sniff tells you HOW to open it.
"""
import argparse
import codecs
import csv
import io
import json
import os
import sys
from collections import Counter

__version__ = "0.1.0"

DELIMITERS = [",", ";", "\t", "|", "^", "~"]
SAMPLE_BYTES = 2 * 1024 * 1024
SCAN_RECORDS = 400

# Strict-decoding candidates, in order of how much we trust them.
ENCODINGS = [
    ("utf-8", "Unicode, no BOM"),
    ("cp1252", "Windows Western Europe (legacy Excel export)"),
    ("gb18030", "Chinese (GBK / GB2312 superset)"),
    ("big5", "Traditional Chinese"),
    ("cp932", "Japanese Shift-JIS"),
    ("latin-1", "ISO-8859-1 - never fails, so it is the last resort"),
]

NUMERIC_HINT = set("0123456789+-.")


def detect_bom(raw):
    """Return (encoding, label) if a BOM is present, else (None, None)."""
    if raw.startswith(codecs.BOM_UTF8):
        return "utf-8-sig", "UTF-8 with BOM"
    if raw.startswith(codecs.BOM_UTF32_LE) or raw.startswith(codecs.BOM_UTF32_BE):
        return "utf-32", "UTF-32 with BOM"
    if raw.startswith(codecs.BOM_UTF16_LE):
        return "utf-16", "UTF-16 with BOM (little-endian)"
    if raw.startswith(codecs.BOM_UTF16_BE):
        return "utf-16", "UTF-16 with BOM (big-endian)"
    return None, None


def text_score(text):
    """How much a decoded sample looks like real text (0..~3, higher is better)."""
    n = max(len(text), 1)
    cjk = 0
    latin_hi = 0
    ctrl = 0
    for ch in text:
        o = ord(ch)
        if 0x4E00 <= o <= 0x9FFF or 0x3040 <= o <= 0x30FF or 0xAC00 <= o <= 0xD7AF:
            cjk += 1
        elif 0x00A0 <= o <= 0x00FF:
            latin_hi += 1
        elif o < 32 and ch not in "\r\n\t":
            ctrl += 1
    ascii_alpha = sum(1 for ch in text if ch.isascii() and ch.isalpha())
    return (3.0 * cjk + 1.0 * ascii_alpha + 0.5 * latin_hi - 10.0 * ctrl) / n


def detect_encoding(raw):
    """Pick an encoding with byte-level evidence. Return (encoding, label, evidence, ranked)."""
    enc, label = detect_bom(raw)
    if enc:
        try:
            raw.decode(enc)
            return enc, label, "byte-order mark at offset 0", [(enc, 1.0)]
        except UnicodeDecodeError:
            pass  # broken BOM - fall through to the normal search

    # NUL bytes without a usable BOM: almost certainly UTF-16.
    if b"\x00" in raw:
        for cand in ("utf-16", "utf-16-le", "utf-16-be"):
            try:
                text = raw.decode(cand)
                if text.count("\x00") == 0:
                    return (
                        cand,
                        "UTF-16 (NUL byte pattern, no BOM)",
                        "NUL bytes every other byte",
                        [(cand, 1.0)],
                    )
            except UnicodeDecodeError:
                continue

    ranked = []
    for cand, cand_label in ENCODINGS:
        try:
            text = raw.decode(cand)
        except UnicodeDecodeError:
            continue
        score = text_score(text)
        if cand == "utf-8":
            score += 0.15  # small prior: utf-8 is the modern default
        ranked.append((score, cand, cand_label))
    if not ranked:
        return "latin-1", "ISO-8859-1", "no strict decode worked; byte-preserving fallback", [("latin-1", 0.0)]

    ranked.sort(key=lambda r: -r[0])
    best_score, best_enc, best_label = ranked[0]
    evidence = "strict %s decode, best text score %.2f" % (best_enc, best_score)
    if len(ranked) > 1:
        evidence += " (next: %s %.2f)" % (ranked[1][1], ranked[1][0])
    table = [(enc, round(sc, 3)) for sc, enc, _ in ranked[:4]]
    return best_enc, best_label, evidence, table


def decode_sample(raw, encoding):
    """Decode with the chosen encoding; fall back to replacement chars if needed."""
    try:
        return raw.decode(encoding)
    except (UnicodeDecodeError, LookupError):
        return raw.decode(encoding, errors="replace")


def record_counts(text, delimiter, limit=SCAN_RECORDS):
    """Field count of the first N records when splitting on `delimiter`."""
    counts = []
    try:
        reader = csv.reader(io.StringIO(text), delimiter=delimiter)
        for i, row in enumerate(reader):
            if i >= limit:
                break
            counts.append(len(row))
    except csv.Error:
        return counts
    return counts


def score_delimiter(counts, limit=SCAN_RECORDS):
    """Score a delimiter by how consistently it yields the same field count."""
    useful = [c for c in counts if c >= 2]
    if not useful:
        return 0.0, 1
    modal, modal_n = Counter(useful).most_common(1)[0]
    if modal < 2:
        return 0.0, modal
    # Consistency is the main signal; a mild bonus for more usable rows.
    consistency = modal_n / len(counts)
    coverage = modal_n / max(limit, 1)
    return consistency * (1.0 + 0.25 * min(coverage, 1.0)), modal


def pick_delimiter(text, limit=SCAN_RECORDS):
    best = None
    table = []
    for cand in DELIMITERS:
        counts = record_counts(text, cand, limit)
        score, modal = score_delimiter(counts, limit)
        table.append({"delimiter": cand, "score": round(score, 4), "fields": modal, "usable": len(counts)})
        if best is None or score > best[1]:
            best = (cand, score, modal, counts)
    cand, score, modal, counts = best
    return (cand, modal, counts, table) if score > 0 else (None, 1, counts, table)


def detect_quotechar(text):
    has_double = '"' in text
    has_single_quote_field = text.count("'") > 0 and '"' not in text
    doubled = '""' in text
    escaped = text.count('\\"') > text.count('""')
    return {
        "quotechar": '"' if has_double else "",
        "doublequote": bool(doubled),
        "escapechar": "\\" if escaped else "",
        "note": "single quotes present but no double quotes; they are probably text, not quoting"
        if has_single_quote_field
        else "",
    }


def detect_line_endings(raw):
    crlf = raw.count(b"\r\n")
    lone_cr = raw.count(b"\r") - crlf
    lf = raw.count(b"\n") - crlf
    names = []
    if crlf:
        names.append("CRLF")
    if lf:
        names.append("LF")
    if lone_cr:
        names.append("CR")
    if not names:
        return "none", names
    return ("mixed (%s)" % " + ".join(names)) if len(names) > 1 else names[0], names


def looks_numeric(value):
    v = value.strip()
    if not v:
        return False
    if v[0] in "+-":
        v = v[1:]
    if not v or v[0] not in NUMERIC_HINT:
        return False
    body = v.replace(",", "").replace(".", "").replace(" ", "")
    return bool(body) and all(ch.isdigit() for ch in body)


def detect_header(rows):
    """Decide whether row 1 is a header, and say why."""
    if not rows:
        return None, "no rows read"
    first = [c.strip() for c in rows[0]]
    if len(first) < 2:
        return None, "only one column"
    if any(not c for c in first):
        return False, "first row has empty cells, so it is probably data"
    if len(set(first)) != len(first):
        return False, "first row has duplicate names, so it is probably data"
    if sum(1 for c in first if looks_numeric(c)) >= max(1, len(first) // 3):
        return False, "several cells in the first row are numeric"
    body = rows[1:1 + 50]
    if not body:
        return None, "no body rows to compare against"
    body_numeric = 0
    for row in body:
        if row and looks_numeric(row[0]):
            body_numeric += 1
    if body_numeric and not looks_numeric(first[0]):
        return True, "row 1 is all non-numeric unique labels; body has numeric or mixed values"
    if all(not any(looks_numeric(c) for c in row) for row in body[:10]):
        return True, "row 1 and body are both text; row 1 reads as column names"
    return True, "no numeric column found in row 1 but the body has numbers"


def find_ragged(rows, modal_fields):
    ragged = []
    for i, row in enumerate(rows, start=1):
        if len(row) != modal_fields:
            ragged.append({"record": i, "fields": len(row), "preview": row[:4]})
    return ragged


def is_plain_number(text):
    t = text.strip()
    if not t:
        return False
    if t[0] in "+-":
        t = t[1:]
    if not t:
        return False
    core = t.replace(",", "").replace(".", "").replace(" ", "")
    return bool(core) and core.isdigit()


def detect_decimal_comma(rows, delimiter):
    """Look at number-like cells only, so text cells cannot water down the ratio."""
    if delimiter != ";":
        return False
    number_cells = 0
    comma_decimals = 0
    for row in rows[1:101]:
        for cell in row:
            if not is_plain_number(cell):
                continue
            number_cells += 1
            c = cell.strip()
            if "," in c and "." not in c:
                comma_decimals += 1
    return number_cells >= 5 and comma_decimals / number_cells > 0.3


def build_snippet(fname, encoding, delimiter, quotechar, has_header, decimal_comma):
    sep = "\\t" if delimiter == "\t" else delimiter
    enc = "utf-8-sig" if encoding == "utf-8-sig" else encoding
    pandas_kwargs = ["sep=%r" % sep, 'encoding="%s"' % enc]
    if quotechar:
        pandas_kwargs.append("quotechar=%r" % quotechar)
    if decimal_comma:
        pandas_kwargs.append("decimal=','")
    if not has_header:
        pandas_kwargs.append("header=None")
    pandas_lines = [
        "import pandas as pd",
        'df = pd.read_csv("%s", %s)' % (fname, ", ".join(pandas_kwargs)),
    ]
    stdlib_lines = [
        "import csv",
        'with open("%s", encoding="%s", newline="") as f:' % (fname, enc),
        "    reader = csv.reader(f, delimiter=%r)" % sep,
        "    for row in reader:",
        "        print(row)",
    ]
    return {"pandas": pandas_lines, "stdlib": stdlib_lines}


def sniff_bytes(raw, fname, sample_label, limit=SCAN_RECORDS):
    encoding, enc_label, enc_evidence, enc_table = detect_encoding(raw)
    text = decode_sample(raw, encoding)
    delimiter, modal_fields, counts, table = pick_delimiter(text, limit)
    quote = detect_quotechar(text)
    ending, endings = detect_line_endings(raw)
    if delimiter is None:
        rows = [[line] for line in text.splitlines() if line.strip()][:limit]
        modal_fields = max(1, len(rows[0]) if rows else 1)
    else:
        rows = list(csv.reader(io.StringIO(text), delimiter=delimiter))[:limit]
    header, header_reason = detect_header(rows)
    ragged = find_ragged(rows, modal_fields) if delimiter else []
    decimal_comma = detect_decimal_comma(rows, delimiter) if delimiter else False

    warnings = []
    if encoding in ("latin-1", "cp1252") and any(ord(ch) > 127 for ch in text):
        warnings.append("non-ASCII text decoded as %s - check accents or non-Latin scripts" % encoding)
    if encoding == "latin-1":
        warnings.append("latin-1 is a fallback and may be the wrong encoding")
    if len(enc_table) > 1 and encoding not in ("utf-8", "utf-8-sig", "utf-16") and enc_table[0][1] - enc_table[1][1] < 0.15:
        warnings.append(
            "encoding is ambiguous: %s (%.2f) vs %s (%.2f) - open the file and check accented characters"
            % (enc_table[0][0], enc_table[0][1], enc_table[1][0], enc_table[1][1])
        )
    if delimiter is None:
        warnings.append("no delimiter found - this looks like a single-column file")
    if ragged:
        warnings.append("%d row(s) have a different number of fields" % len(ragged))
    if decimal_comma:
        warnings.append("comma appears to be the decimal separator; use decimal=',' when parsing numbers")

    return {
        "file": fname,
        "sample": sample_label,
        "encoding": encoding,
        "encoding_label": enc_label,
        "encoding_evidence": enc_evidence,
        "encoding_candidates": enc_table,
        "confidence": enc_table[0][1] if enc_table else None,
        "delimiter": delimiter,
        "delimiter_table": table,
        "fields_per_row": modal_fields,
        "consistency": (
            round(Counter([c for c in counts if c >= 2]).most_common(1)[0][1] / max(len(counts), 1), 4)
            if delimiter
            else None
        ),
        "quotechar": quote["quotechar"],
        "doublequote": quote["doublequote"],
        "escapechar": quote["escapechar"],
        "line_endings": ending,
        "header": header,
        "header_reason": header_reason,
        "rows_scanned": len(rows),
        "ragged_rows": ragged[:5],
        "ragged_count": len(ragged),
        "decimal_comma": decimal_comma,
        "warnings": warnings,
        "snippet": build_snippet(fname, encoding, delimiter or ",", quote["quotechar"], header, decimal_comma),
    }


def read_input(path, sample_bytes):
    if path == "-":
        raw = sys.stdin.buffer.read(sample_bytes)
        return raw, "<stdin>"
    with open(path, "rb") as fh:
        raw = fh.read(sample_bytes)
    return raw, path


def human_size(n):
    for unit in ("B", "KB", "MB", "GB"):
        if n < 1024 or unit == "GB":
            return "%.1f %s" % (n, unit) if unit != "B" else "%d B" % n
        n /= 1024.0


def render(result, size):
    lines = []
    lines.append("")
    lines.append("file       : %s (%s)" % (result["file"], human_size(size)))
    lines.append("encoding   : %s   [%s]" % (result["encoding"], result["encoding_evidence"]))
    if result["delimiter"]:
        delim = "\\t" if result["delimiter"] == "\t" else result["delimiter"]
        lines.append(
            "delimiter  : '%s'   (%s fields per row, %s of %s sampled records agree)"
            % (
                delim,
                result["fields_per_row"],
                "%.0f%%" % (100 * result["consistency"]) if result["consistency"] is not None else "-",
                result["rows_scanned"],
            )
        )
    else:
        lines.append("delimiter  : none found (single column or not tabular)")
    lines.append(
        "quotechar  : %s%s"
        % (
            result["quotechar"] or "none",
            "  (\"\" doubling inside quoted fields)" if result["doublequote"] else "",
        )
    )
    if result["escapechar"]:
        lines.append("escapechar : %s" % result["escapechar"])
    lines.append("line ends  : %s" % result["line_endings"])
    lines.append(
        "header     : %s   (%s)"
        % ({True: "yes", False: "no", None: "unclear"}[result["header"]], result["header_reason"])
    )
    if result["ragged_count"]:
        lines.append("ragged rows: %d  e.g. %s" % (result["ragged_count"], result["ragged_rows"][:3]))
    for w in result["warnings"]:
        lines.append("warning    : %s" % w)
    lines.append("")
    lines.append("read it with:")
    for ln in result["snippet"]["pandas"]:
        lines.append("    " + ln)
    lines.append("")
    lines.append("or with the standard library:")
    for ln in result["snippet"]["stdlib"]:
        lines.append("    " + ln)
    lines.append("")
    return "\n".join(lines)


def main(argv=None):
    ap = argparse.ArgumentParser(
        prog="csv-sniff",
        description="Work out how to read a messy CSV/TSV: encoding, delimiter, quotes, header.",
    )
    ap.add_argument("path", help="file to inspect, or - for stdin")
    ap.add_argument("--json", action="store_true", help="print machine-readable JSON")
    ap.add_argument("--rows", type=int, default=SCAN_RECORDS, help="records to scan (default %d)" % SCAN_RECORDS)
    ap.add_argument("--sample-bytes", type=int, default=SAMPLE_BYTES, help="bytes to sample (default 2MB)")
    ap.add_argument("--version", action="version", version="csv-sniff %s" % __version__)
    args = ap.parse_args(argv)

    limit = max(20, args.rows)

    if args.path != "-" and not os.path.exists(args.path):
        sys.stderr.write("csv-sniff: no such file: %s\n" % args.path)
        return 2

    raw, fname = read_input(args.path, args.sample_bytes)
    if not raw:
        sys.stderr.write("csv-sniff: file is empty\n")
        return 1

    size = len(raw) if args.path == "-" else os.path.getsize(args.path)
    result = sniff_bytes(raw, fname, "first %s" % human_size(len(raw)), limit)
    if args.json:
        result["file_size"] = size
        print(json.dumps(result, ensure_ascii=False, indent=2))
    else:
        print(render(result, size))
    return 0


if __name__ == "__main__":
    sys.exit(main())
