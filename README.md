# csv-sniff

**Work out how to read a CSV that will not load.** One command, no dependencies.

Python 3.8+ standard library only. One file, zero install.

```
$ csv-sniff export.csv

file       : export.csv (365 B)
encoding   : cp1252   [strict cp1252 decode, best text score 0.53 (next: latin-1 0.53)]
delimiter  : ';'   (7 fields per row, 100% of 6 sampled records agree)
quotechar  : "  ("" doubling inside quoted fields)
line ends  : LF
header     : yes   (row 1 is all non-numeric unique labels; body has numeric or mixed values)
warning    : non-ASCII text decoded as cp1252 - check accents or non-Latin scripts
warning    : encoding is ambiguous: cp1252 (0.53) vs latin-1 (0.53) - open the file and check accented characters
warning    : comma appears to be the decimal separator; use decimal=',' when parsing numbers

read it with:
    import pandas as pd
    df = pd.read_csv("export.csv", sep=';', encoding="cp1252", quotechar='"', decimal=',')

or with the standard library:
    import csv
    with open("export.csv", encoding="cp1252", newline="") as f:
        reader = csv.reader(f, delimiter=';')
        for row in reader:
            print(row)
```

## Why

Every broken import starts the same way: the file opens, and the columns are wrong.
The usual causes are always the same five, and none of them are visible in a text editor.

`csv-sniff` looks at the bytes and answers them:

| Question | How it answers |
|---|---|
| **Encoding** | BOM check first, then a strict decode of `utf-8 / cp1252 / gb18030 / big5 / cp932`, scored by how much the result reads as text. Alternatives are printed, so you can see the runner-up. |
| **Delimiter** | Every candidate (`, ; tab \| ^ ~`) is scored by how consistently it gives the same field count. A hunch is not used. |
| **Quote character** | Whether `"` quoting is present, and whether `""` doubling is used inside fields. |
| **Header row** | Whether row 1 is column names or data, with the reason printed. |
| **Line endings** | LF, CRLF, CR, or a mix. |

Then it prints a reader snippet you can paste into pandas or into plain `csv`.

## Install

```bash
# no install needed
curl -O https://raw.githubusercontent.com/CindyLiao1106/csv-sniff/main/csv_sniff.py
python3 csv_sniff.py export.csv

# or keep it as a command
chmod +x csv_sniff.py && mv csv_sniff.py ~/.local/bin/csv-sniff
```

## Usage

```bash
csv-sniff data.csv                 # full report
csv-sniff data.csv --json          # machine-readable, for scripts and agents
csv-sniff data.csv --rows 2000     # scan more records
csv-sniff data.csv --sample-bytes 10485760   # sample 10 MB instead of 2 MB
cat data.csv | csv-sniff -          # read from a pipe
```

Exit codes: `0` report produced, `1` empty input, `2` no such file.

### JSON output

```json
{
  "encoding": "cp1252",
  "encoding_candidates": [["cp1252", 0.68], ["utf-8", 0.31]],
  "delimiter": ";",
  "fields_per_row": 7,
  "consistency": 1.0,
  "quotechar": "\"",
  "line_endings": "CRLF",
  "header": true,
  "ragged_count": 0,
  "decimal_comma": true,
  "warnings": ["comma appears to be the decimal separator; use decimal=',' when parsing numbers"],
  "snippet": {"pandas": ["..."], "stdlib": ["..."]}
}
```

The JSON shape is stable. Field-level scripts and agents can rely on it.

## What it does not do

- It does not read the whole file. It samples the first 2 MB (adjustable).
- It does not guess. When two encodings score close together, it says so in `warnings`
  instead of pretending to be sure.
- It does not fix the file. It tells you how to read it.
  To clean the data itself, use the [free browser CSV cleaner](https://nocodecsv.com/tools/csv-cleaner).
- It does not validate against a schema. It tells you what the file *looks like*.

## Pairs well with

- [csv-peek](https://github.com/CindyLiao1106/csv-peek) — profile what is **inside** the file
  (types, nulls, duplicates). `csv-sniff` tells you how to open it; `csv-peek` tells you what is in it.
- Reading a CSV in Python, step by step:
  [Open a CSV file in Python](https://nocodecsv.com/blog/open-csv-file-in-python)
- Reading a CSV on a server without pandas:
  [Open a CSV file in Linux](https://nocodecsv.com/blog/open-csv-file-in-linux)
- No-code route, if you just need the file cleaned:
  [CSV Cleaner](https://nocodecsv.com/tools/csv-cleaner)

## Tests

```bash
python3 -m unittest discover -s tests -v
```

20 tests cover BOM, cp1252, GB18030, UTF-16, tab/pipe delimiters, quoted fields with
embedded commas and newlines, doubled quotes, CRLF, ragged rows, header detection,
stdin, JSON contract, exit codes, and the emitted snippets.

## License

MIT — see [LICENSE](LICENSE).

Built to scratch a real itch while working with Excel exports. If it saved you ten
minutes, a star helps other people find it.
