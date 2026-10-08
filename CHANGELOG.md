# Changelog

## 0.1.0 — 2026-10-09

First release.

- Encoding detection with byte evidence: BOM (UTF-8/16/32), NUL-byte UTF-16, then a
  strict decode of utf-8 / cp1252 / gb18030 / big5 / cp932 / latin-1, scored by how
  much the decoded text reads as text. Runner-up encodings are reported.
- Delimiter detection by field-count consistency across `, ; TAB | ^ ~`, not by a hunch.
- Quote character and `""` doubling detection, plus `\` escape detection.
- Line ending detection: LF, CRLF, CR, mixed.
- Header row detection with a printed reason.
- Ragged row detection with record numbers and a preview.
- Decimal-comma detection (`;`-separated European exports) and a `decimal=','` hint.
- Ready-to-paste reader snippets for pandas and the standard library.
- `--json` output with a stable shape, `--rows` and `--sample-bytes` controls, stdin support.
- 20 unit tests, standard library only.
