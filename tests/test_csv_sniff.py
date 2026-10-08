"""Tests for csv-sniff. Run: python3 -m unittest discover -s tests -v"""
import json
import os
import subprocess
import sys
import tempfile
import unittest

HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SCRIPT = os.path.join(HERE, "csv_sniff.py")
PY = sys.executable

COMMA = (
    "name,age,city,total_spend,signup_date\n"
    "Alice,34,Shanghai,\"1,234.50\",2024-01-05\n"
    "Bob,,Beijing,890.00,2024-02-11\n"
    "Cara,41,Shenzhen,,2024-03-02\n"
)


def write(tmp, name, data, encoding="utf-8"):
    path = os.path.join(tmp, name)
    if isinstance(data, str):
        data = data.encode(encoding)
    with open(path, "wb") as fh:
        fh.write(data)
    return path


def run(args, cwd=HERE):
    return subprocess.run([PY, SCRIPT] + args, capture_output=True, text=True, cwd=cwd)


def as_json(args):
    r = run(args + ["--json"])
    return r, json.loads(r.stdout)


class TestCsvSniff(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()

    # --- encoding -------------------------------------------------------
    def test_utf8_no_bom(self):
        p = write(self.tmp, "plain.csv", COMMA)
        r, d = as_json([p])
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertEqual(d["encoding"], "utf-8")
        self.assertEqual(d["delimiter"], ",")

    def test_utf8_with_bom(self):
        p = write(self.tmp, "bom.csv", "\ufeff" + COMMA)
        _, d = as_json([p])
        self.assertEqual(d["encoding"], "utf-8-sig")

    def test_cp1252_with_decimal_comma(self):
        rows = ["artikel;preis;menge", "Cafe Crema;1,50;3", "Milchkaffee;2,75;1",
                "Espresso;0,90;12", "Latte;3,10;2", "Tee;1,20;5"]
        data = ("\n".join(rows) + "\n").encode("cp1252")
        data = data.replace(b"Cafe", b"Caf\xe9")  # 0xe9 is only valid in cp1252
        p = write(self.tmp, "euro.csv", data)
        r, d = as_json([p])
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertEqual(d["encoding"], "cp1252")
        self.assertEqual(d["delimiter"], ";")
        self.assertTrue(d["decimal_comma"])

    def test_gbk_chinese(self):
        rows = ["姓名,年龄,城市", "张三,30,上海", "李四,45,北京", "王五,28,广州", "赵六,51,深圳"]
        p = write(self.tmp, "cn.csv", ("\n".join(rows) + "\n").encode("gb18030"))
        r, d = as_json([p])
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertEqual(d["encoding"], "gb18030")
        self.assertEqual(d["delimiter"], ",")
        self.assertEqual(d["fields_per_row"], 3)

    def test_utf16_with_bom(self):
        p = write(self.tmp, "u16.csv", COMMA.encode("utf-16"))
        _, d = as_json([p])
        self.assertIn("utf-16", d["encoding"])

    # --- delimiter ------------------------------------------------------
    def test_tab_delimiter(self):
        p = write(self.tmp, "t.tsv", "a\tb\tc\n1\t2\t3\n4\t5\t6\n")
        _, d = as_json([p])
        self.assertEqual(d["delimiter"], "\t")
        self.assertEqual(d["fields_per_row"], 3)

    def test_pipe_delimiter(self):
        p = write(self.tmp, "p.txt", "a|b|c\n1|2|3\n4|5|6\n")
        _, d = as_json([p])
        self.assertEqual(d["delimiter"], "|")

    def test_single_column(self):
        p = write(self.tmp, "one.txt", "alpha\nbeta\ngamma\ndelta\n")
        r, d = as_json([p])
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIsNone(d["delimiter"])
        self.assertTrue(any("no delimiter" in w for w in d["warnings"]))

    # --- quotes and structure -------------------------------------------
    def test_quoted_field_with_comma_and_newline(self):
        data = 'id,note,total\n1,"hello, world",10\n2,"two\nlines here",20\n3,plain,30\n'
        p = write(self.tmp, "q.csv", data)
        _, d = as_json([p])
        self.assertEqual(d["delimiter"], ",")
        self.assertEqual(d["fields_per_row"], 3)
        self.assertEqual(d["quotechar"], '"')
        self.assertEqual(d["ragged_count"], 0)

    def test_doubled_quotes_detected(self):
        data = 'id,note\n1,"he said ""hi"""\n2,plain\n'
        p = write(self.tmp, "dq.csv", data)
        _, d = as_json([p])
        self.assertTrue(d["doublequote"])

    def test_crlf_line_endings(self):
        p = write(self.tmp, "crlf.csv", "a,b\r\n1,2\r\n3,4\r\n")
        _, d = as_json([p])
        self.assertEqual(d["line_endings"], "CRLF")

    def test_ragged_rows_are_reported(self):
        data = "a,b,c\n1,2,3\n4,5\n6,7,8\n"
        p = write(self.tmp, "ragged.csv", data)
        _, d = as_json([p])
        self.assertEqual(d["ragged_count"], 1)
        self.assertEqual(d["ragged_rows"][0]["record"], 3)

    def test_header_yes_and_no(self):
        p1 = write(self.tmp, "h1.csv", COMMA)
        _, d1 = as_json([p1])
        self.assertTrue(d1["header"])
        p2 = write(self.tmp, "h2.csv", "1,2,3\n4,5,6\n7,8,9\n")
        _, d2 = as_json([p2])
        self.assertFalse(d2["header"])

    # --- interface ------------------------------------------------------
    def test_json_contract(self):
        p = write(self.tmp, "c.csv", COMMA)
        r, d = as_json([p])
        for key in ("file", "encoding", "encoding_candidates", "delimiter", "fields_per_row",
                    "quotechar", "line_endings", "header", "ragged_count", "snippet", "warnings"):
            self.assertIn(key, d, "missing key %s" % key)
        self.assertIn("pandas", d["snippet"])
        self.assertIn("pd.read_csv", d["snippet"]["pandas"][1])

    def test_human_output_has_snippet(self):
        p = write(self.tmp, "c.csv", COMMA)
        r = run([p])
        self.assertIn("read it with:", r.stdout)
        self.assertIn("pd.read_csv", r.stdout)

    def test_emitted_stdlib_snippet_is_valid_python(self):
        p = write(self.tmp, "c.csv", COMMA)
        _, d = as_json([p])
        code = "\n".join(d["snippet"]["stdlib"])
        compile(code, "<snippet>", "exec")  # raises SyntaxError if the snippet is broken

    def test_emitted_pandas_snippet_is_valid_python(self):
        p = write(self.tmp, "c.csv", COMMA)
        _, d = as_json([p])
        code = "\n".join(d["snippet"]["pandas"])
        compile(code, "<snippet>", "exec")

    def test_stdin(self):
        p = write(self.tmp, "c.csv", COMMA)
        with open(p, "rb") as fh:
            raw = fh.read()
        r = subprocess.run([PY, SCRIPT, "-", "--json"], input=raw, capture_output=True)
        self.assertEqual(r.returncode, 0, r.stderr)
        d = json.loads(r.stdout.decode())
        self.assertEqual(d["file"], "<stdin>")
        self.assertEqual(d["delimiter"], ",")

    def test_missing_file_exit_2(self):
        r = run([os.path.join(self.tmp, "nope.csv")])
        self.assertEqual(r.returncode, 2)

    def test_empty_file_exit_1(self):
        p = write(self.tmp, "empty.csv", b"")
        r = run([p])
        self.assertEqual(r.returncode, 1)


if __name__ == "__main__":
    unittest.main()
