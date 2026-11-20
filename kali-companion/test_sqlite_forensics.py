"""Tests for the read-only SQLite forensic inspector."""
import os
import sqlite3
import tempfile
import unittest

import sqlite_forensics as sf


def make_db(directory):
    path = os.path.join(directory, "History")
    con = sqlite3.connect(path)
    cur = con.cursor()
    cur.execute("CREATE TABLE urls (id INTEGER, url TEXT, visit_count INTEGER)")
    cur.executemany("INSERT INTO urls VALUES (?,?,?)",
                    [(1, "https://a.com", 3), (2, "https://b.com", 7)])
    cur.execute("CREATE TABLE blobs (id INTEGER, data BLOB)")
    cur.execute("INSERT INTO blobs VALUES (1, ?)", (b"\x00\x01\x02\x03",))
    con.commit()
    con.close()
    return path


class SqliteInspectTests(unittest.TestCase):
    def test_inspect_lists_tables_columns_and_counts(self):
        with tempfile.TemporaryDirectory() as tmp:
            db = make_db(tmp)
            info = sf.inspect_sqlite(db)
            names = {t["name"]: t for t in info["tables"]}
            self.assertEqual(info["table_count"], 2)
            self.assertEqual(names["urls"]["row_count"], 2)
            self.assertEqual(names["urls"]["columns"], ["id", "url", "visit_count"])

    def test_sample_returns_bounded_rows(self):
        with tempfile.TemporaryDirectory() as tmp:
            db = make_db(tmp)
            sample = sf.sample_table(db, "urls", limit=10)
            self.assertEqual(sample["columns"], ["id", "url", "visit_count"])
            self.assertEqual(sample["rows"][0], [1, "https://a.com", 3])

    def test_blob_cells_are_previewed(self):
        with tempfile.TemporaryDirectory() as tmp:
            db = make_db(tmp)
            out = sf.sample_table(db, "blobs", limit=5)
            self.assertEqual(out["rows"][0][1], {"_type": "blob", "length": 4, "hex_prefix": "00010203"})

    def test_unknown_or_injection_table_is_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            db = make_db(tmp)
            with self.assertRaisesRegex(ValueError, "No such table"):
                sf.sample_table(db, "urls; DROP TABLE urls", limit=5)

    def test_rejects_non_sqlite_file(self):
        with tempfile.TemporaryDirectory() as tmp:
            notdb = os.path.join(tmp, "x.bin")
            with open(notdb, "wb") as handle:
                handle.write(b"this is not a sqlite database")
            with self.assertRaisesRegex(ValueError, "Not a SQLite 3 database"):
                sf.inspect_sqlite(notdb)

    def test_limit_is_bounded(self):
        with tempfile.TemporaryDirectory() as tmp:
            db = make_db(tmp)
            with self.assertRaisesRegex(ValueError, "limit must be"):
                sf.sample_table(db, "urls", limit=99999)

    def test_opened_read_only_cannot_write(self):
        # Prove the read-only/immutable open: a write must fail.
        with tempfile.TemporaryDirectory() as tmp:
            db = make_db(tmp)
            con = sf._open_readonly(sf._validate_file(db))
            try:
                with self.assertRaises(sqlite3.OperationalError):
                    con.execute("INSERT INTO urls VALUES (3, 'x', 1)")
            finally:
                con.close()


if __name__ == "__main__":
    unittest.main()
