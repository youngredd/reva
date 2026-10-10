"""Persistent project database - the IDA-style .idb equivalent.

Everything the analysis learns, plus everything the analyst (me) decides, lives
here and survives across sessions.
"""
from __future__ import annotations

import json
import os
import sqlite3
import time

SCHEMA = """
PRAGMA journal_mode=WAL;
PRAGMA synchronous=NORMAL;

CREATE TABLE IF NOT EXISTS meta (
    key   TEXT PRIMARY KEY,
    value TEXT
);

-- symbol names at an address. one name per va; source records provenance so
-- auto-analysis never clobbers a name I chose by hand.
CREATE TABLE IF NOT EXISTS names (
    va     INTEGER PRIMARY KEY,
    name   TEXT NOT NULL,
    source TEXT NOT NULL DEFAULT 'auto',
    demangled TEXT
);
CREATE INDEX IF NOT EXISTS names_name ON names(name);

CREATE TABLE IF NOT EXISTS comments (
    va   INTEGER NOT NULL,
    kind TEXT NOT NULL DEFAULT 'line',   -- line | pre | post
    text TEXT NOT NULL,
    PRIMARY KEY (va, kind)
);

CREATE TABLE IF NOT EXISTS functions (
    va        INTEGER PRIMARY KEY,
    end       INTEGER,
    size      INTEGER,
    source    TEXT,
    flags     TEXT,                      -- json list: noreturn, thunk, library...
    cc        TEXT,
    prototype TEXT,
    nblocks   INTEGER,
    ninsn     INTEGER,
    stack_size INTEGER,
    fingerprint TEXT                     -- json behavioural summary
);
CREATE INDEX IF NOT EXISTS functions_end ON functions(end);

-- basic blocks, so CFG survives without re-analysis
CREATE TABLE IF NOT EXISTS blocks (
    va    INTEGER PRIMARY KEY,
    func  INTEGER NOT NULL,
    end   INTEGER NOT NULL,
    succs TEXT,                          -- json list of VAs
    kind  TEXT                           -- ret|call|jmp|cond|tail|indirect
);
CREATE INDEX IF NOT EXISTS blocks_func ON blocks(func);

CREATE TABLE IF NOT EXISTS xrefs (
    frm  INTEGER NOT NULL,
    dst  INTEGER NOT NULL,
    kind TEXT NOT NULL,                  -- call|jump|read|write|offset|ptr
    PRIMARY KEY (frm, dst, kind)
);
CREATE INDEX IF NOT EXISTS xrefs_dst ON xrefs(dst, kind);

CREATE TABLE IF NOT EXISTS strings (
    va   INTEGER PRIMARY KEY,
    enc  TEXT NOT NULL,                  -- ascii|utf16|utf8
    len  INTEGER NOT NULL,
    text TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS strings_text ON strings(text);

CREATE TABLE IF NOT EXISTS imports (
    va      INTEGER PRIMARY KEY,         -- IAT slot
    dll     TEXT, name TEXT, ordinal INTEGER, kind TEXT,
    thunk   INTEGER                      -- jmp-thunk VA that forwards here
);
CREATE INDEX IF NOT EXISTS imports_name ON imports(name);
CREATE INDEX IF NOT EXISTS imports_thunk ON imports(thunk);

CREATE TABLE IF NOT EXISTS exports (
    va INTEGER, name TEXT, ordinal INTEGER, forwarder TEXT
);

-- user-defined types (C declarations, parsed into a json layout)
CREATE TABLE IF NOT EXISTS types (
    name TEXT PRIMARY KEY,
    kind TEXT,                           -- struct|union|enum|typedef|func
    decl TEXT,
    layout TEXT
);

-- typed data items: tells the renderer how to show a data address
CREATE TABLE IF NOT EXISTS data_items (
    va    INTEGER PRIMARY KEY,
    type  TEXT NOT NULL,
    count INTEGER DEFAULT 1
);

CREATE TABLE IF NOT EXISTS vtables (
    va INTEGER PRIMARY KEY,
    nslots INTEGER,
    class_name TEXT,
    slots TEXT                           -- json list of VAs
);

CREATE TABLE IF NOT EXISTS bookmarks (
    va INTEGER PRIMARY KEY,
    note TEXT,
    ts INTEGER
);

-- free-form analyst notes keyed by topic, so findings accumulate
CREATE TABLE IF NOT EXISTS notes (
    topic TEXT PRIMARY KEY,
    body  TEXT,
    ts    INTEGER
);

-- staged binary patches, kept reviewable and revertible until written out
CREATE TABLE IF NOT EXISTS patches (
    va       INTEGER PRIMARY KEY,
    original BLOB NOT NULL,
    patched  BLOB NOT NULL,
    note     TEXT,
    ts       INTEGER
);

-- jump tables resolved during analysis
CREATE TABLE IF NOT EXISTS jumptables (
    va      INTEGER PRIMARY KEY,         -- the indirect jmp
    base    INTEGER,
    count   INTEGER,
    targets TEXT
);
"""


class ProjectDB:
    def __init__(self, path: str):
        self.path = path
        new = not os.path.exists(path)
        os.makedirs(os.path.dirname(path), exist_ok=True)
        self.con = sqlite3.connect(path, check_same_thread=False)
        self.con.row_factory = sqlite3.Row
        self.con.executescript(SCHEMA)
        self.con.commit()
        self.is_new = new

    # ---- meta ---------------------------------------------------------
    def set_meta(self, key: str, value) -> None:
        self.con.execute("INSERT OR REPLACE INTO meta VALUES (?,?)",
                         (key, json.dumps(value)))

    def get_meta(self, key: str, default=None):
        r = self.con.execute("SELECT value FROM meta WHERE key=?", (key,)).fetchone()
        return json.loads(r["value"]) if r else default

    # ---- names --------------------------------------------------------
    # precedence: user names are never overwritten by analysis
    SRC_RANK = {"user": 100, "export": 60, "import": 60, "rtti": 50,
                "pdb": 55, "string_ref": 30, "auto": 10, "guess": 5}

    def set_name(self, va: int, name: str, source: str = "auto",
                 demangled: str | None = None) -> bool:
        cur = self.con.execute("SELECT name, source FROM names WHERE va=?",
                               (va,)).fetchone()
        if cur:
            if self.SRC_RANK.get(source, 0) < self.SRC_RANK.get(cur["source"], 0):
                return False
        self.con.execute("INSERT OR REPLACE INTO names VALUES (?,?,?,?)",
                         (va, name, source, demangled))
        return True

    def get_name(self, va: int) -> str | None:
        r = self.con.execute("SELECT name FROM names WHERE va=?", (va,)).fetchone()
        return r["name"] if r else None

    def names_bulk(self, vas) -> dict[int, str]:
        vas = list({int(v) for v in vas})
        out: dict[int, str] = {}
        for i in range(0, len(vas), 900):
            chunk = vas[i:i + 900]
            q = ",".join("?" * len(chunk))
            for r in self.con.execute(
                    f"SELECT va,name FROM names WHERE va IN ({q})", chunk):
                out[r["va"]] = r["name"]
        return out

    def resolve_name(self, name: str) -> int | None:
        r = self.con.execute("SELECT va FROM names WHERE name=? COLLATE NOCASE",
                             (name,)).fetchone()
        return r["va"] if r else None

    # ---- comments -----------------------------------------------------
    def set_comment(self, va: int, text: str, kind: str = "line") -> None:
        if text:
            self.con.execute("INSERT OR REPLACE INTO comments VALUES (?,?,?)",
                             (va, kind, text))
        else:
            self.con.execute("DELETE FROM comments WHERE va=? AND kind=?", (va, kind))

    def comments_in(self, lo: int, hi: int) -> dict[int, dict]:
        out: dict[int, dict] = {}
        for r in self.con.execute(
                "SELECT va,kind,text FROM comments WHERE va>=? AND va<?", (lo, hi)):
            out.setdefault(r["va"], {})[r["kind"]] = r["text"]
        return out

    # ---- functions ----------------------------------------------------
    def func_at(self, va: int) -> sqlite3.Row | None:
        return self.con.execute("SELECT * FROM functions WHERE va=?", (va,)).fetchone()

    def func_containing(self, va: int) -> sqlite3.Row | None:
        return self.con.execute(
            "SELECT * FROM functions WHERE va<=? AND end>? ORDER BY va DESC LIMIT 1",
            (va, va)).fetchone()

    def commit(self) -> None:
        self.con.commit()

    def close(self) -> None:
        try:
            self.con.commit()
            self.con.close()
        except Exception:
            pass

    def counts(self) -> dict:
        c = {}
        for t in ("names", "functions", "blocks", "xrefs", "strings", "comments",
                  "imports", "exports", "types", "vtables", "bookmarks",
                  "jumptables", "data_items", "notes", "patches"):
            c[t] = self.con.execute(f"SELECT COUNT(*) n FROM {t}").fetchone()["n"]
        return c

    def touch(self) -> None:
        self.set_meta("last_opened", int(time.time()))
        self.commit()
