"""SQLite reference stores. Protected pins belong in a separate restore domain."""

from contextlib import closing
from hashlib import sha256
from pathlib import Path
import sqlite3
from threading import RLock
from typing import Protocol

from .protocol import JournalBlocked

EMPTY_CHAIN = sha256(b"aegis-journal-v1/witness-state").digest()


class Pin(Protocol):
    def read(self) -> bytes: ...
    def advance(self, expected: bytes, value: bytes) -> None: ...


class SQLitePin:
    """Reference CAS. Production must protect this database from rollback."""

    def __init__(self, path: Path, name: str):
        self.path, self.name = path, name

    def provision(self, value: bytes) -> None:
        with closing(sqlite3.connect(self.path)) as db, db:
            db.execute("CREATE TABLE IF NOT EXISTS pins (name TEXT PRIMARY KEY, value BLOB NOT NULL)")
            db.execute("INSERT INTO pins VALUES (?, ?)", (self.name, value))

    def read(self) -> bytes:
        try:
            with closing(sqlite3.connect(self.path)) as db:
                row = db.execute("SELECT value FROM pins WHERE name = ?", (self.name,)).fetchone()
        except sqlite3.Error as exc:
            raise JournalBlocked("protected journal pin is unavailable") from exc
        if row is None or type(row[0]) is not bytes:
            raise JournalBlocked("protected journal pin is unavailable")
        return row[0]

    def advance(self, expected: bytes, value: bytes) -> None:
        with closing(sqlite3.connect(self.path)) as db, db:
            result = db.execute("UPDATE pins SET value = ? WHERE name = ? AND value = ?",
                                (value, self.name, expected))
            if result.rowcount != 1:
                raise JournalBlocked("protected journal pin changed concurrently")


class WitnessLedger:
    """Persist before returning a receipt or coverage signature."""

    def __init__(self, path: Path, pin: Pin, context: bytes):
        self.pin = pin
        self.context = context
        self.lock = RLock()
        self.db = sqlite3.connect(path, check_same_thread=False)
        self.state = EMPTY_CHAIN
        self.count = 0
        try:
            with self.db:
                self.db.execute("CREATE TABLE IF NOT EXISTS ops (position INTEGER PRIMARY KEY, wire BLOB NOT NULL)")
            self.records = []
            for index, wire in self.db.execute("SELECT position, wire FROM ops ORDER BY position"):
                if index != self.count or type(wire) is not bytes:
                    raise JournalBlocked("witness journal has missing or malformed records")
                self.state = self._next(wire)
                self.count += 1
                self.records.append(wire)
            self.ensure()
        except BaseException:
            self.db.close()
            raise

    def _next(self, wire):
        return sha256(self.context + self.state + wire).digest()

    def ensure(self) -> None:
        if self.pin.read() != self.state:
            raise JournalBlocked("witness journal does not match its protected pin")

    def append(self, wire: bytes) -> None:
        updated = self._next(wire)
        with self.db:
            self.db.execute("INSERT INTO ops VALUES (?, ?)", (self.count, wire))
        # A crash between writes leaves a mismatch and disables signing.
        self.pin.advance(self.state, updated)
        self.state = updated
        self.count += 1

    def close(self) -> None:
        self.db.close()
