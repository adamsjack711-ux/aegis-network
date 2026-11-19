"""An independent observer retains signed conflicts and checks merge promises."""

from contextlib import closing
import sqlite3

from .protocol import Cut, Entry, JournalBlocked, Policy, Receipt, SignedHead, canonical
from .witness import verify_extension, verify_page


class Monitor:
    def __init__(self, policy: Policy, path):
        self.policy, self.path = policy, path
        with closing(sqlite3.connect(path)) as db, db:
            db.execute("""CREATE TABLE IF NOT EXISTS heads (
                context TEXT NOT NULL, epoch INTEGER NOT NULL, size INTEGER NOT NULL,
                root TEXT NOT NULL, wire BLOB PRIMARY KEY)""")
            db.execute("CREATE INDEX IF NOT EXISTS by_epoch ON heads (context, epoch)")
            db.execute("CREATE INDEX IF NOT EXISTS by_size ON heads (context, size)")
            db.execute("""CREATE TABLE IF NOT EXISTS receipts (
                admission BLOB PRIMARY KEY, receipt BLOB NOT NULL, first_proof REAL, last_alert REAL)""")

    def observe(self, signed: SignedHead) -> tuple[tuple[SignedHead, SignedHead], ...]:
        self.policy.check_head(signed)
        head = signed.head
        wire = canonical(signed)
        with closing(sqlite3.connect(self.path)) as db, db:
            db.execute("INSERT OR IGNORE INTO heads VALUES (?, ?, ?, ?, ?)",
                       (head.context, head.epoch, head.size, head.root, wire))
            rows = db.execute("""SELECT wire FROM heads WHERE context = ? AND
                ((size = ? AND root != ?) OR (epoch = ? AND (size != ? OR root != ?)))""",
                (head.context, head.size, head.root, head.epoch, head.size, head.root))
            return tuple((SignedHead.model_validate_json(row[0]), signed) for row in rows)

    def check_extension(self, older: SignedHead, newer: SignedHead, proof) -> None:
        self.observe(older)
        self.observe(newer)
        verify_extension(older.head, newer.head, proof)

    def merge_status(self, receipt: Receipt, now: float, cut: Cut | None, entry: Entry | None) -> str:
        self.policy.check_receipt(receipt)
        admission = receipt.admission
        deadline = self.policy.cutoff(admission.epoch) + self.policy.merge_seconds
        included = False
        if cut is not None:
            self.policy.check_cut(cut)
            self.observe(cut.signed)
            if (self.policy.cutoff(cut.head.epoch) <= now and entry is not None
                    and entry.index < cut.head.size):
                try:
                    leaf, = verify_page(self.policy, cut.head, entry.index, 1, (entry,))
                    included = leaf.receipt.admission.event == admission.event
                except JournalBlocked:
                    pass
        wire = canonical(receipt.admission)
        with closing(sqlite3.connect(self.path)) as db, db:
            db.execute("INSERT OR IGNORE INTO receipts (admission, receipt) VALUES (?, ?)",
                       (wire, canonical(receipt)))
            if included:
                db.execute("UPDATE receipts SET first_proof = COALESCE(first_proof, ?) WHERE admission = ?",
                           (now, wire))
            observed, = db.execute("SELECT first_proof FROM receipts WHERE admission = ?", (wire,)).fetchone()
            if observed is not None:
                return "included" if observed <= deadline else "included_when_observed_after_deadline"
            if now < deadline:
                return "pending"
            db.execute("UPDATE receipts SET last_alert = ? WHERE admission = ?", (now, wire))
            return "merge_proof_unavailable"
