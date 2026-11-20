"""Authenticated direct withdrawal views and the rollback-checked relying ledger."""

from concurrent.futures import ThreadPoolExecutor

from ..journal.protocol import JournalBlocked, canonical
from ..journal.storage import WitnessLedger
from .protocol import Leaf, MAX_RECORDS, verify, withdrawal_binding


def _fetch(fetch, operator, policy, challenge, latest_epoch):
    try:
        view = fetch(challenge)
        if view.witness != operator:
            raise JournalBlocked("withdrawal endpoint returned another operator")
        verify(policy.journal.operators[operator], "withdrawal-view.v2",
               withdrawal_binding(challenge, operator, view.leaves), view.signature)
        records = []
        events = set()
        for leaf in view.leaves:
            admission = leaf.receipt.admission
            if admission.epoch > latest_epoch or admission.event in events:
                raise JournalBlocked("withdrawal view contains a future or repeated receipt")
            records.append((leaf, policy.check_withdrawal(leaf, operator)))
            events.add(admission.event)
        return records
    except (JournalBlocked, OSError, ValueError):
        return None


class WithdrawalReader:
    def __init__(self, policy, sources, path, pin, clock):
        if policy.status_profile != "withdrawal-v2" or set(sources) != set(policy.journal.operators):
            raise ValueError("withdrawal-v2 requires every enrolled witness endpoint")
        self.policy, self.sources, self.clock = policy, sources, clock
        self.limit = MAX_RECORDS * len(sources)
        self.ledger = WitnessLedger(path, pin, b"aegis-phase4e-withdrawal-v2\0" + bytes.fromhex(policy.context))
        self.records = {}
        try:
            for wire in self.ledger.records:
                if wire == b"exhausted":
                    raise JournalBlocked("withdrawal retention exhausted")
                leaf = Leaf.model_validate_json(wire)
                record = policy.check_withdrawal(leaf, leaf.receipt.votes[0].operator)
                self._remember(leaf, record)
            self.ledger.records.clear()
        except BaseException:
            self.ledger.close()
            raise
        self.exhausted = False

    def _remember(self, leaf, record):
        self.records[leaf.receipt.admission.event] = (leaf.wire, record)

    def read(self, challenge):
        with self.ledger.lock:
            self.ledger.ensure()
            if self.exhausted:
                raise JournalBlocked("withdrawal retention exhausted")
            now = self.clock.sample()
            deadline = self.policy.challenge_deadline(challenge, now)
            epoch = int(now.upper // self.policy.journal.epoch_seconds)
            with ThreadPoolExecutor(max_workers=len(self.sources)) as pool:
                requests = [pool.submit(_fetch, fetch, name, self.policy, challenge, epoch)
                            for name, fetch in self.sources.items()]
                results = tuple(job.result() for job in requests)
            # Keep every authenticated denial received, even during a partial outage.
            self.ledger.ensure()
            for records in results:
                for leaf, record in records or ():
                    event = leaf.receipt.admission.event
                    if event in self.records:
                        continue
                    if len(self.records) >= self.limit:
                        self.ledger.append(b"exhausted")
                        self.exhausted = True
                        raise JournalBlocked("withdrawal retention exhausted")
                    self.ledger.append(canonical(leaf))
                    self._remember(leaf, record)
            now = self.clock.sample()
            current = self.policy.challenge_deadline(challenge, now)
            if any(records is None for records in results) or now.monotonic >= deadline:
                raise JournalBlocked("fresh authenticated withdrawal views required from all enrolled witnesses")
            return tuple(self.records.values()), min(deadline, current), self.ledger.state
