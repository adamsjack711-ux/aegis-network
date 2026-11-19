"""Names used by the coordinator and agents on the existing Mesh transport."""

import os

SUBJECT = "aegis.findings.v1"
REVOCATION_SUBJECT = "aegis.revocations.v1"
STREAM = "AEGIS_FINDINGS"
DEAD_LETTER_STREAM = "AEGIS_DEAD_LETTERS"
DEAD_LETTER_SUBJECT = "aegis.deadletter.v1"

CRITICAL_STREAM = "AEGIS_WITHDRAWALS"
CRITICAL_SUBJECT = "aegis.withdrawals.v1"
CRITICAL_MAX_BYTES = 16 * 1024 * 1024
MAX_EVENT_BYTES = 256 * 1024


def priority_enabled() -> bool:
    return os.getenv("AEGIS_PHASE4E_PRIORITY") == "1"
