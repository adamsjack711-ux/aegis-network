"""The withdrawal gate must not mistake broker progress for durable denial."""

from copy import deepcopy

from score_phase4f_kv_recovery import score_trial


def raw_trial():
    return {
        "recovery_stages": {"enrolled_agent_ids": ["agent-1"], "targeted_agent_withdrawal_pairs": 2},
        "agent_sigkill": True, "ordinary_enqueued": 24,
        "queued_journal_order": [{"event_id": "finding-1"}, {"event_id": "finding-2"}],
        "effective_denials_from_read_only_sqlite": ["finding-1", "finding-2"],
        "independent_withdrawal_id": "withdrawal-1", "mixed_withdrawal_id": "withdrawal-2",
        "independent_withdrawal_ms": {"submit_to_durable_audit_ms": 1000,
                                      "restart_request_to_durable_audit_ms": 900,
                                      "submit_to_confirmed_ack_ms": 1001},
        "mixed_withdrawal_ms": {"submit_to_durable_audit_ms": 1100,
                                "restart_request_to_durable_audit_ms": 1000,
                                "submit_to_confirmed_ack_ms": 1101},
        "durable_denial_readback": {
            "withdrawal-1": {"target_finding_id": "finding-1", "submit_to_first_present_ms": 1025},
            "withdrawal-2": {"target_finding_id": "finding-2", "submit_to_first_present_ms": 1125},
        },
    }


def test_exact_read_only_denial_passes_both_pairs():
    result = score_trial(raw_trial())
    assert result["all_pairs_pass"]
    assert [pair["outcome"] for pair in result["observed_pairs"]] == ["pass", "pass"]


def test_ack_and_worker_report_cannot_substitute_for_readback():
    raw = raw_trial()
    raw.pop("durable_denial_readback")
    assert [pair["outcome"] for pair in score_trial(raw)["observed_pairs"]] == [
        "inconclusive", "inconclusive"]
    raw["independent_withdrawal_ms"]["submit_to_confirmed_ack_ms"] = 2
    assert not score_trial(raw)["all_pairs_pass"]


def test_late_commit_or_missing_exact_denial_fails():
    late = raw_trial()
    late.pop("durable_denial_readback")
    late["independent_withdrawal_ms"]["submit_to_durable_audit_ms"] = 6000
    assert score_trial(late)["observed_pairs"][0]["outcome"] == "fail"
    missing = deepcopy(raw_trial())
    missing["effective_denials_from_read_only_sqlite"].remove("finding-2")
    assert score_trial(missing)["observed_pairs"][1]["outcome"] == "fail"


def test_read_only_observation_may_precede_worker_report():
    raw = raw_trial()
    raw["durable_denial_readback"]["withdrawal-1"]["submit_to_first_present_ms"] = 999
    assert score_trial(raw)["observed_pairs"][0]["outcome"] == "pass"


def test_ordinary_backlog_is_part_of_acceptance():
    raw = raw_trial()
    raw["ordinary_enqueued"] = 0
    assert not score_trial(raw)["acceptance_setup_valid"]
    assert not score_trial(raw)["all_pairs_pass"]
