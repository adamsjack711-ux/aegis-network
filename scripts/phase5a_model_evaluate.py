"""Run the Phase 5A comparison without network unless explicitly authorized."""

import argparse
import json
import os
from pathlib import Path

from aegis.intelligence.model_evaluation import evaluate_model
from aegis.intelligence.provider import HTTPSJSONProvider


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--corpus", type=Path, default=Path("tests/fixtures/phase5a_model_cases.json"))
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--mode", choices=("deterministic", "scripted", "model"), default="deterministic")
    parser.add_argument("--authorize-external-model-calls", action="store_true")
    parser.add_argument("--endpoint", help="exact authorized HTTPS JSON completion endpoint")
    parser.add_argument("--model-name")
    parser.add_argument("--token-env", help="environment variable holding the provider token")
    parser.add_argument("--timeout-seconds", type=float, default=15)
    parser.add_argument("--input-usd-per-million", type=float)
    parser.add_argument("--output-usd-per-million", type=float)
    parser.add_argument("--max-run-cost-usd", type=float,
                        help="required model-mode cap using worst-case input/output token bounds")
    args = parser.parse_args()
    provider = None
    if args.mode == "model":
        if not args.authorize_external_model_calls:
            parser.error("model mode requires --authorize-external-model-calls")
        if not args.endpoint or not args.model_name or not args.token_env:
            parser.error("model mode requires endpoint, model name and token environment variable")
        if (args.input_usd_per_million is None or args.output_usd_per_million is None or
                args.max_run_cost_usd is None or args.max_run_cost_usd <= 0 or
                args.input_usd_per_million < 0 or args.output_usd_per_million < 0):
            parser.error("model mode requires nonnegative token rates and a positive run cost cap")
        count = len(json.loads(args.corpus.read_text()))
        upper_cost = count * (10_000 * args.input_usd_per_million +
                              700 * args.output_usd_per_million) / 1_000_000
        if upper_cost > args.max_run_cost_usd:
            parser.error("worst-case configured inference cost exceeds run cap")
        token = os.environ.get(args.token_env)
        if not token:
            parser.error("provider token environment variable is unset")
        provider = HTTPSJSONProvider(endpoint=args.endpoint, model=args.model_name, token=token,
                                     authorized=True, timeout_seconds=args.timeout_seconds)
    elif args.authorize_external_model_calls or args.endpoint or args.token_env:
        parser.error("external model options require --mode model")
    report = evaluate_model(args.corpus, mode=args.mode, provider=provider,
                            input_usd_per_million=args.input_usd_per_million,
                            output_usd_per_million=args.output_usd_per_million)
    report["provider_configuration"] = ({"endpoint": args.endpoint, "model": args.model_name,
                                         "timeout_seconds": args.timeout_seconds}
                                        if args.mode == "model" else None)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
    print(json.dumps({"mode": args.mode, "cases": len(report["cases"]),
                      "baseline_correct": report["baseline"]["correct"],
                      "raw_model_correct": report["raw_model"]["correct"] if report["raw_model"] else None,
                      "real_model_evaluation_verified": report["real_model_evaluation_verified"]}, sort_keys=True))


if __name__ == "__main__":
    main()
