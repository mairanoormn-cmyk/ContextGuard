#!/usr/bin/env python3
"""
FR-4.7: lobstertrap inspect equivalent — single-prompt DPI debugger.
Usage:
  python scripts/lobstertrap_inspect.py "your prompt here" --intent LEGITIMATE
"""
import argparse
import json
import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "backend"))

from dpi import inspect_prompt_local
from gemini import classify_prompt_intent
from dpi import check_intent_mismatch


def main():
    parser = argparse.ArgumentParser(description="ContextGuard DPI prompt inspector (FR-4.7)")
    parser.add_argument("prompt", help="Prompt text to inspect")
    parser.add_argument("--intent", dest="declared_intent", default=None, help="X-Lobstertrap-Intent header value")
    args = parser.parse_args()

    local = inspect_prompt_local(args.prompt)
    classification = classify_prompt_intent({
        "policy_triggered": "manual_inspect",
        "action_taken": "LOG",
        "metadata": {**local, "declared_intent": args.declared_intent},
    })
    mismatch = check_intent_mismatch(
        args.declared_intent,
        classification.get("intent_category"),
        float(classification.get("confidence", 0.75)),
    )
    print(json.dumps({
        "local_checks": local,
        "classification": classification,
        "intent_mismatch": mismatch,
    }, indent=2))


if __name__ == "__main__":
    main()
