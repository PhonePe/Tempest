#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 PhonePe India Pvt. Ltd.
# SPDX-License-Identifier: Apache-2.0

import json
import re
import sys
from pathlib import Path


BENCH_LINE = re.compile(r"^test (.+?) \.\.\. bench:\s+([0-9,]+) ns/iter")


def main():
    if len(sys.argv) != 3:
        raise SystemExit("usage: check-benchmark-budgets.py BUDGETS_JSON BENCH_OUTPUT")

    budgets = json.loads(Path(sys.argv[1]).read_text())
    observed = {}
    for line in Path(sys.argv[2]).read_text().splitlines():
        match = BENCH_LINE.match(line)
        if match:
            observed[match.group(1)] = int(match.group(2).replace(",", ""))

    missing = sorted(set(budgets) - set(observed))
    if missing:
        raise SystemExit(f"missing benchmark results: {', '.join(missing)}")

    exceeded = []
    for name, maximum_ns in budgets.items():
        actual_ns = observed[name]
        print(f"{name}: {actual_ns} ns/iter (budget {maximum_ns} ns/iter)")
        if actual_ns > maximum_ns:
            exceeded.append(f"{name}={actual_ns}>{maximum_ns}")

    if exceeded:
        raise SystemExit("benchmark budgets exceeded: " + ", ".join(exceeded))


if __name__ == "__main__":
    main()
