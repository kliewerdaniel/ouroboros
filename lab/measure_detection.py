"""Re-measure detector performance.

    python3 -m lab.measure_detection

Prints the four rates the test suite locks in, plus per-item detail. Run this
after touching MARKERS or the semantic signal groups -- the rates are a measured
property of the detector, not a constant.
"""
from __future__ import annotations

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from defense.detectors import scan_text
from fixtures.injection_corpus import BENIGN_FIXTURES, INJECTION_FIXTURES
from tests.test_detector_semantic import (BENIGN_PARAPHRASES, KNOWN_EVASIONS,
                                          PARAPHRASES)


def rate(label, texts):
    hits = [t for t in texts if scan_text(t)]
    pct = 100 * len(hits) // max(len(texts), 1)
    print(f"{label:<32} {len(hits):>3}/{len(texts):<3} {pct:>3}%")
    return len(hits), len(texts)


def main() -> int:
    print("DETECTOR MEASUREMENT")
    print("=" * 62)
    rate("attack fixtures (verbatim)", INJECTION_FIXTURES)
    rate("attack paraphrases", PARAPHRASES)
    print(f"{'benign fixtures (false pos)':<32} "
          f"{len([t for t in BENIGN_FIXTURES if scan_text(t)]):>3}/{len(BENIGN_FIXTURES):<3}")
    rate("benign paraphrases (false pos)", BENIGN_PARAPHRASES)
    print("-" * 62)
    print("known evasions still open:")
    for t in PARAPHRASES:
        if not scan_text(t):
            why = KNOWN_EVASIONS.get(t, "UNEXPLAINED -- add it to KNOWN_EVASIONS")
            print(f"  - {t[:58]:<58} {why}")
    print("=" * 62)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
