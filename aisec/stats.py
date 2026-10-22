"""Rates over repeated trials.

A model is not deterministic, so each scenario's agent arm can run several times
(``--repeat N``) and is reported as "landed in k of n trials". With n as small as 3, a
normal-approximation interval is meaningless (it collapses to zero width at 0/n and n/n),
so rates carry a Wilson score interval instead.
"""

from __future__ import annotations

import math
from typing import Any

Z95 = 1.959963984540054


def wilson_interval(k: int, n: int, z: float = Z95) -> tuple[float, float]:
    if n <= 0:
        raise ValueError("n must be positive")
    if not 0 <= k <= n:
        raise ValueError("k must be between 0 and n")
    p = k / n
    denom = 1 + z * z / n
    centre = (p + z * z / (2 * n)) / denom
    half = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n)) / denom
    low = 0.0 if k == 0 else max(0.0, centre - half)
    high = 1.0 if k == n else min(1.0, centre + half)
    return low, high


def rate(k: int, n: int) -> dict[str, Any] | None:
    """``k`` successes out of ``n`` trials with a 95% Wilson interval; None when n is 0."""
    if n == 0:
        return None
    low, high = wilson_interval(k, n)
    return {"k": k, "n": n, "rate": round(k / n, 4), "ci95_low": round(low, 4), "ci95_high": round(high, 4)}


def fmt_rate(summary: dict[str, Any] | None) -> str:
    """Render as ``2/3 (67%; 95% CI 21-94%)``, or ``n/a``."""
    if summary is None:
        return "n/a"
    return (
        f"{summary['k']}/{summary['n']} ({summary['rate'] * 100:.0f}%; "
        f"95% CI {summary['ci95_low'] * 100:.0f}-{summary['ci95_high'] * 100:.0f}%)"
    )
