"""Statistics helpers for threat hunting - standard library only.

Every function here is small, documented and unit-tested. These are the
building blocks the hunts use to turn raw telemetry into ranked, explainable
findings: dispersion (coefficient of variation), outlier scores (z-score and the
robust MAD z-score), string randomness (Shannon entropy), percentile baselines
and the long-tail / stacking helpers that make "rare across the fleet" a number.

Nothing here imports numpy or pandas on purpose: a hiring manager can read every
line and see exactly how a coefficient of variation or a MAD score is computed,
and it runs anywhere Python does.
"""

from __future__ import annotations

import math
from collections import Counter
from typing import Dict, Iterable, List, Sequence, Tuple

Number = float


def mean(values: Sequence[Number]) -> float:
    """Arithmetic mean. Empty sequence -> 0.0 (callers treat 0 as 'no data')."""
    values = list(values)
    if not values:
        return 0.0
    # math.fsum is correctly rounded on every Python version; the builtin sum()
    # switched to compensated float summation in 3.12, so plain sum() gives
    # last-bit-different means on 3.11 vs 3.12+.
    return math.fsum(values) / len(values)


def pstdev(values: Sequence[Number]) -> float:
    """Population standard deviation. Fewer than 2 points -> 0.0."""
    values = list(values)
    n = len(values)
    if n < 2:
        return 0.0
    mu = mean(values)
    var = math.fsum((x - mu) ** 2 for x in values) / n
    return math.sqrt(var)


def coefficient_of_variation(values: Sequence[Number]) -> float:
    """CV = stdev / mean, the key dispersion metric for beacon hunting.

    A machine beacon has near-constant inter-arrival times, so its CV is small
    (tight clustering around the mean); human/jittered traffic has a large CV.
    Returns 0.0 for a constant series and math.inf when the mean is ~0 but the
    series varies (undefined relative dispersion). Negative means are taken by
    magnitude so the ratio stays interpretable.
    """
    values = list(values)
    if len(values) < 2:
        return 0.0
    mu = mean(values)
    sd = pstdev(values)
    if abs(mu) < 1e-12:
        return 0.0 if sd < 1e-12 else math.inf
    return sd / abs(mu)


def median(values: Sequence[Number]) -> float:
    """Median of a sequence. Empty -> 0.0."""
    values = sorted(values)
    n = len(values)
    if n == 0:
        return 0.0
    mid = n // 2
    if n % 2 == 1:
        return float(values[mid])
    return (values[mid - 1] + values[mid]) / 2.0


def percentile(values: Sequence[Number], pct: float) -> float:
    """Linear-interpolation percentile (same method as numpy's default).

    pct is 0..100. Used for baseline thresholds such as "outbound bytes above
    the host's 95th percentile". Empty -> 0.0; single value -> that value.
    """
    values = sorted(values)
    n = len(values)
    if n == 0:
        return 0.0
    if n == 1:
        return float(values[0])
    if pct <= 0:
        return float(values[0])
    if pct >= 100:
        return float(values[-1])
    rank = (pct / 100.0) * (n - 1)
    low = math.floor(rank)
    high = math.ceil(rank)
    if low == high:
        return float(values[int(rank)])
    frac = rank - low
    return values[low] * (1 - frac) + values[high] * frac


def zscore(value: Number, values: Sequence[Number]) -> float:
    """Classic z-score of `value` against the distribution `values`.

    Returns 0.0 when the distribution has no spread (stdev 0) to avoid a
    divide-by-zero; callers that care about "never seen this high" combine this
    with a never-before-seen check rather than relying on z alone.
    """
    values = list(values)
    if len(values) < 2:
        return 0.0
    sd = pstdev(values)
    if sd < 1e-12:
        return 0.0
    return (value - mean(values)) / sd


def mad(values: Sequence[Number]) -> float:
    """Median absolute deviation (raw, not scaled). Empty -> 0.0."""
    values = list(values)
    if not values:
        return 0.0
    med = median(values)
    return median([abs(x - med) for x in values])


def mad_zscore(value: Number, values: Sequence[Number]) -> float:
    """Robust z-score using the median and MAD instead of mean and stdev.

    The 0.6745 factor makes the MAD a consistent estimator of the standard
    deviation for normal data, so a MAD z of 3.5 means roughly the same thing as
    a classic z of 3.5 but is not dragged around by the very outliers we are
    hunting. When MAD is 0 (more than half the points are identical) we fall back
    to a mean-absolute-deviation scale so a lone different value still scores;
    if every point is identical, returns 0.0.
    """
    values = list(values)
    if len(values) < 2:
        return 0.0
    med = median(values)
    m = mad(values)
    if m < 1e-12:
        # Degenerate MAD: use mean absolute deviation as the scale instead.
        mad_fallback = mean([abs(x - med) for x in values])
        if mad_fallback < 1e-12:
            return 0.0
        return (value - med) / (1.2533 * mad_fallback)
    return 0.6745 * (value - med) / m


def shannon_entropy(text: str) -> float:
    """Shannon entropy of a string in bits per character.

    High entropy (close to log2(alphabet size)) means the characters look
    random - the signature of a DGA domain or an encoded DNS-tunnel label.
    English-ish text sits around 3-4 bits/char; a base32 tunnel label is ~4.8+.
    Empty string -> 0.0.
    """
    if not text:
        return 0.0
    counts = Counter(text)
    n = len(text)
    ent = 0.0
    for c in counts.values():
        p = c / n
        ent -= p * math.log2(p)
    return ent


def stack_counts(items: Iterable) -> Counter:
    """Frequency count of hashable items - the core of 'stacking' / long-tail.

    Stacking (a.k.a. frequency-of-occurrence analysis) ranks values by how often
    they appear so the analyst can read the rare long tail, where novel attacker
    tooling hides, instead of the common head.
    """
    return Counter(items)


def long_tail(items: Iterable, max_count: int = 1) -> List[Tuple[object, int]]:
    """Return (item, count) for items at or below `max_count`, rarest first.

    `max_count=1` gives the strict long tail (seen exactly once). Ties are
    broken by the string form of the item so the ordering is deterministic and
    reproducible in tests.
    """
    counts = stack_counts(items)
    tail = [(k, v) for k, v in counts.items() if v <= max_count]
    tail.sort(key=lambda kv: (kv[1], str(kv[0])))
    return tail


def fleet_rarity(entity_to_hosts: Dict[object, Sequence[str]]) -> Dict[object, int]:
    """Map each entity to the number of distinct hosts it appears on.

    Fleet-rarity turns "this service name exists on only one of 65 machines"
    into a 1, which is the outlier signal for new persistence: common software
    is everywhere, attacker persistence is usually on one host first.
    """
    return {k: len(set(v)) for k, v in entity_to_hosts.items()}


def normalize_scores(scores: Sequence[Number]) -> List[float]:
    """Min-max normalise to 0..1 so heterogeneous signals can be combined.

    A constant list maps to all-zeros (no information to rank on).
    """
    scores = list(scores)
    if not scores:
        return []
    lo, hi = min(scores), max(scores)
    if hi - lo < 1e-12:
        return [0.0 for _ in scores]
    return [(s - lo) / (hi - lo) for s in scores]
