import math

import pytest

from hunt import stats


def test_mean_and_pstdev_known_values():
    assert stats.mean([1, 2, 3, 4]) == 2.5
    assert stats.mean([]) == 0.0
    # population stdev of 2,4,4,4,5,5,7,9 is exactly 2
    assert stats.pstdev([2, 4, 4, 4, 5, 5, 7, 9]) == pytest.approx(2.0)
    assert stats.pstdev([5]) == 0.0


def test_cv_separates_regular_from_bursty():
    assert stats.coefficient_of_variation([300, 300, 300, 300]) == 0.0
    jittered = [300 * (1 + d) for d in (-0.2, 0.1, 0.0, 0.2, -0.1, 0.05)]
    assert stats.coefficient_of_variation(jittered) < 0.2
    assert stats.coefficient_of_variation([1, 1, 1, 1, 3600, 2, 1, 7200]) > 1.5


def test_cv_edge_cases():
    assert stats.coefficient_of_variation([]) == 0.0
    assert stats.coefficient_of_variation([42]) == 0.0
    assert stats.coefficient_of_variation([0, 0, 0]) == 0.0
    assert math.isinf(stats.coefficient_of_variation([-1, 1]))
    # negative mean is taken by magnitude
    assert stats.coefficient_of_variation([-10, -20]) == pytest.approx(stats.coefficient_of_variation([10, 20]))


def test_median_odd_even_empty():
    assert stats.median([3, 1, 2]) == 2
    assert stats.median([4, 1, 3, 2]) == 2.5
    assert stats.median([]) == 0.0


def test_percentile_linear_interpolation():
    vals = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10]
    assert stats.percentile(vals, 50) == pytest.approx(5.5)
    assert stats.percentile(vals, 95) == pytest.approx(9.55)
    assert stats.percentile(vals, 0) == 1
    assert stats.percentile(vals, 100) == 10


def test_percentile_edge_cases():
    assert stats.percentile([], 95) == 0.0
    assert stats.percentile([7], 95) == 7.0
    assert stats.percentile([5, 1], 150) == 5


def test_zscore_basic_and_degenerate():
    assert stats.zscore(9, [2, 4, 4, 4, 5, 5, 7, 9]) == pytest.approx(2.0)
    assert stats.zscore(5, [5, 5, 5]) == 0.0      # zero spread -> 0, no divide-by-zero
    assert stats.zscore(5, [5]) == 0.0


def test_mad_known_value():
    # median 3, abs deviations 2,1,0,1,2,4,6 -> MAD 2
    assert stats.mad([1, 2, 3, 4, 5, 7, 9]) == 2
    assert stats.mad([]) == 0.0


def test_mad_zscore_resists_outliers():
    base = [10, 11, 9, 10, 10, 12, 9, 11]
    poisoned = base + [500]
    # the classic z-score of 500 is dragged down by 500 itself; the robust one is not
    assert stats.mad_zscore(500, poisoned) > 100
    assert stats.zscore(500, poisoned) < 3


def test_mad_zscore_degenerate_mad_fallback():
    vals = [5, 5, 5, 5, 5, 9]          # MAD is 0 (more than half identical)
    assert stats.mad(vals) == 0
    assert stats.mad_zscore(9, vals) > 0
    assert stats.mad_zscore(5, [5, 5, 5, 5]) == 0.0
    assert stats.mad_zscore(5, [5]) == 0.0


def test_entropy_values():
    assert stats.shannon_entropy("") == 0.0
    assert stats.shannon_entropy("aaaa") == 0.0
    assert stats.shannon_entropy("ab") == pytest.approx(1.0)
    assert stats.shannon_entropy("abcd") == pytest.approx(2.0)


def test_entropy_separates_random_from_wordlike():
    assert stats.shannon_entropy("k2x9q7m4z1v8w3r6t5y0p") > 4.0
    assert stats.shannon_entropy("mailserver") < 3.5


def test_stacking_and_long_tail_deterministic():
    items = ["svchost", "svchost", "chrome", "chrome", "chrome", "evil", "rare2"]
    assert stats.stack_counts(items)["chrome"] == 3
    assert stats.long_tail(items, 1) == [("evil", 1), ("rare2", 1)]
    assert [k for k, _ in stats.long_tail(items, 2)] == ["evil", "rare2", "svchost"]


def test_fleet_rarity_counts_distinct_hosts():
    rarity = stats.fleet_rarity({"svc": ["h1", "h1", "h2"], "implant": ["h9"]})
    assert rarity == {"svc": 2, "implant": 1}


def test_normalize_scores():
    assert stats.normalize_scores([0, 5, 10]) == [0.0, 0.5, 1.0]
    assert stats.normalize_scores([3, 3]) == [0.0, 0.0]
    assert stats.normalize_scores([]) == []
