import os
import sys

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

from hunt import data  # noqa: E402
from hunt.hunts import ORDER, get  # noqa: E402


@pytest.fixture(scope="session")
def ds():
    d = data.load()
    for s in data.SOURCES:
        d.events(s)
    return d


@pytest.fixture(scope="session")
def gt():
    return data.load_ground_truth()


@pytest.fixture(scope="session")
def benign_ds():
    return data.benign_dataset()


@pytest.fixture(scope="session")
def results(ds):
    """Ranked findings for every hunt, computed once."""
    return {h: get(h).run(ds, top=10) for h in ORDER}
