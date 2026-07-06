"""The planner-evaluation harness (evals/): corpus integrity and scoring."""

import os
import sys

import yaml

sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "evals"))

from run_planner_eval import canonical, score_item, summarise  # noqa: E402

from safetre.planner import MockPlanner
from safetre.query import QuerySpec

CORPUS = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                      "evals", "corpus.yaml")


def _corpus():
    with open(CORPUS) as fh:
        return yaml.safe_load(fh)


def test_every_reference_spec_is_valid():
    # a corpus whose references do not validate scores nothing meaningfully
    for item in _corpus():
        if item.get("reject"):
            assert "expect" not in item
            continue
        assert item["expect"], f"{item['id']} has no reference specs"
        for ref in item["expect"]:
            QuerySpec(**ref)                       # raises if invalid


def test_canonical_is_order_insensitive():
    a = QuerySpec(**{"dataset": "spend", "measure": {"fn": "mean", "column": "amount_gbp"},
                     "group_by": ["age_band", "region"],
                     "filters": [{"column": "device_os", "op": "==", "value": "iOS"},
                                 {"column": "event_type", "op": "==", "value": "purchase"}]})
    b = QuerySpec(**{"dataset": "spend", "measure": {"fn": "mean", "column": "amount_gbp"},
                     "group_by": ["region", "age_band"],
                     "filters": [{"column": "event_type", "op": "==", "value": "purchase"},
                                 {"column": "device_os", "op": "==", "value": "iOS"}]})
    assert canonical(a) == canonical(b)


def test_reject_item_passes_on_invalid_spec():
    class ProposesDonorId:
        def plan(self, request):
            return {"dataset": "wellbeing", "measure": {"fn": "mean", "column": "wemwbs_score"},
                    "group_by": ["donor_id"]}
    r = score_item({"id": "x", "tags": ["reject"], "reject": True,
                    "request": "per donor"}, ProposesDonorId())
    assert r["rejected_ok"] is True


def test_harness_runs_end_to_end_with_mock_planner():
    corpus = _corpus()
    results = [score_item(item, MockPlanner()) for item in corpus]
    summary = summarise(results)
    assert summary["n_answerable"] + summary["n_reject"] == len(corpus)
    # the mock is keyword-based, so no score floor is pinned — but the harness
    # must produce every metric, and the mock must correctly fail to answer
    # the unanswerable items (it proposes off-allowlist specs for them)
    assert summary["rejected_ok_pct"] is not None
    assert all(r["error"] is None for r in results)
