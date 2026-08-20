"""The inside analyst's vetted loop (safetre/inside_analyst.py; spec R19, P23).

What is pinned here, and why each pin is a safety pin rather than a feature
test:

- R19: every step is an ordinary request through the unchanged service under
  ONE session — the budget is spent, the differencing lineage binds across
  steps exactly as it would for a human, and every step is audited.
- P23: the policy is shown nothing but what a web user sees. `LoopState` has
  exactly the fields the module declares; a denied step carries no frame; a
  hostile category value or a sub-threshold group planted in the data never
  reaches the transcript.
- The dossier's verdicts are a closed vocabulary; a claim about the data
  must cite a released step or is downgraded to a typed refusal; a loop that
  runs out of budget or steps says so rather than answering.
- The model's replies are untrusted input: malformed replies are retried and
  then converted into a typed refusal, never raised.
- The narrative check flags invented figures and accepts honest rounding.

The offline harness is the NIGHTPLAY study at 2,500 people (its plants are
what make several of these checks meaningful) driven by scripted policies and
fake model clients; nothing here needs an LLM.
"""

from __future__ import annotations

import dataclasses
import json

import pytest

from safetre import dataset as dataset_mod
from safetre import disclosure as D
from safetre.audit import AuditLog
from safetre.inside_analyst import (
    VERDICTS, AnalystLoop, Claim, Conclude, Dossier, LLMAnalystPolicy, LLMNarrator,
    LoopState, Query, ScriptedPolicy, Step, parse_action, render_dossier_markdown,
    transcript,
)
from studies.nightplay import generate as G
from studies.nightplay import verify as V

N = 2500

MEAN_BY_BAND = {"dataset": "panel", "measure": {"fn": "mean", "column": "stake_gbp"},
                "group_by": ["night_use_band"], "filters": []}
NOT_AF = [{"column": "employment", "op": "!=", "value": "armed_forces"}]
ADJUSTED_GLM = {"tool": "glm", "dataset": "panel", "family": "gaussian",
                "response": "stake_gbp", "terms": ["night_use_band", "employment"],
                "filters": NOT_AF}
BY_REGION = {"dataset": "panel", "measure": {"fn": "count", "column": None},
             "group_by": ["region"], "filters": []}
BY_APP = {"dataset": "sessions", "measure": {"fn": "count", "column": None},
          "group_by": ["app_category"], "filters": []}


@pytest.fixture(scope="module")
def study():
    tables, truth = G.generate(n_people=N)
    return tables, truth


@pytest.fixture
def service(study):
    tables, _ = study
    dataset_mod.activate(dataset_mod.load_dataset(V.DEFINITION))
    try:
        yield V.build_service(tables)
    finally:
        dataset_mod.activate(dataset_mod.load_dataset(
            __import__("pathlib").Path(dataset_mod.__file__).with_name("demo_dataset.yaml")))


def _conclude(*claims, verdict="supported"):
    return Conclude(list(claims), verdict)


# --------------------------------------------------------------------------- #
# R19: one session, ordinary requests                                         #
# --------------------------------------------------------------------------- #

def test_scripted_loop_runs_steps_and_concludes(service):
    pol = ScriptedPolicy(
        [("mean stake by night use band", MEAN_BY_BAND)],
        _conclude(Claim("stake rises with night use", "supported", [1])))
    d = AnalystLoop(service, pol).run("Is late-night phone use linked to gambling?")
    assert [s.status for s in d.steps] == ["released"]
    assert d.steps[0].output and {"night_use_band", "value", "n"} <= set(d.steps[0].output[0])
    assert d.verdict == "supported" and d.stopped_because == "concluded"
    assert d.budget_spent == 1 and d.budget == D.SessionAuditor().budget
    assert d.dataset == "nightplay-study"
    text = render_dossier_markdown(d)
    assert "[supported] stake rises with night use (steps 1)" in text


def test_iter_run_streams_step_events_then_the_final_dossier(service):
    """iter_run announces each step (start, then settled) and ends with the
    same dossier run() returns — run() is just iter_run consumed. The step
    events carry only the sub-question and the gateway verdict, never a value."""
    def fresh():
        return ScriptedPolicy(
            [("mean stake by night use band", MEAN_BY_BAND)],
            _conclude(Claim("stake rises with night use", "supported", [1])))

    events = list(AnalystLoop(service, fresh()).iter_run("q"))
    assert [k for k, _ in events] == ["step_start", "step", "done"]
    assert events[0][1] == {"id": 1, "sub_question": "mean stake by night use band"}
    assert isinstance(events[1][1], Step) and events[1][1].status == "released"

    streamed = events[-1][1]
    run_dossier = AnalystLoop(service, fresh()).run("q")
    assert isinstance(streamed, Dossier)
    assert streamed.verdict == run_dossier.verdict == "supported"
    assert ([s.status for s in streamed.steps]
            == [s.status for s in run_dossier.steps] == ["released"])


def test_steps_share_one_session_so_the_lineage_binds_across_them(service):
    """The marginal by band, then the same breakdown excluding a sub-threshold
    group, is a differencing pair by the published-marginal bound (P11), and
    the second step is denied INSIDE the loop; asked model-first with a
    consistent filter, both release. The analyst lives in a human's lineage."""
    pol = ScriptedPolicy(
        [("mean stake by night use band", MEAN_BY_BAND),
         ("mean stake by night use band excluding armed forces",
          dict(MEAN_BY_BAND, filters=NOT_AF))],
        _conclude(Claim("x", "supported", [1])))
    d = AnalystLoop(service, pol).run("q")
    assert [s.status for s in d.steps] == ["released", "denied"]
    assert d.steps[1].output is None
    pol2 = ScriptedPolicy(
        [("regress stake on night use band and employment", ADJUSTED_GLM),
         ("mean stake by night use band excluding armed forces",
          dict(MEAN_BY_BAND, filters=NOT_AF))],
        _conclude(Claim("x", "supported", [1, 2])))
    d2 = AnalystLoop(service, pol2).run("q")
    assert [s.status for s in d2.steps] == ["released", "released"]
    assert "cells" in d2.steps[0].artifacts and "model" in d2.steps[0].artifacts


def test_budget_is_the_sessions_and_exhausting_it_stops_the_loop(service):
    calls = []

    class Greedy:
        def next(self, state):
            calls.append(state.budget_remaining)
            return Query("mean stake by month", {
                "dataset": "bets", "measure": {"fn": "mean", "column": "stake_gbp"},
                "group_by": ["month"],
                "filters": [{"column": "product", "op": "==",
                             "value": ["sports", "casino", "slots", "lottery", "bingo"][len(calls) % 5]}]})

    auditor = D.SessionAuditor(budget=3)
    d = AnalystLoop(service, Greedy(), auditor=auditor, max_steps=50).run("q")
    assert d.stopped_because == "budget_exhausted"
    assert d.budget_spent == 3 and d.budget == 3
    assert calls == [3, 2, 1]                     # the policy saw the budget fall
    assert d.verdict == "not_answerable"
    assert d.claims[0].reason == "budget_exhausted"


def test_max_steps_stops_the_loop_without_a_conclusion(service):
    class Forever:
        def next(self, state):
            return Query("mean stake by month",
                         {"dataset": "bets", "measure": {"fn": "mean", "column": "stake_gbp"},
                          "group_by": ["month"], "filters": []})
    d = AnalystLoop(service, Forever(), max_steps=2).run("q")
    assert len(d.steps) == 2 and d.stopped_because == "max_steps"
    assert d.verdict == "not_answerable"


def test_every_step_is_audited_under_the_analyst_user(service, tmp_path):
    log = AuditLog(str(tmp_path / "audit.db"))
    pol = ScriptedPolicy(
        [("mean stake by night use band", MEAN_BY_BAND),
         ("show me every person's stake", {"dataset": "panel",
                                          "measure": {"fn": "mean", "column": "stake_gbp"},
                                          "group_by": ["person_id"], "filters": []})],
        _conclude(Claim("x", "supported", [1])))
    d = AnalystLoop(service, pol, audit_log=log, user="analyst-7").run("q")
    assert [s.status for s in d.steps] == ["released", "denied"]
    assert log.verify() is True
    mine = [r for r in log.since(0) if r.get("user") == "analyst-7"]
    assert len(mine) == 2
    assert {r["request"] for r in mine} == {"mean stake by night use band",
                                            "show me every person's stake"}
    assert {r["status"] for r in mine} == {"released", "denied"}


# --------------------------------------------------------------------------- #
# P23: the policy sees only the public side                                    #
# --------------------------------------------------------------------------- #

def test_loop_state_has_exactly_the_declared_public_fields():
    assert [f.name for f in dataclasses.fields(LoopState)] == [
        "question", "steps", "budget_remaining", "steps_remaining"]
    assert [f.name for f in dataclasses.fields(Step)] == [
        "id", "sub_question", "spec", "status", "message", "findings",
        "output", "artifacts", "cost"]


def test_denied_steps_carry_no_frame_and_hostile_data_never_reach_the_transcript(service, study):
    _, truth = study
    hostile = [s for vals in truth["adversarial"]["hostile_values"].values() for s in vals]
    seen = []

    class Spy(ScriptedPolicy):
        def next(self, state):
            seen.append(transcript(state))
            return super().next(state)

    pol = Spy([("count of people by region", BY_REGION),
               ("count of sessions by app category", BY_APP),
               ("mean stake by night use band", MEAN_BY_BAND)],
              _conclude(Claim("x", "supported", [3])))
    d = AnalystLoop(service, pol).run("q")
    full = "\n".join(seen) + d.to_json()
    for h in hostile:
        assert h not in full, h
    # the sub-threshold plants are suppressed by name: no released row for them
    for s in d.steps:
        for row in s.output or []:
            assert row.get("region") not in ("Northern Ireland",) or row.get("n") is None
            assert row.get("app_category") not in hostile
    # a denied step never carries a frame
    for s in d.steps:
        if s.status == "denied":
            assert s.output is None and s.artifacts is None


def test_findings_shown_to_the_policy_carry_rule_and_detail_only(service):
    pol = ScriptedPolicy(
        [("mean stake by region", {"dataset": "panel",
                                   "measure": {"fn": "mean", "column": "stake_gbp"},
                                   "group_by": ["region"], "filters": []})],
        _conclude(Claim("x", "supported", [1])))
    d = AnalystLoop(service, pol).run("q")
    for f in d.steps[0].findings:
        assert set(f) == {"rule", "detail"}


# --------------------------------------------------------------------------- #
# Typed conclusions                                                           #
# --------------------------------------------------------------------------- #

def test_claims_without_released_evidence_are_downgraded(service):
    pol = ScriptedPolicy(
        [("mean stake by night use band", MEAN_BY_BAND),
         ("mean stake by night use band excluding armed forces",
          dict(MEAN_BY_BAND, filters=NOT_AF))],          # denied (lineage)
        Conclude([Claim("real", "supported", [1]),
                  Claim("cites the denied step", "supported", [2]),
                  Claim("cites nothing", "null", []),
                  Claim("cites a step that does not exist", "not_supported", [9]),
                  Claim("honest refusal", "not_answerable", [2], "differencing")],
                 "supported"))
    d = AnalystLoop(service, pol).run("q")
    verdicts = [c.verdict for c in d.claims]
    assert verdicts == ["supported", "not_answerable", "not_answerable",
                        "not_answerable", "not_answerable"]
    assert d.claims[1].reason == "claim cites no released step"
    assert d.verdict == "supported"


def test_overall_verdict_needs_a_surviving_claim_of_its_kind(service):
    pol = ScriptedPolicy([], Conclude([Claim("nothing was asked", "supported", [])], "supported"))
    d = AnalystLoop(service, pol).run("q")
    assert d.claims[0].verdict == "not_answerable"
    assert d.verdict == "not_answerable"


def test_unknown_verdicts_are_coerced_to_not_answerable(service):
    pol = ScriptedPolicy([("mean stake by night use band", MEAN_BY_BAND)],
                         Conclude([Claim("x", "supported", [1])], "probably"))
    d = AnalystLoop(service, pol).run("q")
    assert d.verdict == "not_answerable"


# --------------------------------------------------------------------------- #
# The model's replies are untrusted input                                     #
# --------------------------------------------------------------------------- #

def test_parse_action_accepts_the_two_forms_and_rejects_the_rest():
    q = parse_action('{"action":"query","sub_question":"mean stake by month","spec":{"dataset":"bets"}}')
    assert isinstance(q, Query) and q.spec == {"dataset": "bets"}
    c = parse_action(json.dumps({"action": "conclude", "verdict": "null",
                                 "claims": [{"text": "no link", "verdict": "null", "evidence": [1]}]}))
    assert isinstance(c, Conclude) and c.claims[0].evidence == [1]
    for bad in ["not json", "[1,2]", '{"action":"delete"}',
                '{"action":"query","sub_question":"","spec":{}}',
                '{"action":"query","sub_question":"x","spec":"select *"}',
                '{"action":"conclude","verdict":"maybe","claims":[]}',
                '{"action":"conclude","verdict":"null","claims":[]}',
                '{"action":"conclude","verdict":"null","claims":[{"text":"x","verdict":"null","evidence":["1"]}]}']:
        with pytest.raises(ValueError):
            parse_action(bad)


class FakeClient:
    def __init__(self, replies):
        self.replies = list(replies)
        self.calls = []

    def complete(self, system, user):
        self.calls.append((system, user))
        return self.replies.pop(0) if self.replies else '{"action":"conclude","verdict":"not_answerable","claims":[{"text":"out of replies","verdict":"not_answerable","evidence":[]}]}'


def test_llm_policy_retries_once_then_refuses_typed(service):
    client = FakeClient(["garbage", "still garbage"])
    pol = LLMAnalystPolicy(client, retries=1)
    d = AnalystLoop(service, pol).run("q")
    assert d.verdict == "not_answerable"
    assert d.claims[0].reason.startswith("protocol_error")
    assert len(client.calls) == 2
    assert "not usable" in client.calls[1][1]


def test_llm_policy_recovers_on_the_retry(service):
    good = json.dumps({"action": "query", "sub_question": "mean stake by night use band",
                       "spec": MEAN_BY_BAND})
    done = json.dumps({"action": "conclude", "verdict": "supported",
                       "claims": [{"text": "rises", "verdict": "supported", "evidence": [1]}]})
    client = FakeClient(["nope", good, done])
    d = AnalystLoop(service, LLMAnalystPolicy(client)).run("q")
    assert [s.status for s in d.steps] == ["released"] and d.verdict == "supported"
    # the policy's system prompt carries the catalogue, and its user turn the
    # transcript — and nothing in either is a row
    assert '"dataset":"sessions|bets|panel|wellbeing|giving"' in client.calls[0][0]
    assert "RESEARCH QUESTION: q" in client.calls[-1][1]
    assert "released table:" in client.calls[-1][1]


def test_conclusion_within_budget_and_the_dossier_round_trips(service):
    pol = ScriptedPolicy([("mean stake by night use band", MEAN_BY_BAND)],
                         _conclude(Claim("rises", "supported", [1])))
    d = AnalystLoop(service, pol).run("q")
    back = json.loads(d.to_json())
    assert back["verdict"] == "supported" and back["steps"][0]["status"] == "released"
    assert set(back) >= {"question", "dataset", "steps", "claims", "verdict", "budget"}


# --------------------------------------------------------------------------- #
# The narrative check                                                         #
# --------------------------------------------------------------------------- #

def test_check_narrative_flags_invention_and_accepts_rounding(service):
    pol = ScriptedPolicy([("mean stake by night use band", MEAN_BY_BAND)],
                         _conclude(Claim("rises", "supported", [1])))
    d = AnalystLoop(service, pol).run("q")
    heavy = next(r["value"] for r in d.steps[0].output if r["night_use_band"] == "heavy")
    rare = next(r["value"] for r in d.steps[0].output if r["night_use_band"] == "rare")
    ok = f"Heavy users staked about {heavy:.0f} a month against {rare:.1f} for rare users, over 3 waves."
    assert d.check_narrative(ok) == []
    assert d.check_narrative("The mean was 123.45 and 9,999 people took part.") == ["123.45", "9,999"]


def test_llm_narrator_sees_only_the_dossier_and_records_unsupported_figures(service):
    pol = ScriptedPolicy([("mean stake by night use band", MEAN_BY_BAND)],
                         _conclude(Claim("rises", "supported", [1])))
    d = AnalystLoop(service, pol).run("q")
    client = FakeClient(["Stakes rise with night use; the effect was 777.7 units."])
    text = LLMNarrator(client).render(d)
    assert d.narrative == text and d.unsupported_figures == ["777.7"]
    shown = json.loads(client.calls[0][1])
    assert set(shown) == {"question", "verdict", "claims", "notes", "steps"}
    assert set(shown["steps"][0]) == {"id", "sub_question", "status", "message",
                                      "released_table", "released_companions"}


def test_verdict_vocabulary_is_closed():
    assert VERDICTS == ("supported", "not_supported", "null", "not_answerable")
    d = Dossier(question="q", dataset="x")
    assert d.verdict == "not_answerable"


def test_verdict_spellings_are_normalised_but_the_vocabulary_stays_closed():
    c = parse_action(json.dumps({"action": "conclude", "verdict": "Not Supported",
                                 "claims": [{"text": "x", "verdict": "unanswerable", "evidence": []},
                                            {"text": "y", "verdict": "no association", "evidence": [1]}]}))
    assert c.verdict == "not_supported"
    assert [k.verdict for k in c.claims] == ["not_answerable", "null"]
    with pytest.raises(ValueError):
        parse_action(json.dumps({"action": "conclude", "verdict": "partially supported",
                                 "claims": [{"text": "x", "verdict": "supported", "evidence": [1]}]}))


def test_a_conclusion_without_an_overall_verdict_takes_its_first_substantive_claims():
    c = parse_action(json.dumps({"action": "conclude",
                                 "claims": [{"text": "no causal reading", "verdict": "not_answerable", "evidence": []},
                                            {"text": "survives stratification", "verdict": "supported", "evidence": [3]}]}))
    assert c.verdict == "supported"
    c2 = parse_action(json.dumps({"action": "conclude",
                                  "claims": [{"text": "x", "verdict": "not_answerable", "evidence": []}]}))
    assert c2.verdict == "not_answerable"


# --- Benjamini-Hochberg multiplicity correction across released tests ------------

def test_multiplicity_correction_across_released_test_pvalues():
    d = Dossier(question="q", dataset="x")
    d.steps = [
        Step(id=1, sub_question="anova", spec={}, status="released",
             output=[{"source": "band", "p_value": 0.001},
                     {"source": "Residual", "p_value": float("nan")}]),
        Step(id=2, sub_question="corr", spec={}, status="released",
             output=[{"value": 0.5, "p_value": 0.04}]),
        Step(id=3, sub_question="denied", spec={}, status="denied", output=None),
    ]
    d.correct_multiplicity()
    # collected the two non-nan released p-values, in step order
    assert [m["step"] for m in d.multiplicity] == [1, 2]
    assert [m["p_value"] for m in d.multiplicity] == [0.001, 0.04]
    # BH of [0.001, 0.04] with m=2 -> [0.002, 0.04]
    assert d.multiplicity[0]["p_adjusted"] == pytest.approx(0.002, abs=1e-6)
    assert d.multiplicity[1]["p_adjusted"] == pytest.approx(0.04, abs=1e-6)
    # the adjusted values are citable (a narrator may write them; not flagged)
    assert 0.002 in d.released_numbers()


def test_multiplicity_needs_at_least_two_tests():
    d = Dossier(question="q", dataset="x")
    d.steps = [Step(id=1, sub_question="one", spec={}, status="released",
                    output=[{"p_value": 0.01}])]
    d.correct_multiplicity()
    assert d.multiplicity == []          # a correction over one test is the test
