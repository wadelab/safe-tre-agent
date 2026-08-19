"""The reviewer-facing bundle and its signature (build plan M7 and M8).

**Milestone 7's acceptance test is about a person, not a schema.** A technically
competent reviewer holding only the exported directory and the source repository
should be able to answer six questions: what was asked, what public method ran,
what evidence was released, whether the computation replayed, whether the
analysis was pre-specified or exploratory, and what they still have to trust the
custodian about. Each of those is one test below, asked of the generated
`README.md` — because the report is what a reviewer actually reads, and a bundle
whose JSON contains an answer its report does not surface has not answered it.

The report is generated, so it is also *checkable*: `verify_bundle_dir`
re-renders it from the JSON beside it and compares bytes. A Markdown file a
reviewer reads but cannot re-derive is prose asserting things about data they
cannot see, which is what D9 exists to replace.

**Milestone 8 is tamper-evidence.** The signature must fail after each of the
five changes the plan names — a reported value, the dataset manifest, the replay
certificate, a provenance node, the analysis classification — and the internal
HMAC key must not be what checks it.

Throughout: nothing private may reach the directory. The plan under test
excludes a sub-threshold employment category through its data-sighted
contingency, so there is a real private string to look for, and every file is
swept for it.
"""

from __future__ import annotations

import json
import os

import pytest

from safetre import attestation as A
from safetre import vrr_bundle as B
from safetre.config import load_policy_config
from safetre.provenance import compile_public_provenance
from safetre.replay import ReplayContext, replay
from safetre.research_record import RecordError
from studies.nightplay import verify as V
from tests.vrr_harness import (
    ADJUSTED, CONFOUNDED, CUSTODIAN, KEY, POPULATION, SNAPSHOT, build_record,
)

SEED = b"a-fixed-32-byte-test-signing-key"


@pytest.fixture
def signed(vrr_study, vrr_service, vrr_manifests, vrr_log, tmp_path):
    """A complete, replayed, signed, exported record. The whole vertical slice
    in one fixture, because every check below is about the artifact a reviewer
    receives rather than about a stage of building it."""
    tables, _ = vrr_study
    _, _, record = build_record(vrr_service, vrr_manifests, vrr_log)
    context = ReplayContext(
        tables=tables, policy_config=load_policy_config(),
        service_factory=V.build_service, snapshot_id=SNAPSHOT,
        commitment_key=KEY, population=POPULATION, custodian=CUSTODIAN)
    record = record.model_copy(update={"certificate": replay(record, context)})
    secret, public = A.generate_keypair(seed=SEED)
    out = str(tmp_path / "bundle")
    B.export_bundle(record, out, attestation=A.attest(record, secret, public))
    return record, out, public


def _load(path, name):
    with open(os.path.join(path, name), encoding="utf-8") as fh:
        return json.load(fh)


def _report(path):
    with open(os.path.join(path, B.REPORT), encoding="utf-8") as fh:
        return fh.read()


def _rewrite(path, name, mutate):
    data = _load(path, name)
    mutate(data)
    with open(os.path.join(path, name), "w", encoding="utf-8") as fh:
        json.dump(data, fh, indent=2, sort_keys=True)


# --------------------------------------------------------------------------- #
# milestone 7 — what a reviewer can answer from the bundle alone              #
# --------------------------------------------------------------------------- #

def test_the_bundle_holds_the_files_it_claims(signed):
    _, path, _ = signed
    assert sorted(os.listdir(path)) == sorted(B.FILES)
    assert _load(path, "record.json")["files"] == list(B.FILES)


def test_a_reviewer_can_see_what_was_asked(signed):
    record, path, _ = signed
    report = _report(path)
    assert record.trace.question in report
    # The plan's HASH, not its body (#109). This test used to assert that every
    # declared sub-question appeared in the report, which is the leak: a reader
    # holding the plan takes its stage set minus the published nodes and has the
    # gateway's verdict on each stage of the cohort.
    assert record.trace.plan_ref in report
    for stage in record.trace.committed_plan["stages"]:
        assert stage["sub_question"] not in report
        assert stage["id"] not in report or stage["id"] in {
            n["stage_id"] for n in _load(path, "provenance.json")["nodes"]}


def test_the_report_says_why_the_plan_body_is_absent(signed):
    """An omission a reader cannot distinguish from an oversight will be read as
    an oversight, and the next person will helpfully "fix" it."""
    _, path, _ = signed
    report = _report(path)
    assert "The plan's **hash** is published; its body is not" in report
    assert "finding #109" in report


def test_a_reviewer_can_see_what_public_method_ran(signed):
    _, path, _ = signed
    report = _report(path)
    assert "glm (gaussian)" in report
    assert "`stake_gbp ~ night_use_band, employment`" in report
    assert "TRE_REPLAYABLE_EXACT" in report


def test_a_reviewer_can_see_what_evidence_was_released(signed):
    record, path, _ = signed
    report = _report(path)
    for item in record.evidence:
        assert item.evidence_id in report
    assert len(_load(path, "evidence.json")) == len(record.evidence)


def test_a_reviewer_can_see_whether_it_replayed(signed):
    _, path, _ = signed
    assert "COMPUTATION_REPRODUCED" in _report(path)
    assert _load(path, "replay_certificate.json")["outcome"] == "COMPUTATION_REPRODUCED"


def test_a_reviewer_can_see_whether_it_was_prespecified(signed):
    _, path, _ = signed
    report = _report(path)
    assert "TRE_PRECOMMITTED" in report
    assert "narrower than scientific pre-registration" in report


def test_a_reviewer_can_see_what_is_left_to_trust(signed):
    _, path, _ = signed
    report = _report(path)
    assert "## 9. What is and is not verified" in report
    assert "Machine verification is not scientific validity" in report
    assert "only the custodian can attest that" in report


def test_the_report_names_the_population_the_numbers_are_over(signed):
    _, path, _ = signed
    assert POPULATION in _report(path)


def test_the_report_is_regenerable_from_the_json_beside_it(signed):
    _, path, _ = signed
    regenerated = B.render_report_from_public(
        record_id=_load(path, "record.json")["record_id"],
        provenance=_load(path, "provenance.json"),
        evidence=_load(path, "evidence.json"),
        certificate=_load(path, "replay_certificate.json"),
        software=_load(path, "software_manifest.json"),
        dataset=_load(path, "dataset_manifest.json"),
        disclosure=_load(path, "disclosure_manifest.json"))
    assert regenerated == _report(path)


def test_the_bundle_is_byte_deterministic(signed, tmp_path):
    record, first, _ = signed
    secret, public = A.generate_keypair(seed=SEED)
    second = str(tmp_path / "again")
    B.export_bundle(record, second, attestation=A.attest(record, secret, public))
    for name in B.FILES:
        with open(os.path.join(first, name), "rb") as a, \
             open(os.path.join(second, name), "rb") as b:
            assert a.read() == b.read(), name


def test_the_bundle_verifies_offline(signed):
    _, path, public = signed
    ok, findings = B.verify_bundle_dir(path, public_key=public)
    assert ok, findings


# --------------------------------------------------------------------------- #
# nothing private reaches the directory                                       #
# --------------------------------------------------------------------------- #

def test_no_private_string_is_anywhere_in_the_bundle(signed):
    record, path, _ = signed
    private = [lv for st in record.trace.stages for lv in st.excluded_levels]
    private += [st.message for st in record.trace.stages if st.message]
    private += [str(f["detail"]) for st in record.trace.stages
                for f in st.findings if f.get("detail")]
    private.append(record.trace.user)
    private = [s for s in private if s]
    assert any(lv for st in record.trace.stages for lv in st.excluded_levels), \
        "the plan's contingency should have excluded a level, or this test has " \
        "nothing private to look for"
    for name in B.FILES:
        with open(os.path.join(path, name), encoding="utf-8") as fh:
            text = fh.read()
        for secret in private:
            assert secret not in text, f"{secret!r} leaked into {name}"


def test_the_private_trace_is_not_in_the_bundle(signed):
    record, path, _ = signed
    for name in B.FILES:
        with open(os.path.join(path, name), encoding="utf-8") as fh:
            text = fh.read()
        assert "executed_parameters" not in text
        assert "selection_bits" not in text
        assert "private_detail" not in text
    assert record.trace.stages[0].executed_parameters["filters"]


def test_an_export_that_would_leak_is_refused(signed):
    record, path, _ = signed
    # forge a record whose public question quotes the withheld category
    level = record.trace.stages[0].excluded_levels[0]
    trace = record.trace.model_copy(update={"question": f"why is {level} missing?"})
    forged = record.model_copy(update={
        "trace": trace,
        "provenance": record.provenance.model_copy(
            update={"question": f"why is {level} missing?"})})
    with pytest.raises(RecordError, match="private trace content"):
        B.export_bundle(forged, path + "-leaky")


def test_a_bundle_needs_compiled_provenance(signed):
    record, path, _ = signed
    with pytest.raises(RecordError, match="needs compiled public provenance"):
        B.export_bundle(record.model_copy(update={"provenance": None}), path + "-bare")


# --------------------------------------------------------------------------- #
# milestone 8 — tamper-evidence                                               #
# --------------------------------------------------------------------------- #

def test_the_signature_is_asymmetric_and_not_the_audit_key(signed):
    record, _, public = signed
    secret, _ = A.generate_keypair(seed=SEED)
    assert secret != public, "a shared secret is not an asymmetric key"
    digest = A.bundle_digest(record)
    signature = A.sign_bundle(digest, secret)
    assert A.verify_bundle(digest, signature, public)
    # verification needs only the PUBLIC half; nothing secret leaves the safepod
    _, other_public = A.generate_keypair(seed=b"a-different-32-byte-test-keyxxxx")
    assert not A.verify_bundle(digest, signature, other_public)


def test_the_signed_payload_covers_the_parts_it_claims(signed):
    record, _, _ = signed
    payload = A.attestation_payload(record)
    assert set(payload) == {
        "scheme", "record_id", "schema_version", "public_bundle_digest",
        "replay_certificate_digest", "software_manifest_digest",
        "dataset_manifest_digest", "disclosure_manifest_digest"}
    assert all(v is not None for v in payload.values())


def test_verification_fails_after_changing_a_reported_value(signed):
    _, path, public = signed

    def edit(items):
        key = sorted(items[0]["values"])[0]
        items[0]["values"][key] = 99.9

    _rewrite(path, "evidence.json", edit)
    ok, findings = B.verify_bundle_dir(path, public_key=public)
    assert not ok
    assert any("attestation" in f or "digest" in f for f in findings)


def test_verification_fails_after_swapping_the_dataset_manifest(signed):
    _, path, public = signed
    _rewrite(path, "dataset_manifest.json",
             lambda d: d.update({"snapshot_id": "a-different-snapshot"}))
    ok, findings = B.verify_bundle_dir(path, public_key=public)
    assert not ok
    assert any("dataset_manifest.json" in f for f in findings)


def test_verification_fails_after_swapping_the_replay_certificate(signed):
    _, path, public = signed
    _rewrite(path, "replay_certificate.json",
             lambda d: d.update({"record_digest": "0" * 64}))
    ok, findings = B.verify_bundle_dir(path, public_key=public)
    assert not ok
    assert any("stale or swapped certificate" in f for f in findings)


def test_verification_fails_after_deleting_a_provenance_node(signed):
    _, path, public = signed
    _rewrite(path, "provenance.json", lambda d: d.update({"nodes": []}))
    ok, findings = B.verify_bundle_dir(path, public_key=public)
    assert not ok
    assert any("public bundle digest" in f for f in findings)


def test_verification_fails_after_changing_the_classification(signed):
    _, path, public = signed
    _rewrite(path, "provenance.json",
             lambda d: d.update({"classification": "TRE_PRECOMMITTED"
                                 if d["classification"] != "TRE_PRECOMMITTED"
                                 else "EXPLORATORY_POSTHOC"}))
    ok, findings = B.verify_bundle_dir(path, public_key=public)
    assert not ok


def test_verification_fails_after_editing_the_report(signed):
    _, path, public = signed
    with open(os.path.join(path, B.REPORT), "a", encoding="utf-8") as fh:
        fh.write("\nThe effect is causal and large.\n")
    ok, findings = B.verify_bundle_dir(path, public_key=public)
    assert not ok
    assert any("README.md is not what this bundle's JSON renders to" in f
               for f in findings)


def test_verification_fails_without_the_attestation(signed):
    _, path, public = signed
    with open(os.path.join(path, "attestation.json"), "w", encoding="utf-8") as fh:
        fh.write("null\n")
    ok, findings = B.verify_bundle_dir(path, public_key=public)
    assert not ok
    assert any("carries no attestation" in f for f in findings)


def test_a_missing_file_fails_verification(signed):
    _, path, public = signed
    os.remove(os.path.join(path, "evidence.json"))
    ok, findings = B.verify_bundle_dir(path, public_key=public)
    assert not ok and "missing file(s)" in findings[0]


def test_the_attestation_is_re_derived_not_trusted(signed):
    record, path, public = signed
    block = _load(path, "attestation.json")
    ok, why = A.verify_attestation(block, record, public)
    assert ok, why
    edited = record.evidence[0].model_copy(update={"values": {"estimate": 1.0}})
    moved = record.model_copy(update={"evidence": [edited, *record.evidence[1:]]})
    ok, why = A.verify_attestation(block, moved, public)
    assert not ok and "not this record's payload" in why


# --------------------------------------------------------------------------- #
# the signing primitive                                                       #
# --------------------------------------------------------------------------- #

def test_the_reference_signer_matches_rfc8032():
    """RFC 8032 §7.1 test vector 1. The fallback signer is hand-written, so it
    is checked against the standard's own vector rather than against itself."""
    from safetre.attestation import _ref_public, _ref_sign, _ref_verify

    secret = bytes.fromhex(
        "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60")
    public = bytes.fromhex(
        "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a")
    assert _ref_public(secret) == public
    signature = _ref_sign(secret, b"")
    assert signature.hex() == (
        "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e06522490155"
        "5fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b")
    assert _ref_verify(public, b"", signature)
    assert not _ref_verify(public, b"x", signature)


def test_a_malformed_signature_is_rejected_rather_than_raised():
    _, public = A.generate_keypair(seed=SEED)
    assert A.verify_bundle("digest", "not hex", public) is False
    assert A.verify_bundle("digest", "00" * 64, public) is False
    assert A.verify_bundle("digest", "", public) is False


def test_the_signature_is_domain_separated():
    secret, public = A.generate_keypair(seed=SEED)
    from safetre.attestation import _ref_verify
    signature = bytes.fromhex(A.sign_bundle("abc", secret))
    assert _ref_verify(public, A.DOMAIN + b"abc", signature)
    assert not _ref_verify(public, b"abc", signature), \
        "a bare-digest signature could be replayed into another protocol"


def test_a_level_the_committed_plan_itself_names_can_be_waived(signed):
    """The one legal case the private-string sweep would otherwise block.

    A committed plan may filter on a named category, and the same category may
    also be what the plan's contingency excludes — at which point the level is
    in `excluded_levels` (private) AND in the published plan (public, because
    the researcher declared it in advance). The sweep sees a private string in
    a public file and is right to stop; the waiver is how a custodian says
    "that one was ours", and it is explicit so nothing is waived silently.
    """
    record, path, _ = signed
    stage = record.trace.stages[0]
    level = stage.excluded_levels[0]
    # A committed filter naming the level: request-decided, so it is legitimately
    # among the stage's PUBLIC parameters, and the sweep is right to stop on it
    # because the same string is also what the contingency excluded.
    declared = stage.model_copy(update={"public_parameters": dict(
        stage.public_parameters,
        filters=[{"column": "employment", "op": "!=", "value": level}])})
    trace = record.trace.model_copy(update={"stages": [declared]})
    forged = record.model_copy(update={"trace": trace})
    forged = forged.model_copy(update={
        "provenance": compile_public_provenance(trace, forged.evidence)})

    with pytest.raises(RecordError, match="private trace content"):
        B.export_bundle(forged, path + "-declared")
    B.export_bundle(forged, path + "-declared", allow_expected_levels=(level,))
    assert os.path.exists(os.path.join(path + "-declared", B.REPORT))


# --------------------------------------------------------------------------- #
# 🧪 the Alchemist: a perfectly reproduced bad analysis                        #
# --------------------------------------------------------------------------- #
#
# The one beast in `docs/bestiary-vrr-additions.md` with no deterministic cage:
# every hash matches, the replay is exact, the signature is valid, and the model
# adjusted for the wrong thing. Its keeper is a fixture — an intentionally
# reproducible but scientifically wrong analysis — to check the report awards it
# no correctness badge. NIGHTPLAY plants the trap on purpose (T2), so the
# fixture is the study's own confounded model rather than something contrived.

@pytest.fixture
def confounded(vrr_study, vrr_service, vrr_manifests, vrr_log, tmp_path):
    tables, _ = vrr_study
    _, run, record = build_record(vrr_service, vrr_manifests, vrr_log, CONFOUNDED)
    context = ReplayContext(
        tables=tables, policy_config=load_policy_config(),
        service_factory=V.build_service, snapshot_id=SNAPSHOT,
        commitment_key=KEY, population=POPULATION, custodian=CUSTODIAN)
    record = record.model_copy(update={"certificate": replay(record, context)})
    secret, public = A.generate_keypair(seed=SEED)
    out = str(tmp_path / "confounded")
    B.export_bundle(record, out, attestation=A.attest(record, secret, public))
    return record, run, out, public


def test_the_confounded_analysis_really_does_replay_and_verify(confounded):
    """The premise. If this record did not verify, the test below would be
    checking that a *broken* bundle awards no badge, which proves nothing."""
    record, _, path, public = confounded
    assert record.certificate.reproduced()
    ok, findings = B.verify_bundle_dir(path, public_key=public)
    assert ok, findings


def test_the_confounded_estimate_is_wrong_by_a_third(confounded, vrr_service,
                                                     vrr_manifests, tmp_path):
    """And it is wrong in the direction NIGHTPLAY planted, so the fixture is
    demonstrably a bad analysis rather than merely an unadjusted one."""
    from safetre.audit import AuditLog

    _, run, _, _ = confounded
    naive = {(r["term"], r["level"]): r["estimate"] for r in run.stages[0].output}

    other = AuditLog(str(tmp_path / "adjusted.db"))
    _, adjusted_run, _ = build_record(vrr_service, vrr_manifests, other, ADJUSTED)
    adjusted = {(r["term"], r["level"]): r["estimate"]
                for r in adjusted_run.stages[0].output}

    key = ("night_use_band", "heavy")
    assert naive[key] > adjusted[key] * 1.2, (
        f"unadjusted {naive[key]} vs adjusted {adjusted[key]}: the planted "
        "confounder should inflate the naive estimate")


def test_a_reproducible_wrong_analysis_gets_no_correctness_badge(confounded):
    _, _, path, _ = confounded
    report = _report(path)

    # nothing anywhere in the bundle asserts the science
    for name in B.FILES:
        with open(os.path.join(path, name), encoding="utf-8") as fh:
            text = fh.read().upper()
        for badge in ("SCIENTIFICALLY_VALID", "SCIENTIFICALLY VALID", "IS VALID",
                      "IS CORRECT", "CONCLUSION SUPPORTED", "CAUSAL"):
            assert badge not in text, f"{name} awards {badge!r}"

    # and the report says so, next to the green ticks rather than far from them
    assert "Machine verification is not scientific validity" in report
    assert "no machine-generated field anywhere in this bundle asserts it" in report
    assert "the cohort, model and covariates were scientifically appropriate" in report


def test_the_assurance_table_does_not_collapse_into_one_badge(confounded):
    """The Peacock's rule, checked on the bundle a reviewer receives: the
    computation reproducing must not be presented as the data being attested."""
    _, _, path, _ = confounded
    report = _report(path)
    assert "| `COMPUTATION_REPRODUCED` | established" in report
    assert "| `DATA_SNAPSHOT_ATTESTED` | not established" in report
    assert "rests on the custodian's word" in report


# --------------------------------------------------------------------------- #
# 🗣️ the Court Reporter: publishes everything because "transparency"          #
# --------------------------------------------------------------------------- #
#
# The keeper the bestiary asks for is planted strings, not the ones that happen
# to be there. `test_no_private_string_is_anywhere_in_the_bundle` sweeps for the
# category the contingency really excluded, which is a genuine private fact but
# also the only one this plan produces. Planting is what covers the fields no
# current analysis fills — and one of them, `private_detail`, is deliberately
# untyped, which is exactly where a future caller will put something careless.

PLANTED = {
    "private_detail": "CANARY-DIAGNOSTIC-4f2a: donor 88213 holds 91% of the cell",
    "message": "CANARY-MESSAGE-9c1b: suppressed 6 cells below threshold",
    "finding": "CANARY-FINDING-77de: armed_forces has 6 donors",
    "executed_filter": "CANARY-FILTER-1e05",
    "user": "CANARY-USER-b3c9",
    "probe": "CANARY-PROBE-a740",
}


@pytest.fixture
def planted(vrr_service, vrr_manifests, vrr_log, tmp_path):
    """A record with a hostile string in every private field there is."""
    _, _, record = build_record(vrr_service, vrr_manifests, vrr_log)
    stage = record.trace.stages[0]
    loaded = stage.model_copy(update={
        "private_detail": {"diagnostic": PLANTED["private_detail"],
                           "retries": 3, "rejected": ["a-candidate-model"]},
        "message": PLANTED["message"],
        "findings": [{"rule": "dominance", "detail": PLANTED["finding"]}],
        "executed_parameters": dict(stage.executed_parameters, filters=[
            {"column": "employment", "op": "!=", "value": PLANTED["executed_filter"]}]),
        "excluded_levels": [PLANTED["probe"]],
    })
    trace = record.trace.model_copy(update={"stages": [loaded],
                                           "user": PLANTED["user"]})
    loaded_record = record.model_copy(update={"trace": trace})
    secret, public = A.generate_keypair(seed=SEED)
    out = str(tmp_path / "planted")
    B.export_bundle(loaded_record, out,
                    attestation=A.attest(loaded_record, secret, public))
    return loaded_record, out


def test_no_planted_private_string_reaches_the_public_bundle(planted):
    _, path = planted
    for name in B.FILES:
        with open(os.path.join(path, name), encoding="utf-8") as fh:
            text = fh.read()
        for label, canary in PLANTED.items():
            assert canary not in text, f"{label} leaked into {name}"
        assert "CANARY" not in text, f"an unlabelled canary reached {name}"


def test_the_planted_record_is_otherwise_a_normal_bundle(planted):
    """So the test above is not passing because the export quietly failed."""
    record, path = planted
    assert sorted(os.listdir(path)) == sorted(B.FILES)
    assert len(_load(path, "evidence.json")) == len(record.evidence)
    assert _load(path, "provenance.json")["nodes"]


def test_planting_a_canary_in_a_public_field_is_caught(planted, vrr_service,
                                                       vrr_manifests, vrr_log,
                                                       tmp_path):
    """The control. The sweep must be able to fail, or the two tests above are
    checking that a string nobody copied did not get copied."""
    record, _ = planted
    stage = record.trace.stages[0]
    leaky = stage.model_copy(update={
        "public_parameters": dict(stage.public_parameters,
                                  response=PLANTED["private_detail"])})
    trace = record.trace.model_copy(update={"stages": [leaky]})
    forged = record.model_copy(update={"trace": trace})
    forged = forged.model_copy(update={
        "provenance": compile_public_provenance(trace, forged.evidence)})
    with pytest.raises(RecordError, match="private trace content"):
        B.export_bundle(forged, str(tmp_path / "leaky"))
