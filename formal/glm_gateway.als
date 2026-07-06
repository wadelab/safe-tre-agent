// glm_gateway — a bounded formal model of the GLM release path (spec R16).
//
// What is modelled: the catalogue (real atoms, generated from
// formal/skeleton.json), GLMSpec admissibility (mirroring
// safetre/query.py::GLMSpec._check_allowlist), the gateway's nondeterministic
// per-cell decision (the checker explores every combination of
// released/suppressed cells), and the service rule from
// safetre/service.py::_handle_model — a fit exists only when every design
// cell of its spec is released, and consumes exactly those cells.
//
// What is checked:
//   P19_noFitOnSuppressedCells  — no fit coexists with a suppressed cell of
//                                 its spec (deny on incomplete cell table);
//   P21_fitterSeesOnlyReleasedCells — a fit's inputs are all-and-only the
//                                 gateway-released cells of its spec;
//   P4_internalNeverEntersAModel — over the REAL catalogue atoms, at exact
//                                 bounds (an exhaustive check, not a sample):
//                                 no admissible spec can name an internal
//                                 column as a response or term;
//   AdmissibleSpaceMatchesCatalogue — dims and internal are disjoint per
//                                 dataset, so the two clauses above cannot
//                                 be vacuously satisfied.
//
// Correspondence discipline: the generated block below is produced by
// scripts/gen_alloy_catalogue.py from formal/skeleton.json; pytest
// (test_skeleton_sync.py, test_formal_alloy_sync.py) regenerates both and
// fails on drift, so the solver always checks the space the code exposes.

module glm_gateway

abstract sig Column {}
abstract sig Dataset {
  dims: set Column,
  internal: set Column,
}
abstract sig Family {}
one sig Gaussian, Binomial, Poisson extends Family {}

one sig Cat {
  allowedResponse: Family -> Dataset -> Column,
}

// --- GENERATED FROM formal/skeleton.json — do not edit by hand ---
one sig C_age_band, C_age_rating, C_age_years, C_amount_gbp, C_contains_lootboxes, C_device_os, C_event_type, C_genre, C_igds_score, C_income_band, C_ingame_currency, C_lootbox_events, C_monthly_spend_selfreport, C_pgsi_score, C_price_tier, C_purchase_events, C_region, C_sex, C_total_spend_gbp, C_wave, C_wemwbs_score extends Column {}
one sig D_donor_spend, D_spend, D_wellbeing extends Dataset {}
fact Catalogue {
  D_donor_spend.dims = C_age_band + C_device_os + C_income_band + C_region + C_sex
  D_donor_spend.internal = C_age_years
  D_spend.dims = C_age_band + C_age_rating + C_contains_lootboxes + C_device_os + C_event_type + C_genre + C_income_band + C_price_tier + C_region + C_sex
  D_spend.internal = C_age_years
  D_wellbeing.dims = C_age_band + C_device_os + C_income_band + C_region + C_sex + C_wave
  D_wellbeing.internal = C_age_years
  Cat.allowedResponse[Gaussian] = D_donor_spend -> C_total_spend_gbp + D_spend -> C_amount_gbp + D_spend -> C_ingame_currency + D_wellbeing -> C_igds_score + D_wellbeing -> C_monthly_spend_selfreport + D_wellbeing -> C_pgsi_score + D_wellbeing -> C_wemwbs_score
  Cat.allowedResponse[Binomial] = D_spend -> C_contains_lootboxes
  Cat.allowedResponse[Poisson] = D_donor_spend -> C_lootbox_events + D_donor_spend -> C_purchase_events
}
// --- END GENERATED ---

// --- GLMSpec admissibility (query.py GLMSpec._check_allowlist) --------------

sig GLMSpec {
  dataset: one Dataset,
  family: one Family,
  response: one Column,
  terms: set Column,
}

pred admissible[s: GLMSpec] {
  s.terms in s.dataset.dims
  #s.terms >= 1 and #s.terms <= 3
  s.response !in s.terms
  (s.dataset -> s.response) in Cat.allowedResponse[s.family]
}

// the boundary rejects everything else before any execution (P8)
fact OnlyAdmissibleSpecsExist { all s: GLMSpec | admissible[s] }

// --- the gateway and the service rule (service.py _handle_model) ------------

abstract sig Status {}
one sig Released, Suppressed extends Status {}

sig Cell {
  cellSpec: one GLMSpec,
  status: one Status,       // free: the checker explores every vetting outcome
}

sig Fit {
  fitSpec: one GLMSpec,
  inputs: set Cell,
}

fact ServiceRule {
  all f: Fit | {
    // the fit consumes exactly its spec's design cells ...
    f.inputs = { c: Cell | c.cellSpec = f.fitSpec }
    some f.inputs
    // ... and exists only when the gateway released every one of them
    all c: f.inputs | c.status = Released
  }
}

// --- the checked properties --------------------------------------------------

assert P19_noFitOnSuppressedCells {
  no f: Fit, c: Cell |
    c.cellSpec = f.fitSpec and c.status = Suppressed
}
check P19_noFitOnSuppressedCells for 6 GLMSpec, 18 Cell, 6 Fit

assert P21_fitterSeesOnlyReleasedCells {
  all f: Fit | f.inputs.status = Released and f.inputs.cellSpec = f.fitSpec
}
check P21_fitterSeesOnlyReleasedCells for 6 GLMSpec, 18 Cell, 6 Fit

// Exhaustive over the real catalogue: Dataset/Column/Family are exact one-sig
// atoms, and 3 terms over the largest dims set bounds GLMSpec's shape, so a
// check over all GLMSpec atoms at this scope covers the whole admissible
// space one spec at a time.
assert P4_internalNeverEntersAModel {
  all s: GLMSpec |
    no (s.terms & s.dataset.internal) and s.response !in s.dataset.internal
}
check P4_internalNeverEntersAModel for 4 GLMSpec, 0 Cell, 0 Fit

// guards the two checks above against vacuity: if a catalogue edit ever put
// an internal column among dims (or an internal response into the allowed
// map), this fails rather than letting P4 hold emptily
assert AdmissibleSpaceMatchesCatalogue {
  all d: Dataset | no (d.dims & d.internal)
  all f: Family | all d: Dataset |
    no (Cat.allowedResponse[f][d] & d.internal)
}
check AdmissibleSpaceMatchesCatalogue for 0 GLMSpec, 0 Cell, 0 Fit

// sanity: the admissible space is inhabited (the checks are not vacuous)
pred someAdmissibleSpec { some s: GLMSpec | #s.terms = 3 }
run someAdmissibleSpec for 3 GLMSpec, 0 Cell, 0 Fit
