# Certification, hardware, and key custody

This document is guidance for taking safe-tre-agent from a synthetic-data
prototype to a service that could hold real data. It covers the standard to
benchmark against (SATRE), the certifications that sit around a live TRE, and the
authentication and key-custody hardware that make the software controls real.

Two framings up front. First, the code provides technical controls a certifier
looks for — an off-box audit key, identity gating, a restricted channel, a
disclosure gateway — but certification itself is an organisational programme, not
a dependency you install. Second, the guidance is UK-centric because the project
builds on OpenSAFELY, ACRO/SACRO and the Five Safes; the synthetic data is
Swiss-flavoured, so the Swiss/EU equivalents are noted where they differ.

## The benchmark: SATRE

The reference for a UK TRE is the [Standardised Architecture for Trusted Research
Environments (SATRE)](https://satre-specification.readthedocs.io/en/stable/),
from DARE UK and the University of Dundee. It is now the de facto standard, cited
in the 2024 Sudlow Review and the 2025 Scottish Safe Haven Charter. SATRE is
**75 mandatory statements** across four pillars, and an organisation
self-assesses against it. Version 2.0 is strengthening disclosure control and
federation.

Map the project onto SATRE first — it turns "is this a real TRE?" into a
checklist. The pillars, and what safe-tre-agent already contributes to each:

| SATRE pillar | What the prototype contributes today | What remains organisational / process |
|---|---|---|
| **Information governance** | audit trail (hash-chained log); documented threat model and hardening log | ISMS, project/researcher accreditation, DPIA, training, risk register |
| **Computing technology** | localhost bind + restricted-channel enforcement; hardened systemd unit; least-privilege read-only engine | host hardening, patching, secure boot, network firewalling, monitoring |
| **Data management** | the disclosure gateway and session auditor (output checking); identity allowlist (Safe People); no row-level egress by construction | data lifecycle, ingestion/curation, two-human output checking, metadata catalogue |
| **Supporting capabilities** | — | procurement, finance, PPIE, incident response, business continuity |

The gateway sits squarely in **Data management / output control**, which SATRE
v2.0 is expanding — the [best-practice review](best-practice-review.md) is the
detailed comparison against the ACRO/SACRO output-checking baseline that pillar
expects.

## Certification and accreditation stack

These are organisational certifications; ISO 27001 is the common baseline and the
others layer on depending on the data and route to access.

- **ISO 27001** — an information security management system (ISMS). The baseline
  for any contract that handles data, and increasingly a hard requirement.
- **ISO 27701** — the privacy extension to 27001, aligning the ISMS with GDPR
  obligations. Add it when the data is personal.
- **Cyber Essentials / Cyber Essentials Plus** — the UK baseline technical
  controls; often the floor for public-sector work, and no substitute for 27001.
- **NHS DSPT** (Data Security and Protection Toolkit) — a mandatory annual
  self-assessment against the National Data Guardian's ten standards, required if
  you touch NHS data. From 2025/26, IT suppliers need an **independent audit**,
  not self-assessment alone.
- **DEA / ONS accreditation** — for research access under the Digital Economy
  Act, if that is the legal route.

**Switzerland / EU.** The synthetic data uses Swiss cantons. For a Swiss or EU
deployment the analogues are the **SPHN / BioMedIT** information-security policy
and **FADP / GDPR** compliance, on the same **ISO 27001** base.

None of these exempts the others, and none certifies the code by itself — they
certify the organisation and its processes.

## Authentication: phishing-resistant MFA

Use hardware security keys for the people who reach the pod. NIST recognises only
two phishing-resistant authenticators — smart cards and **FIDO2** — and YubiKeys
implement FIDO2 and are FIPS 140-2 validated to AAL3. They matter in three
places here:

- **Safe People access.** Today the app trusts a tailnet login plus
  `SAFETRE_ALLOWLIST`. Production should put phishing-resistant MFA (FIDO2 /
  YubiKey) at the identity provider in front of the restricted channel. A phished
  researcher credential is the most realistic access attack, and this closes it.
- **Administrative and break-glass access.** Separate hardware keys, with use
  logged and reviewed — the [safepod model](safepod.md) already asks for the
  logging and a two-person rule for disk/console/firmware work.
- **Signed commits on the boundary files.** The repository's `AGENTS.md` flags
  signed commits as recommended; a YubiKey (PIV/GPG, or gitsign) is how you
  enforce it, so a change to the validation, engine, gateway or auditor carries a
  hardware-backed signature.

## Key custody and host hardware

The tamper-evident audit log is only as strong as where its key lives. The chain
is HMAC-keyed and the docs already require the key (`SAFETRE_AUDIT_KEY`) and the
head anchor to sit **off-box**. To make that real:

- **Hold the audit key in an HSM** (FIPS 140-2/3, Common Criteria) or at least a
  hardware-backed key store. An HSM gives a controlled key lifecycle and keeps
  its own audit trail of key use; a YubiKey/PIV can stand in at small scale. The
  audit head should be anchored off-pod so a host compromise cannot rewrite
  history undetected (`verify(expected_head=...)` checks it).
- **TPM plus secure or measured boot** on the host. Anchor the full-disk
  encryption keys in the TPM and lock firmware setup, so a stolen or tampered pod
  is detected and the data at rest stays protected. The
  [safepod model](safepod.md) lists the surrounding physical controls.
- **Keep the local model inside the pod.** The 120B-class planning profile in the
  [security model](security.md) runs on in-pod hardware (a testing box or an
  H100-class accelerator), so research questions never egress. A remote model is
  itself an egress channel and stays synthetic-data-only.

## Checklist before real data

- [ ] SATRE self-assessment complete; gaps tracked as an ISMS risk register.
- [ ] ISO 27001 (and 27701 for personal data) in progress or held; Cyber
      Essentials Plus; NHS DSPT if NHS data; DEA/ONS accreditation if that route.
- [ ] Phishing-resistant MFA (FIDO2/YubiKey) at the IdP for all Safe People and
      admins; break-glass keys held separately and logged.
- [ ] `SAFETRE_AUDIT_KEY` in an HSM / hardware-backed store; audit head anchored
      and mirrored off-pod; `/api/audit/verify` monitored.
- [ ] TPM + secure/measured boot; full-disk encryption keys TPM-anchored;
      firmware locked; USB/Thunderbolt/Wi-Fi/Bluetooth/serial disabled.
- [ ] Local model on in-pod hardware; `SAFETRE_ALLOW_REMOTE_LLM` unset;
      `IPAddressDeny=any` plus the fixed model endpoint only.
- [ ] Two trained human output checkers on every real release; the automated
      gateway is a pre-filter that reduces their load, not a replacement.
- [ ] Signed commits enforced on the boundary files; branch protection on `main`.

## What the code gives you, and what you must add

The prototype supplies the technical controls: the QuerySpec boundary, the
read-only engine, the disclosure gateway, the session auditor, the restricted
channel, the identity allowlist, and the off-box-keyed audit chain. Everything in
this document — the ISMS, the certifications, the hardware authentication and key
custody, the human output-checking process — is the organisation and operations
around those controls. The project is synthetic-only today precisely so none of
it is load-bearing yet.

## References

- SATRE specification. <https://satre-specification.readthedocs.io/en/stable/>
- DARE UK, SATRE driver project. <https://dareuk.org.uk/how-we-work/previous-activities/dare-uk-phase-1-driver-projects/satre-standardised-architecture-for-trusted-research-environments/>
- NHS Data Security and Protection Toolkit. <https://www.dsptoolkit.nhs.uk/>
- Yubico, FIDO2 / phishing-resistant MFA. <https://www.yubico.com/authentication-standards/fido2/>
- NIST SP 800-63B — authenticator assurance and phishing resistance.
- Hardware security modules for key management (overview). <https://www.fortinet.com/resources/cyberglossary/hardware-security-module>
- [Best-practice review](best-practice-review.md) · [Safepod model](safepod.md) · [Security model](security.md) · [Deployment](deployment.md)
