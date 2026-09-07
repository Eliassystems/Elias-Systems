# ECGK v1.0.3 — Elias Constitutional Governance Kernel

## Trust, Authority and Execution-Time Governance

ECGK is the Elias model-agnostic governance kernel for authority, evidence, posture, admissibility and trust verification before consequential execution.

Its central rule is:

**CAPABILITY ≠ AUTHORITY TO EXECUTE**

A system may be technically capable of acting while lacking valid present authority to do so.

---

## Architectural Position

The public Elias sequence now moves through:

**Human → Identity → Epistemic Governance → Constitutional Control → Authority Revalidation → Execution → Witness**

The preceding Elias Runtime layer establishes governance before execution.

ECGK moves that proposition into a bounded executable trust and authority mechanism.

---

## ECGK v1.0.3

Version 1.0.3 hardened the kernel around authenticated, bound, current and non-replayable governance objects.

ECGK v1.0.3 requires authority to be established through:

- configured trust roots;
- current-state resolution;
- bounded scope;
- validity-window checks;
- revocation checks;
- attributable authority provenance;
- and execution-time revalidation.

Caller-declared `verified=True` is not trusted merely because the caller supplied it.

---

## Evidence Binding

Evidence promotion must remain bound to the exact canonical claim and its source or content commitment.

The governing principle is:

**ATTESTATION ≠ TRUTH**

A valid attestation can establish provenance or integrity without automatically proving that every underlying proposition is true.

Evidence must therefore remain attributable to what it actually establishes.

---

## Continuity

ECGK binds receipt continuity to:

**session → turn → posture → prior accepted receipt**

Caller-supplied posture cannot silently replace the trusted posture carried by the governance ledger.

Replay, rollback and invalid cross-session continuation are designed to fail closed.

---

## Scope and Consequence

Consequential permission is checked against a required action scope rather than simply trusting the scope label supplied by a caller.

This preserves another Elias distinction:

**REQUESTED SCOPE ≠ AUTHORISED SCOPE**

A valid determination must remain bound to the action it actually governs.

---

## Execution Permit

Where a consequential decision is admissible, ECGK can issue a short-lived execution permit.

That permit does not create permanent authority.

Immediately before execution, the kernel can revalidate the permit against the current authority state.

This addresses the changed-state problem:

**VALID THEN ≠ VALID NOW**

An authority that was valid when a decision was made may later be revoked, expired, superseded or otherwise lose governing standing.

Execution must therefore be governed by present state, not historical validity alone.

---

## Constitutional Veto

Constitutional veto conditions remain upstream of the Elias 97/3 weighted governance score.

A prohibited constitutional condition cannot be averaged away by otherwise favourable scoring.

**A veto is a veto.**

---

## Public Implementation

Public kernel:

`elias_constitutional_governance_kernel_v1_0_3.py`

Recorded SHA-256:

`bee70e97a41a00c9d1bd3f80080cb55614018fa8693bd6d64b445ac6a7872ce1`

Recorded constitution fingerprint:

`1680b86f063270b038692ed715d89d54b0e750bd29c92f504dfcd4061b20fc3f`

---

## Public Boundary

ECGK v1.0.3 is a transparent single-process demonstration kernel.

Its public evidence supports bounded internal adversarial and regression behaviour.

It does not establish:

- production readiness;
- independent certification;
- regulatory approval;
- universal AI safety;
- production-grade trust-root administration;
- distributed durable continuity;
- or route-complete non-bypass enforcement across every external executor.

Production deployment would require stronger independent trust infrastructure, protected key custody, durable state and deployment-specific controls.

---

## Preceding Layer

**03 — Elias Runtime — Constitutional Control Plane**

Governance between intelligence and consequence.

---

## Next Layer

**05 — Keystone — Consequence-Bearing Successor Layer**

The next layer moves from bounded governance primitives toward consequence-bearing implementation and successor hardening.

---

## Public Examination

ECGK is published so that reviewers can inspect the actual boundary between:

**authority → evidence → standing → permission → execution**

Do not assume authority.

Establish it.

Do not rely on historical validity.

Revalidate it.

Do not erase failure.

Preserve the evidence.

**Lock it. Log it. Prove it.**

Elias Systems Ltd  
Founder & AI Governance Architect: Gary Williams
