# SCGA EXAMINATION ARCHITECTURE SUCCESSOR STOPPING RULE
## Version 1.0 — FROZEN BEFORE CONSTITUTION OF v0.4

Status: FROZEN
v0.3 package root SHA-256: 25c8def8a16846a8c87144604f6fe79638384136bb6597affa7623ad5216bf7b
v0.3 adversarial evaluation SHA-256: b99de4bd62a8bb0bf4054ecd506ddc87ba457a5e9cc96c01227873e3f4482f34

## Purpose
This rule fixes when redesign of the SCGA examination architecture stops and the frozen architecture is run against SCGA. It prevents indefinite recursion in which each trust anchor, causal model, topology model, proof mapping or evidence source must prove a deeper mechanism beneath itself.

## Continuation rule
A new successor is required only when a completed adversarial review of the current frozen successor produces at least one of:
1. a materially new BLOCKING falsifier capable of permitting a materially false strongest-positive result within the claimed scope;
2. a materially new failure class requiring a new examination primitive, governing layer, composition mechanism, evidence-authority mechanism, causal-entitlement mechanism or epistemic-termination rule;
3. a defect showing that an existing closure rule can hide, launder, synthesize or misclassify a materially false strongest-positive result.

Bounded scope narrowing, explicit limitations, implementation/test detail, or evidence-sufficiency findings do not by themselves require another redesign unless they satisfy one of the conditions above.

## Stopping condition
Architecture redesign STOPS when one frozen successor receives one complete adversarial pass satisfying all four:

SR-1: BLOCKING_FINDINGS = 0.

SR-2: NEW_PRIMITIVE_FAILURE_CLASS = 0.

SR-3: Every remaining finding is limited to bounded scope/claim narrowing, explicit epistemic limitation, implementation/test detail, evidence sufficiency within the declared architecture, or operational hardening that cannot elevate an unsupported state into the strongest positive result.

SR-4: No remaining finding can convert NOT_SUPPORTED, UNESTABLISHED, INSUFFICIENT_EVIDENCE, DIVERGENT, EXAMINATION_INVALID, or an out-of-model limitation into the strongest positive disposition through aggregation, omission, scope manipulation, trust-anchor recursion, evidence reuse, causal inference or composition.

When SR-1 through SR-4 hold:
ARCHITECTURE_REDESIGN_STOPS = TRUE
The next phase is execution of the frozen examination architecture against SCGA.

## Epistemic floor
The stopping rule does not require proof of the absence of every unknown trust dependency, topology path, causal confounder, consequence manifestation, higher-order interaction, or toolchain defect.

Instead, terminal trust roots, discovery bases, causal assumptions, interaction models, detectability models and proof/correspondence assumptions must be explicit and every positive result must be bounded to them.

A transparent bounded assumption is not treated as a hidden proof.

## Anti-goalpost rule
This stopping threshold SHALL NOT be changed in response to v0.4 or any later review result.

Any later stopping-rule successor must:
1. be separately identified and justified by a materially new reason the existing rule is unsafe;
2. be frozen before the examination-architecture successor whose result it governs;
3. have no retrospective effect on whether an already reviewed successor met this v1.0 threshold.

## Complete adversarial pass
A complete pass means the reviewer received the exact frozen object, attacked it as an opportunity to lose, issued one consolidated finding set with severity, and stated whether any new primitive-level failure class or materially false strongest-positive pathway remains.

## Governing interpretation
The finish condition is not “no criticism remains.”

It is:
No remaining criticism demonstrates that the examination architecture can award materially more than its frozen evidence, assumptions, causal basis, trust basis, interaction basis and scope legitimately earn.
