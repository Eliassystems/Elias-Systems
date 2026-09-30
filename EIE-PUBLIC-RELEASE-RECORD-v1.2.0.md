# Elias Systems — Governed AI Runtime & Evidence Record v1.2.0

**PUBLIC SUCCESSOR RELEASE RECORD**

**Lock it. Log it. Prove it.**

This v1.2.0 release records a major successor step in the Elias Systems programme: the move from public architecture records and bounded reference implementations into a working governed conversational AI system that has completed a local production-readiness examination within a defined, evidence-bound test boundary.

It does **not** replace the frozen Elias Discipline — EBASE-001 v1.0.0 baseline or the v1.1.0 Public Architecture Record. Those remain preserved historical predecessors.

The central principle remains unchanged:

> **Capability does not equal authority.**

The v1.2.0 successor record shows how that principle is now carried through memory, evidence, database authority, execution boundaries, security controls, recovery, runtime alignment and deployment restraint.

---

## 1. From Architecture to a Working Governed AI System

The Elias EIE programme now includes a working application stack with:

- frontend, backend, PostgreSQL and containerised runtime;
- live conversational AI with provider/model routing and streamed responses;
- persistent conversations;
- persistent tenant-controlled SQL memory;
- cross-conversation memory retrieval;
- relevance gating that can deliberately retrieve zero memories when none are relevant;
- centrally protected provider credentials used internally at runtime;
- governed conversation receipts recording relevant runtime context.

This is not presented as a generic chatbot milestone.

The focus is the governance surface around what the system knew, what it used, what authority existed and what evidence can later establish.

---

## 2. Historical Memory Evidence That Survives Live-State Change

A key breakthrough in this successor line is the separation of **historical evidence** from **mutable live memory**.

Governed receipts preserve the memory snapshot used at the time of the governed event, including snapshot identities and digest material sufficient for later verification inside the tested boundary.

Controlled testing established that:

- a historical receipt can remain independently verifiable after the corresponding live memory is changed or deleted;
- preserved snapshot evidence is not retrospectively rewritten to match later live state;
- live-state drift is reported separately from historical evidence;
- absence of the live memory does not silently erase the historical record.

This creates an important distinction:

> **Changed live state ≠ changed historical evidence.**

The system is designed to report what was used then and what exists now as separate facts.

---

## 3. Receipt Integrity and Runtime Mutation Restraint

The receipt layer was examined beyond simple application behaviour.

Within the tested database boundary:

- the normal runtime role retains read/insert capability required for operation;
- direct receipt UPDATE authority is denied;
- direct receipt DELETE authority is denied;
- direct receipt TRUNCATE authority is denied;
- application-level deletion behaviour refuses destructive removal where preserved historical receipt state would be lost;
- the foreign-key ancestor graph was examined transitively;
- no complete runtime-deletable cascade path into the historical receipt root was established.

The public claim is intentionally bounded.

Some receipt relationships are relational/application-level bindings rather than a claim that every relationship in the system is independently cryptographically chained.

Where cryptographic evidence exists, it is described as cryptographic. Where the evidence is relational, it is described as relational.

---

## 4. Separation of Runtime Authority From Administrative Authority

The database authority model was hardened so the application runtime does not inherit administrative or migration authority merely because it can access the database.

The tested model separates:

- restricted runtime operation;
- administrative ownership;
- migration authority;
- schema-changing capability.

The backend runtime operates through a restricted database identity.

Migration authority is not implicitly available to normal runtime startup.

This follows the same Elias control rule used elsewhere:

> **Possession of a technical capability does not establish standing authority to exercise it.**

---

## 5. Request, Session and Origin Hardening

The live application boundary was hardened and then behaviorally falsified.

The tested controls include:

- an actual byte-count request-body limit rather than relying only on declared Content-Length;
- rejection of malformed request-length declarations;
- refusal of oversized bodies even where declared size is absent or understated;
- replay of accepted request bodies to downstream application logic;
- explicit Origin enforcement for cookie-authenticated unsafe HTTP methods;
- refusal of authenticated unsafe requests with a foreign Origin;
- refusal of authenticated unsafe requests with no Origin;
- allowed same-origin traffic continuing through to the application/authentication boundary;
- safe GET requests remaining independent of the unsafe-method Origin rule;
- unauthenticated login/bootstrap paths remaining reachable rather than being accidentally blocked by the CSRF control.

The final live regression ran through the actual local proxy/backend stack, not only an isolated class harness.

---

## 6. Recovery, Persistence and Evidence Continuity

The production-hardening programme included a hash-bound database backup and isolated restore examination.

Within the tested PostgreSQL 16 boundary:

- a backup artifact and manifest were hash-bound;
- restore was performed in an isolated PostgreSQL environment;
- the expected public-table set was recovered;
- the original backup identities remained unchanged;
- the live application database was not used as the restore target;
- failed predecessor harness logic was preserved rather than retrospectively rewritten as if it had passed.

This is a recoverability result inside the tested boundary.

It is not presented as universal disaster-recovery certification or proof of every possible row-level recovery scenario.

---

## 7. Runtime Resilience and Production Source Controls

The successor production source layer now contains bounded operational controls including:

- explicit container health/restart posture;
- bounded JSON log retention;
- production HTTPS source configuration;
- HTTP-to-HTTPS redirection with a health exception;
- minimum TLS configuration at the proxy layer;
- HSTS and security headers;
- public-host allowlisting;
- secure-cookie enforcement for production configuration;
- exact production-origin binding;
- production demo-mode disablement;
- fail-closed required production configuration inputs.

Crucially, the programme did **not** manufacture a fake public deployment to make the checklist look complete.

When no real public hostname, DNS authority and real TLS identity were available, the deployment gate correctly remained:

**HOLD — external identity not complete.**

That hold is part of the evidence.

---

## 8. Frozen Source ↔ Live Runtime Alignment

The programme identified that a healthy running backend can still be executing predecessor bytes after source hardening.

Instead of assuming a healthy container meant the new controls were live, Elias compared the running source identity with the frozen source identity.

A mismatch was found.

The response was bounded:

- rebuild only the authorised backend component;
- recreate only that backend container;
- preserve proxy, frontend and database container identities;
- verify the new runtime source matches the frozen source;
- re-establish the restricted runtime database role;
- compare database fingerprints before and after recreation;
- confirm preserved historical receipt count remains unchanged;
- re-run the live security regression through the proxy.

This converted a source-level hardening claim into a verified live-runtime claim.

---

## 9. Evidence Discipline: Failed Harnesses Were Preserved

Several examination stages exposed defects in the **test harness**, not in the governed candidate.

Those failures were not silently repaired and rewritten as successful predecessor runs.

Instead the process preserved:

- the failed harness result;
- the reason it was inadmissible as candidate evidence;
- the unchanged candidate identity;
- the successor harness;
- the successor result.

This matters because an evidence system that edits away its own failed examinations cannot credibly claim glass-box governance.

The working discipline was:

**Freeze → inspect → change one bounded thing → falsify → bind bytes → run live → preserve failure → establish successor.**

---

## 10. External Scrutiny and Cross-Architecture Examination

During the broader Elias programme, selected frozen packages and bounded propositions have been submitted to independent external examination.

Public-safe outcomes from that work include:

- independent hash verification of received frozen packages;
- bounded review of present governing state versus preserved historical authority;
- refusal behaviour where authority state changed;
- preservation of explicit claim ceilings;
- no automatic conversion of inspection into execution authority;
- no automatic claim of production equivalence, architectural equivalence or integration;
- cross-architecture comparison work performed against independently locked mappings;
- successor/new-chain boundaries preserved where required evidence continuity was absent.

The principle remains:

> **Inspection ≠ execution.**
>
> **Simulation ≠ historical evidence.**
>
> **Changed condition ≠ changed record.**
>
> **New proposition = new chain.**

Names, private partner material, proprietary implementation detail and non-public exchange records are intentionally not reproduced in this public release.

---

## 11. External-State Governance and No-Workaround Discipline

Another important programme result is the treatment of blocked external execution conditions.

Where a provider-origin external state established that a requested consequential capability was not available under the current account/contract state, the system did not fabricate success through:

- workaround execution;
- simulation presented as real execution;
- provider substitution presented as equivalent evidence;
- retrospective mutation of the governed attempt.

Instead, provider-origin evidence was preserved and handed into the established examination chain.

This is a practical expression of:

> **Uncertainty is admissible.**
>
> **No authority is not authority.**
>
> **A blocked execution is evidence, not an invitation to invent success.**

---

## 12. Final Local Readiness Determination

The final local readiness gate established, inside the tested boundary:

- frozen source identity preserved;
- worktree clean;
- all four local services healthy;
- live backend source aligned to frozen source;
- restricted runtime database role active;
- proxy/API health established;
- live actual-byte body limit passed;
- foreign Origin refusal passed;
- missing Origin refusal passed;
- allowed Origin pass-through passed;
- unauthenticated login path remained reachable;
- safe GET remained outside the unsafe-method Origin gate;
- five historical receipts remained present;
- direct receipt UPDATE authority absent;
- direct receipt DELETE authority absent;
- direct receipt TRUNCATE authority absent;
- transitive runtime-delete risk into the receipt root not established;
- database fingerprint unchanged across the final regression;
- container identities unchanged during the final readiness gate.

A separate hash-bound local-readiness evidence receipt was then sealed outside the source repository.

The supported determination is:

> **LOCAL PRODUCTION READINESS — ESTABLISHED WITHIN THE TESTED BOUNDARY.**

---

## 13. What Is Still Deliberately Not Claimed

This release does **not** claim:

- public deployment has occurred;
- a public domain or hostname has been established;
- public DNS has been established;
- a real production TLS certificate has been established;
- external post-deployment verification has been completed;
- external certification;
- regulatory approval;
- legal authority;
- universal production readiness across every environment;
- universal empirical proof;
- architectural equivalence with another system;
- integration with another governance architecture;
- performance claims beyond separately frozen and bounded evidence;
- disclosure of proprietary Elias implementation internals.

The external deployment branch remains intentionally held until real external identity exists.

---

## 14. What v1.2.0 Represents

v1.0.0 froze the canonical discipline.

v1.1.0 published the connected public architecture record.

v1.2.0 records the next step:

**a governed AI system whose memory, evidence, authority, recovery, security and runtime state have been examined together as one bounded operational chain.**

The significance is not that every possible problem has been solved.

The significance is that the system is being built so that it can say, with evidence:

**what happened,  
what was used,  
what changed,  
what authority existed,  
what authority did not exist,  
what failed,  
what was preserved,  
and where the evidence stops.**

That is the standard Elias is working toward.

**Lock it. Log it. Prove it.**

---

## Elias Systems Ltd

**Founder & AI Governance Architect:** Gary Williams

**Motto:** *Work is for Robots & Life is for Humans.*

© 2026 Elias Systems Ltd. All rights reserved.

Public visibility does not transfer proprietary implementation, commercial, licensing or integration rights. See the repository licensing record for the governing public-use boundary.
