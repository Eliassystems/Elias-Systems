from __future__ import annotations

import hashlib
import hmac
import json
import logging
import threading
import time
import uuid
from dataclasses import asdict, dataclass, field, is_dataclass
from enum import Enum
from types import MappingProxyType
from typing import Any, Dict, Iterable, List, Mapping, Optional, Protocol, Sequence, Tuple


# -----------------------------------------------------------------------------
# Logging
# -----------------------------------------------------------------------------

LOGGER = logging.getLogger("elias.hpm")
if not LOGGER.handlers:
    handler = logging.StreamHandler()
    handler.setFormatter(
        logging.Formatter(
            "%(asctime)s - [ELIAS_HPM] - %(levelname)s - %(message)s"
        )
    )
    LOGGER.addHandler(handler)
LOGGER.setLevel(logging.INFO)
LOGGER.propagate = False


# -----------------------------------------------------------------------------
# Canonical helpers
# -----------------------------------------------------------------------------


def _utc_timestamp() -> float:
    return time.time()


def _new_id(prefix: str) -> str:
    return f"{prefix}_{uuid.uuid4().hex}"


def _to_json_safe(value: Any) -> Any:
    """Convert supported Python objects into deterministic JSON-safe values."""
    if is_dataclass(value):
        return _to_json_safe(asdict(value))
    if isinstance(value, Enum):
        return value.value
    if isinstance(value, Mapping):
        return {
            str(key): _to_json_safe(item)
            for key, item in sorted(value.items(), key=lambda pair: str(pair[0]))
        }
    if isinstance(value, (list, tuple)):
        return [_to_json_safe(item) for item in value]
    if isinstance(value, set):
        return sorted(_to_json_safe(item) for item in value)
    if value is None or isinstance(value, (str, int, float, bool)):
        return value
    raise TypeError(f"Value is not JSON serialisable: {type(value).__name__}")


def _canonical_json(value: Any) -> str:
    return json.dumps(
        _to_json_safe(value),
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    )


def _sha256(value: Any) -> str:
    return hashlib.sha256(_canonical_json(value).encode("utf-8")).hexdigest()


def _normalise_scalar(value: Any) -> str:
    """Canonical comparison form for deterministic contradiction checks."""
    return _canonical_json(value).casefold().strip()


# -----------------------------------------------------------------------------
# Governance vocabulary
# -----------------------------------------------------------------------------


class EpistemicClassification(str, Enum):
    VERIFIED_FACT = "VERIFIED_FACT"
    USER_ASSERTION = "USER_ASSERTION"
    REASONED_INFERENCE = "REASONED_INFERENCE"
    UNVERIFIED_CLAIM = "UNVERIFIED_CLAIM"
    UNCERTAINTY_GAP = "UNCERTAINTY_GAP"


class SystemState(str, Enum):
    ANCHORED_97 = "ANCHORED_97"
    ADAPTIVE_3 = "ADAPTIVE_3"
    FAIL_CLOSED = "FAIL_CLOSED"


class GovernanceDecision(str, Enum):
    ADMIT = "ADMIT"
    QUALIFY = "QUALIFY"
    HOLD = "HOLD"
    REJECT = "REJECT"


class EventType(str, Enum):
    CLAIM_ADMITTED = "CLAIM_ADMITTED"
    CLAIM_QUALIFIED = "CLAIM_QUALIFIED"
    CLAIM_HELD = "CLAIM_HELD"
    CLAIM_REJECTED = "CLAIM_REJECTED"
    CLAIM_SUPERSEDED = "CLAIM_SUPERSEDED"
    SIGNAL_RECEIVED = "SIGNAL_RECEIVED"
    OUTPUT_RELEASED = "OUTPUT_RELEASED"
    OUTPUT_BLOCKED = "OUTPUT_BLOCKED"
    CACHE_PURGED = "CACHE_PURGED"
    ANCHOR_FAILURE = "ANCHOR_FAILURE"


class SourceRole(str, Enum):
    USER = "USER"
    SYSTEM = "SYSTEM"
    TOOL = "TOOL"
    MODEL = "MODEL"
    EXTERNAL = "EXTERNAL"


# -----------------------------------------------------------------------------
# Constitutional anchor: identity before intelligence
# -----------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class EliasConstitution:
    """
    Immutable constitutional anchor for HPM.

    The 97/3 split is an allocation of authority, not a claim that exactly
    97 percent of Python instructions are deterministic. The protected core
    defines what adaptation may never overwrite.
    """

    identity: str = "Elias"
    product: str = "High Precision Mode (HPM)"
    governance_basis: str = "LOVE-OS"
    purpose: str = (
        "Preserve human sovereignty, truth integrity, identity continuity, "
        "and compassionate governance before intelligence or execution."
    )
    operational_rule: str = "Admissibility_Over_Completion"
    immutable_core_ratio: float = 0.97
    adaptive_context_ratio: float = 0.03
    allow_unsupported_assertion: bool = False
    version: str = "2.0.0"
    principles: Tuple[str, ...] = (
        "Identity_Before_Intelligence",
        "Purpose_Governs_Operation",
        "Admissibility_Over_Completion",
        "Uncertainty_Is_A_Valid_State",
        "Fact_Inference_And_Assertion_Must_Remain_Separate",
        "Continuity_Must_Not_Be_Rewritten_By_Volatile_Context",
        "Consequential_Governance_Must_Leave_A_Witness_Receipt",
        "The_Adaptive_3_May_Inform_But_May_Not_Overwrite_The_Anchored_97",
    )

    def __post_init__(self) -> None:
        total = self.immutable_core_ratio + self.adaptive_context_ratio
        if abs(total - 1.0) > 1e-9:
            raise ValueError("The constitutional authority ratios must total 1.0")
        if self.immutable_core_ratio <= self.adaptive_context_ratio:
            raise ValueError("The immutable core must remain the governing authority")

    @property
    def fingerprint(self) -> str:
        return _sha256(asdict(self))


# -----------------------------------------------------------------------------
# Evidence and source integrity
# -----------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class EvidenceReceipt:
    receipt_id: str
    authority_id: str
    source_reference: str
    claim_digest: str
    issued_at: float
    verification_method: str
    signature: str
    metadata: Mapping[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        object.__setattr__(self, "metadata", MappingProxyType(dict(self.metadata)))

    def signing_payload(self) -> Mapping[str, Any]:
        return {
            "receipt_id": self.receipt_id,
            "authority_id": self.authority_id,
            "source_reference": self.source_reference,
            "claim_digest": self.claim_digest,
            "issued_at": self.issued_at,
            "verification_method": self.verification_method,
            "metadata": dict(self.metadata),
        }


class EvidenceVerifier(Protocol):
    def verify(self, receipt: EvidenceReceipt, expected_claim_digest: str) -> bool:
        ...


class HMACEvidenceAuthority:
    """
    Minimal reference authority for signed evidence receipts.

    Production deployments should store authority keys outside the process,
    rotate them, and replace HMAC with an appropriate public-key trust model.
    """

    METHOD = "HMAC-SHA256"

    def __init__(self, authority_id: str, secret: bytes):
        if not authority_id.strip():
            raise ValueError("authority_id is required")
        if len(secret) < 16:
            raise ValueError("secret must contain at least 16 bytes")
        self.authority_id = authority_id
        self._secret = bytes(secret)

    def issue(
        self,
        *,
        claim_digest: str,
        source_reference: str,
        metadata: Optional[Mapping[str, Any]] = None,
    ) -> EvidenceReceipt:
        unsigned = EvidenceReceipt(
            receipt_id=_new_id("evidence"),
            authority_id=self.authority_id,
            source_reference=source_reference,
            claim_digest=claim_digest,
            issued_at=_utc_timestamp(),
            verification_method=self.METHOD,
            signature="",
            metadata=metadata or {},
        )
        signature = hmac.new(
            self._secret,
            _canonical_json(unsigned.signing_payload()).encode("utf-8"),
            hashlib.sha256,
        ).hexdigest()
        return EvidenceReceipt(
            receipt_id=unsigned.receipt_id,
            authority_id=unsigned.authority_id,
            source_reference=unsigned.source_reference,
            claim_digest=unsigned.claim_digest,
            issued_at=unsigned.issued_at,
            verification_method=unsigned.verification_method,
            signature=signature,
            metadata=unsigned.metadata,
        )

    def verifier(self) -> "HMACEvidenceVerifier":
        return HMACEvidenceVerifier({self.authority_id: self._secret})


class HMACEvidenceVerifier:
    def __init__(self, trusted_authorities: Mapping[str, bytes]):
        self._trusted_authorities = {
            authority: bytes(secret)
            for authority, secret in trusted_authorities.items()
        }

    def verify(self, receipt: EvidenceReceipt, expected_claim_digest: str) -> bool:
        if receipt.verification_method != HMACEvidenceAuthority.METHOD:
            return False
        if receipt.claim_digest != expected_claim_digest:
            return False
        secret = self._trusted_authorities.get(receipt.authority_id)
        if secret is None:
            return False
        expected_signature = hmac.new(
            secret,
            _canonical_json(receipt.signing_payload()).encode("utf-8"),
            hashlib.sha256,
        ).hexdigest()
        return hmac.compare_digest(receipt.signature, expected_signature)


# -----------------------------------------------------------------------------
# Claims, signals, and candidate outputs
# -----------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class Claim:
    """
    A structured proposition.

    Contradiction checks are deterministic only when subject, predicate,
    reference frame, and temporal scope are structured consistently.
    """

    subject: str
    predicate: str
    value: Any
    reference_frame: str
    source_role: SourceRole
    claim_id: str = field(default_factory=lambda: _new_id("claim"))
    temporal_scope: str = "CURRENT"
    explicit_user_input: bool = False
    evidence_ids: Tuple[str, ...] = ()
    premise_claim_ids: Tuple[str, ...] = ()
    inference_rule: Optional[str] = None
    confidence: Optional[float] = None
    supersedes_claim_ids: Tuple[str, ...] = ()
    metadata: Mapping[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if not self.subject.strip():
            raise ValueError("claim.subject is required")
        if not self.predicate.strip():
            raise ValueError("claim.predicate is required")
        if not self.reference_frame.strip():
            raise ValueError("claim.reference_frame is required")
        if not self.temporal_scope.strip():
            raise ValueError("claim.temporal_scope is required")
        if self.confidence is not None and not 0.0 <= self.confidence <= 1.0:
            raise ValueError("claim.confidence must be between 0.0 and 1.0")
        _canonical_json(self.value)  # fail early if the value is not serialisable
        object.__setattr__(self, "metadata", MappingProxyType(dict(self.metadata)))

    @property
    def contradiction_key(self) -> Tuple[str, str, str, str]:
        return (
            self.reference_frame.casefold().strip(),
            self.temporal_scope.casefold().strip(),
            self.subject.casefold().strip(),
            self.predicate.casefold().strip(),
        )

    @property
    def digest(self) -> str:
        return _sha256(
            {
                "subject": self.subject,
                "predicate": self.predicate,
                "value": self.value,
                "reference_frame": self.reference_frame,
                "temporal_scope": self.temporal_scope,
            }
        )


@dataclass(frozen=True, slots=True)
class IncomingSignal:
    source: str
    source_role: SourceRole
    claims: Tuple[Claim, ...]
    signal_id: str = field(default_factory=lambda: _new_id("signal"))
    received_at: float = field(default_factory=_utc_timestamp)
    metadata: Mapping[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if not self.source.strip():
            raise ValueError("signal.source is required")
        if not self.claims:
            raise ValueError("signal.claims must contain at least one claim")
        object.__setattr__(self, "metadata", MappingProxyType(dict(self.metadata)))


@dataclass(frozen=True, slots=True)
class AnswerSegment:
    """
    One claim-bound segment of an intended model answer.

    HPM renders the final qualification itself. The model is therefore not
    trusted to correctly label its own assertion as fact, inference, or user
    testimony.
    """

    claim_id: str
    text: str

    def __post_init__(self) -> None:
        if not self.claim_id.strip():
            raise ValueError("answer segment claim_id is required")
        if not self.text.strip():
            raise ValueError("answer segment text is required")


@dataclass(frozen=True, slots=True)
class CandidateAnswer:
    segments: Tuple[AnswerSegment, ...]
    answer_id: str = field(default_factory=lambda: _new_id("answer"))
    generated_at: float = field(default_factory=_utc_timestamp)

    def __post_init__(self) -> None:
        if not self.segments:
            raise ValueError(
                "candidate answers must contain at least one claim-bound segment"
            )

    @property
    def claim_ids(self) -> Tuple[str, ...]:
        return tuple(segment.claim_id for segment in self.segments)

    @property
    def raw_text(self) -> str:
        return " ".join(segment.text.strip() for segment in self.segments)


# -----------------------------------------------------------------------------
# Governance results and witness receipts
# -----------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class ClaimAssessment:
    claim_id: str
    decision: GovernanceDecision
    classification: EpistemicClassification
    reason: str
    conflicting_claim_ids: Tuple[str, ...] = ()
    verified_evidence_ids: Tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class WitnessReceipt:
    witness_id: str
    event_type: EventType
    subject_id: str
    decision: GovernanceDecision
    policy_fingerprint: str
    reason: str
    timestamp: float
    previous_witness_hash: str
    witness_hash: str
    details: Mapping[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        object.__setattr__(self, "details", MappingProxyType(dict(self.details)))


@dataclass(frozen=True, slots=True)
class SignalGovernanceResult:
    signal_id: str
    assessments: Tuple[ClaimAssessment, ...]
    witness_ids: Tuple[str, ...]

    @property
    def fully_admitted(self) -> bool:
        return all(
            assessment.decision in {GovernanceDecision.ADMIT, GovernanceDecision.QUALIFY}
            for assessment in self.assessments
        )


@dataclass(frozen=True, slots=True)
class OutputGovernanceResult:
    answer_id: str
    release_allowed: bool
    released_text: Optional[str]
    assessments: Tuple[ClaimAssessment, ...]
    witness_id: str
    message: str


@dataclass(frozen=True, slots=True)
class StoredClaim:
    claim: Claim
    classification: EpistemicClassification
    decision: GovernanceDecision
    admitted_at: float
    active: bool = True


# -----------------------------------------------------------------------------
# Tamper-evident in-memory continuity ledger
# -----------------------------------------------------------------------------


class ContinuityLedger:
    GENESIS_HASH = "0" * 64

    def __init__(self) -> None:
        self._claims: Dict[str, StoredClaim] = {}
        self._witnesses: List[WitnessReceipt] = []
        self._lock = threading.RLock()

    def get_claim(self, claim_id: str) -> Optional[StoredClaim]:
        with self._lock:
            return self._claims.get(claim_id)

    def active_claims(self) -> Tuple[StoredClaim, ...]:
        with self._lock:
            return tuple(item for item in self._claims.values() if item.active)

    def add_claim(
        self,
        claim: Claim,
        classification: EpistemicClassification,
        decision: GovernanceDecision,
    ) -> None:
        with self._lock:
            if claim.claim_id in self._claims:
                raise ValueError(f"Duplicate claim_id: {claim.claim_id}")
            self._claims[claim.claim_id] = StoredClaim(
                claim=claim,
                classification=classification,
                decision=decision,
                admitted_at=_utc_timestamp(),
                active=True,
            )

    def supersede(self, claim_ids: Iterable[str]) -> Tuple[str, ...]:
        superseded: List[str] = []
        with self._lock:
            for claim_id in claim_ids:
                stored = self._claims.get(claim_id)
                if stored is None or not stored.active:
                    continue
                self._claims[claim_id] = StoredClaim(
                    claim=stored.claim,
                    classification=stored.classification,
                    decision=stored.decision,
                    admitted_at=stored.admitted_at,
                    active=False,
                )
                superseded.append(claim_id)
        return tuple(superseded)

    def find_conflicts(self, incoming: Claim) -> Tuple[StoredClaim, ...]:
        incoming_value = _normalise_scalar(incoming.value)
        conflicts: List[StoredClaim] = []
        with self._lock:
            for stored in self._claims.values():
                if not stored.active:
                    continue
                if stored.claim.contradiction_key != incoming.contradiction_key:
                    continue
                if _normalise_scalar(stored.claim.value) != incoming_value:
                    conflicts.append(stored)
        return tuple(conflicts)

    def append_witness(
        self,
        *,
        event_type: EventType,
        subject_id: str,
        decision: GovernanceDecision,
        policy_fingerprint: str,
        reason: str,
        details: Optional[Mapping[str, Any]] = None,
    ) -> WitnessReceipt:
        with self._lock:
            previous_hash = (
                self._witnesses[-1].witness_hash
                if self._witnesses
                else self.GENESIS_HASH
            )
            timestamp = _utc_timestamp()
            witness_id = _new_id("witness")
            unsigned = {
                "witness_id": witness_id,
                "event_type": event_type.value,
                "subject_id": subject_id,
                "decision": decision.value,
                "policy_fingerprint": policy_fingerprint,
                "reason": reason,
                "timestamp": timestamp,
                "previous_witness_hash": previous_hash,
                "details": dict(details or {}),
            }
            witness_hash = _sha256(unsigned)
            receipt = WitnessReceipt(
                witness_id=witness_id,
                event_type=event_type,
                subject_id=subject_id,
                decision=decision,
                policy_fingerprint=policy_fingerprint,
                reason=reason,
                timestamp=timestamp,
                previous_witness_hash=previous_hash,
                witness_hash=witness_hash,
                details=details or {},
            )
            self._witnesses.append(receipt)
            return receipt

    def witnesses(self) -> Tuple[WitnessReceipt, ...]:
        with self._lock:
            return tuple(self._witnesses)

    def verify_witness_chain(self) -> bool:
        with self._lock:
            previous_hash = self.GENESIS_HASH
            for receipt in self._witnesses:
                if receipt.previous_witness_hash != previous_hash:
                    return False
                unsigned = {
                    "witness_id": receipt.witness_id,
                    "event_type": receipt.event_type.value,
                    "subject_id": receipt.subject_id,
                    "decision": receipt.decision.value,
                    "policy_fingerprint": receipt.policy_fingerprint,
                    "reason": receipt.reason,
                    "timestamp": receipt.timestamp,
                    "previous_witness_hash": receipt.previous_witness_hash,
                    "details": dict(receipt.details),
                }
                if _sha256(unsigned) != receipt.witness_hash:
                    return False
                previous_hash = receipt.witness_hash
            return True


# -----------------------------------------------------------------------------
# HPM engine
# -----------------------------------------------------------------------------


class HPMEngine:
    """
    Elias High Precision Mode reasoning-governance runtime.

    Guarantees provided by this reference implementation:
    - fail-closed constitutional integrity checks;
    - structured epistemic classification;
    - signed evidence validation;
    - deterministic contradiction checks for structured claims;
    - uncertainty preservation instead of unsupported completion;
    - output release control;
    - tamper-evident witness continuity.

    It does not claim that a probabilistic language model can never make an
    error. It prevents claims that fail HPM governance from being released as
    admitted truth.
    """

    CLASSIFICATION_RANK: Mapping[EpistemicClassification, int] = MappingProxyType(
        {
            EpistemicClassification.UNCERTAINTY_GAP: 0,
            EpistemicClassification.UNVERIFIED_CLAIM: 1,
            EpistemicClassification.USER_ASSERTION: 2,
            EpistemicClassification.REASONED_INFERENCE: 3,
            EpistemicClassification.VERIFIED_FACT: 4,
        }
    )

    def __init__(
        self,
        *,
        system_id: str,
        evidence_verifier: EvidenceVerifier,
        constitution: Optional[EliasConstitution] = None,
        cache_ttl_seconds: int = 600,
        minimum_inference_confidence: float = 0.65,
    ) -> None:
        if not system_id.strip():
            raise ValueError("system_id is required")
        if cache_ttl_seconds <= 0:
            raise ValueError("cache_ttl_seconds must be greater than zero")
        if not 0.0 <= minimum_inference_confidence <= 1.0:
            raise ValueError("minimum_inference_confidence must be between 0 and 1")

        self.system_id = system_id
        self._constitution = constitution or EliasConstitution()
        self._constitution_fingerprint = self._constitution.fingerprint
        self._evidence_verifier = evidence_verifier
        self._cache_ttl_seconds = cache_ttl_seconds
        self._minimum_inference_confidence = minimum_inference_confidence

        self._state = SystemState.ANCHORED_97
        self._sandbox: Dict[str, Mapping[str, Any]] = {}
        self._last_cache_purge_timestamp = _utc_timestamp()
        self._evidence: Dict[str, EvidenceReceipt] = {}
        self._ledger = ContinuityLedger()
        self._lock = threading.RLock()

    @property
    def constitution(self) -> EliasConstitution:
        return self._constitution

    @property
    def state(self) -> SystemState:
        return self._state

    @property
    def ledger(self) -> ContinuityLedger:
        return self._ledger

    def register_evidence(self, receipt: EvidenceReceipt) -> None:
        with self._lock:
            self._assert_anchor_integrity()
            if receipt.receipt_id in self._evidence:
                raise ValueError(f"Duplicate evidence receipt: {receipt.receipt_id}")
            self._evidence[receipt.receipt_id] = receipt

    def enforce_97_baseline_sync(self, *, force: bool = False) -> None:
        with self._lock:
            self._assert_anchor_integrity()
            current_time = _utc_timestamp()
            expired = (
                current_time - self._last_cache_purge_timestamp
                >= self._cache_ttl_seconds
            )
            if not (force or expired):
                return

            purged_count = len(self._sandbox)
            self._sandbox.clear()
            self._state = SystemState.ANCHORED_97
            self._last_cache_purge_timestamp = current_time
            self._ledger.append_witness(
                event_type=EventType.CACHE_PURGED,
                subject_id=self.system_id,
                decision=GovernanceDecision.ADMIT,
                policy_fingerprint=self._constitution_fingerprint,
                reason="Adaptive cache purged; anchored baseline restored.",
                details={"purged_item_count": purged_count, "forced": force},
            )
            LOGGER.info(
                "97%% baseline synchronisation completed; %s sandbox items purged.",
                purged_count,
            )

    def process_incoming_signal(self, signal: IncomingSignal) -> SignalGovernanceResult:
        with self._lock:
            self._assert_anchor_integrity()
            self.enforce_97_baseline_sync()
            self._state = SystemState.ADAPTIVE_3
            self._sandbox[signal.signal_id] = MappingProxyType(
                {
                    "received_at": signal.received_at,
                    "source": signal.source,
                    "source_role": signal.source_role.value,
                    "claim_ids": tuple(claim.claim_id for claim in signal.claims),
                    "metadata": dict(signal.metadata),
                }
            )

            signal_witness = self._ledger.append_witness(
                event_type=EventType.SIGNAL_RECEIVED,
                subject_id=signal.signal_id,
                decision=GovernanceDecision.ADMIT,
                policy_fingerprint=self._constitution_fingerprint,
                reason="Signal isolated inside the adaptive 3% boundary.",
                details={"source": signal.source, "claim_count": len(signal.claims)},
            )

            assessments: List[ClaimAssessment] = []
            witnesses: List[str] = [signal_witness.witness_id]

            try:
                for claim in signal.claims:
                    assessment = self._assess_claim(claim, expected_source_role=signal.source_role)
                    assessments.append(assessment)
                    witness = self._commit_assessment(claim, assessment)
                    witnesses.append(witness.witness_id)
            finally:
                self._sandbox.pop(signal.signal_id, None)
                if self._state != SystemState.FAIL_CLOSED:
                    self._state = SystemState.ANCHORED_97

            return SignalGovernanceResult(
                signal_id=signal.signal_id,
                assessments=tuple(assessments),
                witness_ids=tuple(witnesses),
            )

    def govern_candidate_answer(self, candidate: CandidateAnswer) -> OutputGovernanceResult:
        """
        Govern the model's intended output, not only its incoming context.

        Every segment must be bound to an active governed claim. HPM performs
        the epistemic labelling itself so the model cannot silently present a
        user assertion or inference as verified fact.
        """
        with self._lock:
            self._assert_anchor_integrity()
            assessments: List[ClaimAssessment] = []
            blocking_reasons: List[str] = []
            rendered_segments: List[str] = []

            for segment in candidate.segments:
                claim_id = segment.claim_id
                stored = self._ledger.get_claim(claim_id)
                if stored is None or not stored.active:
                    assessment = ClaimAssessment(
                        claim_id=claim_id,
                        decision=GovernanceDecision.REJECT,
                        classification=EpistemicClassification.UNCERTAINTY_GAP,
                        reason="Candidate answer references an unknown or inactive claim.",
                    )
                    assessments.append(assessment)
                    blocking_reasons.append(f"{claim_id}: unknown or inactive claim")
                    continue

                if stored.classification == EpistemicClassification.VERIFIED_FACT:
                    assessment = ClaimAssessment(
                        claim_id=claim_id,
                        decision=GovernanceDecision.ADMIT,
                        classification=stored.classification,
                        reason="Verified fact is admissible for direct assertion.",
                    )
                    rendered_segments.append(segment.text.strip())
                elif stored.classification == EpistemicClassification.REASONED_INFERENCE:
                    assessment = ClaimAssessment(
                        claim_id=claim_id,
                        decision=GovernanceDecision.QUALIFY,
                        classification=stored.classification,
                        reason="Inference released with an HPM-controlled qualification.",
                    )
                    rendered_segments.append(
                        f"[REASONED_INFERENCE] {segment.text.strip()}"
                    )
                elif stored.classification == EpistemicClassification.USER_ASSERTION:
                    assessment = ClaimAssessment(
                        claim_id=claim_id,
                        decision=GovernanceDecision.QUALIFY,
                        classification=stored.classification,
                        reason="User input released only as an attributed assertion.",
                    )
                    rendered_segments.append(
                        f"[USER_ASSERTION] {segment.text.strip()}"
                    )
                else:
                    assessment = ClaimAssessment(
                        claim_id=claim_id,
                        decision=GovernanceDecision.REJECT,
                        classification=stored.classification,
                        reason="Unsupported claim is inadmissible for output release.",
                    )
                    blocking_reasons.append(f"{claim_id}: unsupported claim")

                assessments.append(assessment)

            release_allowed = not blocking_reasons
            if release_allowed:
                event_type = EventType.OUTPUT_RELEASED
                decision = GovernanceDecision.ADMIT
                released_text: Optional[str] = " ".join(rendered_segments)
                message = (
                    "Output released under HPM with system-controlled epistemic labels."
                )
            else:
                event_type = EventType.OUTPUT_BLOCKED
                decision = GovernanceDecision.REJECT
                released_text = None
                message = self.reverse_hallucination_response(
                    "Candidate output contains claims that did not satisfy admissibility: "
                    + "; ".join(blocking_reasons)
                )

            witness = self._ledger.append_witness(
                event_type=event_type,
                subject_id=candidate.answer_id,
                decision=decision,
                policy_fingerprint=self._constitution_fingerprint,
                reason=message,
                details={
                    "claim_ids": candidate.claim_ids,
                    "release_allowed": release_allowed,
                    "raw_text_digest": _sha256(candidate.raw_text),
                    "released_text_digest": (
                        _sha256(released_text) if released_text is not None else None
                    ),
                },
            )
            return OutputGovernanceResult(
                answer_id=candidate.answer_id,
                release_allowed=release_allowed,
                released_text=released_text,
                assessments=tuple(assessments),
                witness_id=witness.witness_id,
                message=message,
            )

    @staticmethod
    def reverse_hallucination_response(reason: str) -> str:
        return (
            "[HPM_RESTRICTION] Admissibility validation failed: "
            f"{reason} Data gap preserved. The system refuses unsupported "
            "completion in order to maintain truth integrity."
        )

    def _assert_anchor_integrity(self) -> None:
        actual = self._constitution.fingerprint
        if actual == self._constitution_fingerprint:
            return

        self._state = SystemState.FAIL_CLOSED
        self._ledger.append_witness(
            event_type=EventType.ANCHOR_FAILURE,
            subject_id=self.system_id,
            decision=GovernanceDecision.REJECT,
            policy_fingerprint=self._constitution_fingerprint,
            reason="Constitutional anchor fingerprint mismatch. Runtime failed closed.",
            details={"expected": self._constitution_fingerprint, "actual": actual},
        )
        raise RuntimeError("HPM constitutional anchor integrity failure")

    def _assess_claim(
        self,
        claim: Claim,
        *,
        expected_source_role: SourceRole,
    ) -> ClaimAssessment:
        if claim.source_role != expected_source_role:
            return ClaimAssessment(
                claim_id=claim.claim_id,
                decision=GovernanceDecision.REJECT,
                classification=EpistemicClassification.UNCERTAINTY_GAP,
                reason="Claim source role does not match the containing signal.",
            )

        classification, verified_evidence = self._classify_claim(claim)
        conflicts = self._ledger.find_conflicts(claim)

        if conflicts:
            return self._resolve_conflicts(
                claim=claim,
                classification=classification,
                conflicts=conflicts,
                verified_evidence=verified_evidence,
            )

        if classification == EpistemicClassification.VERIFIED_FACT:
            return ClaimAssessment(
                claim_id=claim.claim_id,
                decision=GovernanceDecision.ADMIT,
                classification=classification,
                reason="Claim is supported by valid evidence from a trusted authority.",
                verified_evidence_ids=verified_evidence,
            )

        if classification == EpistemicClassification.USER_ASSERTION:
            return ClaimAssessment(
                claim_id=claim.claim_id,
                decision=GovernanceDecision.QUALIFY,
                classification=classification,
                reason=(
                    "Explicit user input preserved as an attributed assertion; "
                    "it is not promoted to verified fact."
                ),
            )

        if classification == EpistemicClassification.REASONED_INFERENCE:
            return ClaimAssessment(
                claim_id=claim.claim_id,
                decision=GovernanceDecision.QUALIFY,
                classification=classification,
                reason=(
                    "Inference is supported by active premises and meets the minimum "
                    "confidence threshold; it must remain labelled as inference."
                ),
            )

        return ClaimAssessment(
            claim_id=claim.claim_id,
            decision=GovernanceDecision.HOLD,
            classification=EpistemicClassification.UNCERTAINTY_GAP,
            reason=(
                "Insufficient shared evidence. Completion is inadmissible and the "
                "uncertainty gap must remain open."
            ),
        )

    def _classify_claim(
        self,
        claim: Claim,
    ) -> Tuple[EpistemicClassification, Tuple[str, ...]]:
        verified_evidence: List[str] = []
        for evidence_id in claim.evidence_ids:
            receipt = self._evidence.get(evidence_id)
            if receipt is None:
                continue
            if self._evidence_verifier.verify(receipt, claim.digest):
                verified_evidence.append(evidence_id)

        if claim.evidence_ids and len(verified_evidence) == len(claim.evidence_ids):
            return EpistemicClassification.VERIFIED_FACT, tuple(verified_evidence)

        if (
            claim.source_role == SourceRole.USER
            and claim.explicit_user_input
            and not claim.evidence_ids
        ):
            return EpistemicClassification.USER_ASSERTION, ()

        if self._valid_inference(claim):
            return EpistemicClassification.REASONED_INFERENCE, ()

        return EpistemicClassification.UNVERIFIED_CLAIM, ()

    def _valid_inference(self, claim: Claim) -> bool:
        if not claim.premise_claim_ids:
            return False
        if not claim.inference_rule or not claim.inference_rule.strip():
            return False
        if claim.confidence is None:
            return False
        if claim.confidence < self._minimum_inference_confidence:
            return False

        for premise_id in claim.premise_claim_ids:
            premise = self._ledger.get_claim(premise_id)
            if premise is None or not premise.active:
                return False
            if premise.classification not in {
                EpistemicClassification.VERIFIED_FACT,
                EpistemicClassification.REASONED_INFERENCE,
            }:
                return False
        return True

    def _resolve_conflicts(
        self,
        *,
        claim: Claim,
        classification: EpistemicClassification,
        conflicts: Sequence[StoredClaim],
        verified_evidence: Tuple[str, ...],
    ) -> ClaimAssessment:
        conflict_ids = tuple(stored.claim.claim_id for stored in conflicts)
        incoming_rank = self.CLASSIFICATION_RANK[classification]
        strongest_existing_rank = max(
            self.CLASSIFICATION_RANK[stored.classification] for stored in conflicts
        )

        explicitly_supersedes_all = set(conflict_ids).issubset(
            set(claim.supersedes_claim_ids)
        )

        if incoming_rank > strongest_existing_rank and explicitly_supersedes_all:
            return ClaimAssessment(
                claim_id=claim.claim_id,
                decision=GovernanceDecision.ADMIT,
                classification=classification,
                reason=(
                    "Higher-integrity claim explicitly supersedes lower-integrity "
                    "continuity records."
                ),
                conflicting_claim_ids=conflict_ids,
                verified_evidence_ids=verified_evidence,
            )

        if incoming_rank < strongest_existing_rank:
            return ClaimAssessment(
                claim_id=claim.claim_id,
                decision=GovernanceDecision.REJECT,
                classification=classification,
                reason=(
                    "Incoming claim conflicts with a stronger active continuity record."
                ),
                conflicting_claim_ids=conflict_ids,
                verified_evidence_ids=verified_evidence,
            )

        return ClaimAssessment(
            claim_id=claim.claim_id,
            decision=GovernanceDecision.HOLD,
            classification=EpistemicClassification.UNCERTAINTY_GAP,
            reason=(
                "Unresolved contradiction detected. The system preserves both the "
                "conflict and the uncertainty instead of selecting a convenient answer."
            ),
            conflicting_claim_ids=conflict_ids,
            verified_evidence_ids=verified_evidence,
        )

    def _commit_assessment(
        self,
        claim: Claim,
        assessment: ClaimAssessment,
    ) -> WitnessReceipt:
        if assessment.decision in {
            GovernanceDecision.ADMIT,
            GovernanceDecision.QUALIFY,
        }:
            superseded = self._ledger.supersede(claim.supersedes_claim_ids)
            self._ledger.add_claim(
                claim=claim,
                classification=assessment.classification,
                decision=assessment.decision,
            )
            if superseded:
                self._ledger.append_witness(
                    event_type=EventType.CLAIM_SUPERSEDED,
                    subject_id=claim.claim_id,
                    decision=GovernanceDecision.ADMIT,
                    policy_fingerprint=self._constitution_fingerprint,
                    reason="Earlier continuity records were explicitly superseded.",
                    details={"superseded_claim_ids": superseded},
                )

        event_type = {
            GovernanceDecision.ADMIT: EventType.CLAIM_ADMITTED,
            GovernanceDecision.QUALIFY: EventType.CLAIM_QUALIFIED,
            GovernanceDecision.HOLD: EventType.CLAIM_HELD,
            GovernanceDecision.REJECT: EventType.CLAIM_REJECTED,
        }[assessment.decision]

        witness = self._ledger.append_witness(
            event_type=event_type,
            subject_id=claim.claim_id,
            decision=assessment.decision,
            policy_fingerprint=self._constitution_fingerprint,
            reason=assessment.reason,
            details={
                "classification": assessment.classification.value,
                "conflicting_claim_ids": assessment.conflicting_claim_ids,
                "verified_evidence_ids": assessment.verified_evidence_ids,
                "claim_digest": claim.digest,
            },
        )

        log_method = (
            LOGGER.info
            if assessment.decision in {GovernanceDecision.ADMIT, GovernanceDecision.QUALIFY}
            else LOGGER.warning
        )
        log_method(
            "Claim %s -> %s / %s: %s",
            claim.claim_id,
            assessment.decision.value,
            assessment.classification.value,
            assessment.reason,
        )
        return witness


# -----------------------------------------------------------------------------
# Executable self-test / usage example
# -----------------------------------------------------------------------------


def _demo() -> None:
    authority = HMACEvidenceAuthority(
        authority_id="elias-local-evidence-authority",
        secret=b"replace-this-with-a-secure-secret",
    )
    engine = HPMEngine(
        system_id="demo-runtime",
        evidence_verifier=authority.verifier(),
        cache_ttl_seconds=600,
    )

    # 1) Preserve a user's statement as an assertion, not as verified reality.
    user_claim = Claim(
        subject="project.alpha",
        predicate="launch_status",
        value="ready",
        reference_frame="Project Alpha launch review",
        temporal_scope="2026-08-03",
        source_role=SourceRole.USER,
        explicit_user_input=True,
    )
    user_result = engine.process_incoming_signal(
        IncomingSignal(
            source="gary",
            source_role=SourceRole.USER,
            claims=(user_claim,),
        )
    )
    assert user_result.assessments[0].classification == EpistemicClassification.USER_ASSERTION

    # 2) Admit a verified fact that explicitly corrects the earlier assertion.
    verified_claim = Claim(
        subject="project.alpha",
        predicate="launch_status",
        value="blocked_pending_security_review",
        reference_frame="Project Alpha launch review",
        temporal_scope="2026-08-03",
        source_role=SourceRole.TOOL,
        supersedes_claim_ids=(user_claim.claim_id,),
    )
    receipt = authority.issue(
        claim_digest=verified_claim.digest,
        source_reference="security-review-report-104",
        metadata={"review_status": "signed"},
    )
    engine.register_evidence(receipt)
    verified_claim = Claim(
        subject=verified_claim.subject,
        predicate=verified_claim.predicate,
        value=verified_claim.value,
        reference_frame=verified_claim.reference_frame,
        temporal_scope=verified_claim.temporal_scope,
        source_role=verified_claim.source_role,
        claim_id=verified_claim.claim_id,
        evidence_ids=(receipt.receipt_id,),
        supersedes_claim_ids=verified_claim.supersedes_claim_ids,
    )
    verified_result = engine.process_incoming_signal(
        IncomingSignal(
            source="security-review-tool",
            source_role=SourceRole.TOOL,
            claims=(verified_claim,),
        )
    )
    assert verified_result.assessments[0].decision == GovernanceDecision.ADMIT

    # 3) Block an unsupported model-generated claim.
    invented_claim = Claim(
        subject="project.alpha",
        predicate="investor_commitment",
        value="GBP 5,000,000 confirmed",
        reference_frame="Project Alpha financing",
        temporal_scope="CURRENT",
        source_role=SourceRole.MODEL,
    )
    invented_result = engine.process_incoming_signal(
        IncomingSignal(
            source="language-model",
            source_role=SourceRole.MODEL,
            claims=(invented_claim,),
        )
    )
    assert invented_result.assessments[0].decision == GovernanceDecision.HOLD

    candidate = CandidateAnswer(
        segments=(
            AnswerSegment(
                claim_id=invented_claim.claim_id,
                text="A GBP 5,000,000 investment has been confirmed.",
            ),
        )
    )
    output_result = engine.govern_candidate_answer(candidate)
    assert output_result.release_allowed is False
    assert output_result.released_text is None
    assert engine.ledger.verify_witness_chain()

    LOGGER.info("HPM self-test completed successfully.")


if __name__ == "__main__":
    _demo()
