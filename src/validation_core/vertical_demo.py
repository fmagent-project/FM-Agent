"""Non-admissible Stage 7--11 vertical demonstration.

The demo connects the existing Router/Registry to the constrained exact-ref
planner.  It intentionally stops before a real Broker, current outcome, or
certificate can be produced.  CCC can only be selected for shadow evaluation
with a caller-injected registration.  vLLM and OpenHarmony report explicit
infrastructure inconclusives because this module has no service, GPU, xDevice,
or device capability.

No production entry imports this module.  The default rollout policy selects
``legacy_prompt`` for full, resume, incremental, and all-bugs operation.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum

from .constrained_adapter import (
    ConstrainedExactRefPlanner,
    ConstrainedExecutionPlan,
    ConstrainedPlanRequest,
)
from .contracts.base import canonical_sha256, validate_identifier, validate_sha256
from .contracts.preset import RegistrationRecord, RegistrationTrustTier
from .contracts.routing import (
    GenericAdapterKind,
    RoutingDecision,
    RoutingReasonCode,
    RoutingRequest,
    ValidationEngine,
)
from .presets.ccc.preset import CCC_LEGACY_PRESET
from .registry import PresetRegistry
from .routing import AdapterResolver, ValidationRouter


class DemoEntryMode(str, Enum):
    FULL = "full"
    RESUME = "resume"
    INCREMENTAL = "incremental"
    ALL_BUGS = "all_bugs"


class VerticalDemoStatus(str, Enum):
    """Closed terminal states of the non-admissible demo."""

    LEGACY_ONLY = "LEGACY_ONLY"
    SHADOW_ROUTE_ONLY = "SHADOW_ROUTE_ONLY"
    INCONCLUSIVE_INFRA = "INCONCLUSIVE_INFRA"
    INCONCLUSIVE_ORACLE = "INCONCLUSIVE_ORACLE"


class VerticalDemoReason(str, Enum):
    LEGACY_PROMPT_DEFAULT = "LEGACY_PROMPT_DEFAULT"
    CCC_SHADOW_ROUTE_ONLY_NON_ADMISSIBLE = (
        "CCC_SHADOW_ROUTE_ONLY_NON_ADMISSIBLE"
    )
    VLLM_SERVICE_GPU_BROKER_NOT_CONNECTED = (
        "VLLM_SERVICE_GPU_BROKER_NOT_CONNECTED"
    )
    OPENHARMONY_XDEVICE_DEVICE_BROKER_NOT_CONNECTED = (
        "OPENHARMONY_XDEVICE_DEVICE_BROKER_NOT_CONNECTED"
    )
    NO_REAL_ADAPTER_IMPLEMENTATION = "NO_REAL_ADAPTER_IMPLEMENTATION"


class DemoEvidenceClass(str, Enum):
    NONE = "NONE"
    CCC_SHADOW_ROUTE_ONLY = "CCC_SHADOW_ROUTE_ONLY"
    EXACT_REF_PLAN_ONLY = "EXACT_REF_PLAN_ONLY"


class VerticalDemoErrorCode(str, Enum):
    INVALID_REQUEST = "INVALID_REQUEST"
    CCC_REGISTRATION_REQUIRED = "CCC_REGISTRATION_REQUIRED"
    CCC_REGISTRATION_MISMATCH = "CCC_REGISTRATION_MISMATCH"
    APPROVED_PLAN_REQUIRED = "APPROVED_PLAN_REQUIRED"


class VerticalDemoError(ValueError):
    def __init__(self, code: VerticalDemoErrorCode, message: str) -> None:
        if type(code) is not VerticalDemoErrorCode:
            raise TypeError("code must be a VerticalDemoErrorCode")
        self.code = code
        super().__init__(message)


def _error(code: VerticalDemoErrorCode, message: str) -> None:
    raise VerticalDemoError(code, message)


@dataclass(frozen=True)
class DemoRolloutPolicy:
    """Pure feature-flag matrix; an empty matrix preserves legacy everywhere."""

    generic_shadow_modes: tuple[DemoEntryMode, ...] = ()

    def __post_init__(self) -> None:
        if type(self.generic_shadow_modes) not in (tuple, list):
            _error(
                VerticalDemoErrorCode.INVALID_REQUEST,
                "generic_shadow_modes must be a collection of DemoEntryMode values",
            )
        modes = tuple(self.generic_shadow_modes)
        if any(type(mode) is not DemoEntryMode for mode in modes):
            _error(
                VerticalDemoErrorCode.INVALID_REQUEST,
                "generic_shadow_modes must contain only DemoEntryMode values",
            )
        if len(modes) != len(set(modes)):
            _error(
                VerticalDemoErrorCode.INVALID_REQUEST,
                "generic_shadow_modes must not contain duplicates",
            )
        object.__setattr__(
            self,
            "generic_shadow_modes",
            tuple(sorted(modes, key=lambda mode: mode.value)),
        )

    def engine_for(self, mode: DemoEntryMode) -> ValidationEngine:
        if type(mode) is not DemoEntryMode:
            _error(
                VerticalDemoErrorCode.INVALID_REQUEST,
                "mode must be a DemoEntryMode",
            )
        if mode in self.generic_shadow_modes:
            return ValidationEngine.GENERIC_HARNESS
        return ValidationEngine.LEGACY_PROMPT


def _routing_document(decision: RoutingDecision) -> dict[str, object]:
    preset = decision.preset
    return {
        "engine": decision.engine.value,
        "system_id": decision.system_id,
        "reason_code": decision.reason_code.value,
        "adapter_kind": (
            None if decision.adapter_kind is None else decision.adapter_kind.value
        ),
        "preset": (
            None
            if preset is None
            else {
                "preset_id": preset.preset_id,
                "preset_version": preset.preset_version,
                "content_sha256": preset.content_sha256,
            }
        ),
        "registration_sha256": decision.registration_sha256,
    }


@dataclass(frozen=True)
class VerticalDemoReport:
    """A shadow report structurally unable to claim admission or certification."""

    entry_mode: DemoEntryMode
    route: RoutingDecision
    status: VerticalDemoStatus
    reason: VerticalDemoReason
    evidence_class: DemoEvidenceClass
    simulated: bool
    plan_sha256: str | None = None
    admissible: bool = field(default=False, init=False)
    current_outcome_sha256: None = field(default=None, init=False)
    certificate_sha256: None = field(default=None, init=False)

    def __post_init__(self) -> None:
        if type(self.entry_mode) is not DemoEntryMode:
            raise TypeError("entry_mode must be a DemoEntryMode")
        if type(self.route) is not RoutingDecision:
            raise TypeError("route must be a RoutingDecision")
        if type(self.status) is not VerticalDemoStatus:
            raise TypeError("status must be a VerticalDemoStatus")
        if type(self.reason) is not VerticalDemoReason:
            raise TypeError("reason must be a VerticalDemoReason")
        if type(self.evidence_class) is not DemoEvidenceClass:
            raise TypeError("evidence_class must be a DemoEvidenceClass")
        if type(self.simulated) is not bool:
            raise TypeError("simulated must be a bool")
        if self.plan_sha256 is not None:
            validate_sha256(self.plan_sha256, "plan_sha256")
        if self.admissible is not False:
            raise ValueError("vertical demo reports are never admissible")
        if self.current_outcome_sha256 is not None or self.certificate_sha256 is not None:
            raise ValueError("vertical demo reports cannot bind outcomes or certificates")

        if self.status is VerticalDemoStatus.LEGACY_ONLY:
            if (
                self.route.engine is not ValidationEngine.LEGACY_PROMPT
                or self.reason is not VerticalDemoReason.LEGACY_PROMPT_DEFAULT
                or self.evidence_class is not DemoEvidenceClass.NONE
                or self.simulated
                or self.plan_sha256 is not None
            ):
                raise ValueError("legacy-only demo report has inconsistent fields")
            return

        if self.route.engine is not ValidationEngine.GENERIC_HARNESS:
            raise ValueError("non-legacy demo reports require a generic route")
        if not self.simulated:
            raise ValueError("generic vertical demo reports must be marked simulated")
        if self.status is VerticalDemoStatus.SHADOW_ROUTE_ONLY:
            if (
                self.reason
                is not VerticalDemoReason.CCC_SHADOW_ROUTE_ONLY_NON_ADMISSIBLE
                or self.evidence_class
                is not DemoEvidenceClass.CCC_SHADOW_ROUTE_ONLY
                or self.route.adapter_kind
                is not GenericAdapterKind.TRUSTED_SYSTEM_PRESET
                or self.route.preset != CCC_LEGACY_PRESET.ref
                or self.plan_sha256 is not None
            ):
                raise ValueError("CCC shadow report has inconsistent fields")
            return

        if self.plan_sha256 is None:
            raise ValueError("generic inconclusive reports require an exact-ref plan")
        if self.route.adapter_kind is not GenericAdapterKind.GENERIC_AGENT:
            raise ValueError("generic inconclusive reports require the Generic Agent")
        expected_infra_reason = {
            "vllm": VerticalDemoReason.VLLM_SERVICE_GPU_BROKER_NOT_CONNECTED,
            "openharmony": (
                VerticalDemoReason.OPENHARMONY_XDEVICE_DEVICE_BROKER_NOT_CONNECTED
            ),
        }.get(self.route.system_id)
        if self.status is VerticalDemoStatus.INCONCLUSIVE_INFRA:
            if (
                expected_infra_reason is None
                or self.reason is not expected_infra_reason
                or self.evidence_class is not DemoEvidenceClass.EXACT_REF_PLAN_ONLY
            ):
                raise ValueError(
                    "infrastructure inconclusive report has inconsistent fields"
                )
            return
        if self.status is VerticalDemoStatus.INCONCLUSIVE_ORACLE:
            if (
                expected_infra_reason is not None
                or self.reason
                is not VerticalDemoReason.NO_REAL_ADAPTER_IMPLEMENTATION
                or self.evidence_class is not DemoEvidenceClass.EXACT_REF_PLAN_ONLY
            ):
                raise ValueError("Oracle inconclusive report has inconsistent fields")
            return
        raise ValueError("unsupported vertical demo status matrix")

    def to_document(self) -> dict[str, object]:
        return {
            "contract_kind": "stage_7_11_vertical_demo_report",
            "schema_version": 1,
            "entry_mode": self.entry_mode.value,
            "route": _routing_document(self.route),
            "status": self.status.value,
            "reason": self.reason.value,
            "evidence_class": self.evidence_class.value,
            "simulated": self.simulated,
            "plan_sha256": self.plan_sha256,
            "admissible": False,
            "current_outcome_sha256": None,
            "certificate_sha256": None,
        }

    @property
    def content_sha256(self) -> str:
        return canonical_sha256(self.to_document())


class VerticalDemoHarness:
    """Run one dormant, non-admissible routing/planning demonstration."""

    def __init__(
        self,
        *,
        ccc_registration: RegistrationRecord | None = None,
    ) -> None:
        if ccc_registration is not None and type(ccc_registration) is not RegistrationRecord:
            _error(
                VerticalDemoErrorCode.INVALID_REQUEST,
                "ccc_registration must be a RegistrationRecord or None",
            )
        if ccc_registration is not None and (
            ccc_registration.preset != CCC_LEGACY_PRESET.ref
            or ccc_registration.trust_tier is not RegistrationTrustTier.TRUSTED_PRESET
        ):
            _error(
                VerticalDemoErrorCode.CCC_REGISTRATION_MISMATCH,
                "CCC demo registration must trust the exact staged CCC preset",
            )
        self._ccc_registration = ccc_registration

    @staticmethod
    def _legacy_report(
        system_id: str,
        entry_mode: DemoEntryMode,
    ) -> VerticalDemoReport:
        route = ValidationRouter().route(RoutingRequest(system_id=system_id))
        return VerticalDemoReport(
            entry_mode=entry_mode,
            route=route,
            status=VerticalDemoStatus.LEGACY_ONLY,
            reason=VerticalDemoReason.LEGACY_PROMPT_DEFAULT,
            evidence_class=DemoEvidenceClass.NONE,
            simulated=False,
        )

    def _ccc_shadow_report(self, entry_mode: DemoEntryMode) -> VerticalDemoReport:
        registration = self._ccc_registration
        if registration is None:
            _error(
                VerticalDemoErrorCode.CCC_REGISTRATION_REQUIRED,
                "CCC shadow selection requires a caller-injected registration",
            )
        registry = PresetRegistry((CCC_LEGACY_PRESET,), (registration,))
        router = ValidationRouter(AdapterResolver(registry))
        route = router.route(
            RoutingRequest(
                system_id="ccc",
                requested_engine=ValidationEngine.GENERIC_HARNESS,
                requested_preset=CCC_LEGACY_PRESET.ref,
            )
        )
        return VerticalDemoReport(
            entry_mode=entry_mode,
            route=route,
            status=VerticalDemoStatus.SHADOW_ROUTE_ONLY,
            reason=VerticalDemoReason.CCC_SHADOW_ROUTE_ONLY_NON_ADMISSIBLE,
            evidence_class=DemoEvidenceClass.CCC_SHADOW_ROUTE_ONLY,
            simulated=True,
        )

    @staticmethod
    def _generic_inconclusive_report(
        system_id: str,
        entry_mode: DemoEntryMode,
        planner: ConstrainedExactRefPlanner | None,
        plan_request: ConstrainedPlanRequest | None,
    ) -> VerticalDemoReport:
        if (
            type(planner) is not ConstrainedExactRefPlanner
            or type(plan_request) is not ConstrainedPlanRequest
        ):
            _error(
                VerticalDemoErrorCode.APPROVED_PLAN_REQUIRED,
                "generic shadow demo requires an exact-ref planner and plan request",
            )
        plan: ConstrainedExecutionPlan = planner.plan(plan_request)
        if plan.system_id != system_id:
            _error(
                VerticalDemoErrorCode.INVALID_REQUEST,
                "planned system does not match the demo system",
            )
        route = ValidationRouter().route(
            RoutingRequest(
                system_id=system_id,
                requested_engine=ValidationEngine.GENERIC_HARNESS,
            )
        )
        if system_id == "vllm":
            status = VerticalDemoStatus.INCONCLUSIVE_INFRA
            reason = VerticalDemoReason.VLLM_SERVICE_GPU_BROKER_NOT_CONNECTED
            evidence_class = DemoEvidenceClass.EXACT_REF_PLAN_ONLY
        elif system_id == "openharmony":
            status = VerticalDemoStatus.INCONCLUSIVE_INFRA
            reason = (
                VerticalDemoReason.OPENHARMONY_XDEVICE_DEVICE_BROKER_NOT_CONNECTED
            )
            evidence_class = DemoEvidenceClass.EXACT_REF_PLAN_ONLY
        else:
            status = VerticalDemoStatus.INCONCLUSIVE_ORACLE
            reason = VerticalDemoReason.NO_REAL_ADAPTER_IMPLEMENTATION
            evidence_class = DemoEvidenceClass.EXACT_REF_PLAN_ONLY
        return VerticalDemoReport(
            entry_mode=entry_mode,
            route=route,
            status=status,
            reason=reason,
            evidence_class=evidence_class,
            simulated=True,
            plan_sha256=plan.content_sha256,
        )

    def run(
        self,
        *,
        system_id: str,
        entry_mode: DemoEntryMode,
        rollout: DemoRolloutPolicy = DemoRolloutPolicy(),
        planner: ConstrainedExactRefPlanner | None = None,
        plan_request: ConstrainedPlanRequest | None = None,
    ) -> VerticalDemoReport:
        validate_identifier(system_id, "system_id")
        if type(entry_mode) is not DemoEntryMode:
            _error(
                VerticalDemoErrorCode.INVALID_REQUEST,
                "entry_mode must be a DemoEntryMode",
            )
        if type(rollout) is not DemoRolloutPolicy:
            _error(
                VerticalDemoErrorCode.INVALID_REQUEST,
                "rollout must be a DemoRolloutPolicy",
            )
        engine = rollout.engine_for(entry_mode)
        if engine is ValidationEngine.LEGACY_PROMPT:
            return self._legacy_report(system_id, entry_mode)
        if system_id == "ccc":
            return self._ccc_shadow_report(entry_mode)
        return self._generic_inconclusive_report(
            system_id,
            entry_mode,
            planner,
            plan_request,
        )


__all__ = (
    "DemoEntryMode",
    "DemoEvidenceClass",
    "DemoRolloutPolicy",
    "VerticalDemoError",
    "VerticalDemoErrorCode",
    "VerticalDemoHarness",
    "VerticalDemoReason",
    "VerticalDemoReport",
    "VerticalDemoStatus",
)
