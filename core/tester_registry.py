"""v3 tester registry + ``@register_tester`` metadata.

Compatibility note: the decorator accepts BOTH signatures so the 19 existing
testers can continue to call ``@register_tester(RiskCategory.X)`` unchanged.
A ``DEFAULT_METADATA`` table supplies sensible per-category requirements
(``required_capabilities``, ``applicable_transports``, ``requires_clean_state``,
``multi_turn``, ``seed_payload_module``) so the v3 runner can do capability
filtering, transport gating, and clean-state sequencing without editing
every tester.

Testers may still pass explicit kwargs to override the defaults.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Callable, Type

from models.agent_profile import AgentCapability, Transport
from models.enums import RiskCategory


@dataclass(frozen=True)
class TesterMetadata:
    """Static metadata about a tester class. Used by the v3 runner to decide
    whether to invoke a tester for a given profile."""

    category: RiskCategory
    required_capabilities: frozenset[AgentCapability] = frozenset()
    applicable_transports: frozenset[Transport] = frozenset({Transport.REST})
    requires_clean_state: bool = False
    multi_turn: bool = False
    seed_payload_module: str | None = None


@dataclass
class TesterEntry:
    cls: Type[Any]                                # BaseASITester subclass — typed Any to avoid import cycle
    metadata: TesterMetadata


# ---------------------------------------------------------------------------
# Per-category defaults
# ---------------------------------------------------------------------------

# Each entry: (required_capabilities, applicable_transports, requires_clean_state, multi_turn, seed_module)
_ALL_TRANSPORTS = frozenset({Transport.REST, Transport.GRAPHQL, Transport.MCP, Transport.WEBSOCKET})
_REST_ONLY = frozenset({Transport.REST})

DEFAULT_METADATA: dict[RiskCategory, dict[str, Any]] = {
    # ── ASI01–10 ────────────────────────────────────────────────────────
    RiskCategory.ASI01: dict(  # Agent Goal Hijack
        required_capabilities=frozenset(),  # universal
        applicable_transports=_ALL_TRANSPORTS,
        seed_payload_module="payloads.injection_payloads",
    ),
    RiskCategory.ASI02: dict(  # Tool Misuse / SQL Injection
        required_capabilities=frozenset({AgentCapability.SQL_QUERY, AgentCapability.TOOL_INVOKE}),
        applicable_transports=_ALL_TRANSPORTS,
        seed_payload_module="payloads.sql_payloads",
    ),
    RiskCategory.ASI03: dict(  # Identity & Privilege Abuse
        required_capabilities=frozenset(),
        applicable_transports=_ALL_TRANSPORTS,
    ),
    RiskCategory.ASI04: dict(  # Supply Chain
        required_capabilities=frozenset(),
        applicable_transports=_ALL_TRANSPORTS,
    ),
    RiskCategory.ASI05: dict(  # Code Execution
        required_capabilities=frozenset({AgentCapability.CODE_EXECUTION, AgentCapability.SHELL_EXEC}),
        applicable_transports=_ALL_TRANSPORTS,
    ),
    RiskCategory.ASI06: dict(  # Memory & Context Poisoning
        required_capabilities=frozenset({AgentCapability.MEMORY_PERSIST}),
        applicable_transports=_ALL_TRANSPORTS,
        requires_clean_state=True,        # mutates agent memory
        multi_turn=True,
    ),
    RiskCategory.ASI07: dict(  # Insecure Inter-Agent Communication
        required_capabilities=frozenset({AgentCapability.SUBAGENT_DISPATCH}),
        applicable_transports=_ALL_TRANSPORTS,
    ),
    RiskCategory.ASI08: dict(  # Cascading Failures
        required_capabilities=frozenset(),
        applicable_transports=_ALL_TRANSPORTS,
        requires_clean_state=True,        # may DoS the agent
    ),
    RiskCategory.ASI09: dict(  # Trust Exploitation
        required_capabilities=frozenset(),
        applicable_transports=_ALL_TRANSPORTS,
    ),
    RiskCategory.ASI10: dict(  # Rogue Agents
        required_capabilities=frozenset({AgentCapability.SUBAGENT_DISPATCH}),
        applicable_transports=_ALL_TRANSPORTS,
    ),
    # ── EXT01–EXT17 ────────────────────────────────────────────────────
    RiskCategory.EXT01: dict(  # Indirect Log Injection
        applicable_transports=_ALL_TRANSPORTS,
    ),
    RiskCategory.EXT02: dict(  # LTL Invariant Chain
        applicable_transports=_ALL_TRANSPORTS,
        multi_turn=True,
    ),
    RiskCategory.EXT03: dict(  # Gossip Consensus Spoofer
        required_capabilities=frozenset({AgentCapability.SUBAGENT_DISPATCH}),
        applicable_transports=_ALL_TRANSPORTS,
    ),
    RiskCategory.EXT04: dict(  # Active Inference Entropy Boundary
        applicable_transports=_ALL_TRANSPORTS,
    ),
    RiskCategory.EXT05: dict(  # Metamorphic Consistency
        applicable_transports=_ALL_TRANSPORTS,
    ),
    RiskCategory.EXT06: dict(  # Z3 Constraint Prober
        required_capabilities=frozenset({AgentCapability.SQL_QUERY}),
        applicable_transports=_ALL_TRANSPORTS,
    ),
    RiskCategory.EXT07: dict(  # Goal Drift Injector
        applicable_transports=_ALL_TRANSPORTS,
        multi_turn=True,
        requires_clean_state=True,
    ),
    RiskCategory.EXT08: dict(  # Sandbox Isolation
        required_capabilities=frozenset({AgentCapability.CODE_EXECUTION, AgentCapability.SHELL_EXEC}),
        applicable_transports=_ALL_TRANSPORTS,
    ),
    RiskCategory.EXT09: dict(  # FOL Axiom Enforcer
        applicable_transports=_ALL_TRANSPORTS,
    ),
    RiskCategory.EXT10: dict(  # XPIA — Indirect Prompt Injection
        applicable_transports=_ALL_TRANSPORTS,
        seed_payload_module="payloads.xpia_payloads",
    ),
    RiskCategory.EXT11: dict(  # MCP Tool Poisoning
        applicable_transports=frozenset({Transport.MCP, Transport.REST}),
    ),
    RiskCategory.EXT12: dict(  # Alignment Checker
        applicable_transports=_ALL_TRANSPORTS,
        multi_turn=True,
    ),
    RiskCategory.EXT13: dict(  # Model Extraction
        applicable_transports=_ALL_TRANSPORTS,
        seed_payload_module="payloads.poisoning_payloads",
    ),
    RiskCategory.EXT14: dict(  # Data Poisoning via Training Endpoint
        required_capabilities=frozenset({AgentCapability.MEMORY_PERSIST}),
        applicable_transports=_ALL_TRANSPORTS,
        requires_clean_state=True,
    ),
    RiskCategory.EXT15: dict(  # Attribute Inference
        required_capabilities=frozenset({AgentCapability.SQL_QUERY}),
        applicable_transports=_ALL_TRANSPORTS,
    ),
    RiskCategory.EXT16: dict(  # Cache Poisoning
        applicable_transports=_ALL_TRANSPORTS,
        requires_clean_state=True,
    ),
    RiskCategory.EXT17: dict(  # Delivery Hijack
        required_capabilities=frozenset({AgentCapability.EMAIL_SEND}),
        applicable_transports=_ALL_TRANSPORTS,
    ),
}


# ---------------------------------------------------------------------------
# Registry
# ---------------------------------------------------------------------------

_REGISTRY: dict[RiskCategory, TesterEntry] = {}


def register_tester(
    category: RiskCategory | None = None,
    *,
    required_capabilities: frozenset[AgentCapability] | set[AgentCapability] | None = None,
    applicable_transports: frozenset[Transport] | set[Transport] | None = None,
    requires_clean_state: bool | None = None,
    multi_turn: bool | None = None,
    seed_payload_module: str | None = None,
) -> Callable[[Type[Any]], Type[Any]]:
    """Decorator: register an ASI tester class with v3 metadata.

    Two compatible forms:

      @register_tester(RiskCategory.ASI02)                       # legacy
      @register_tester(category=RiskCategory.ASI02, ...)         # explicit

    Missing fields fall back to ``DEFAULT_METADATA[category]``.
    """

    def decorator(cls: Type[Any]) -> Type[Any]:
        # Resolve category — legacy positional first.
        cat = category
        if cat is None:
            cat = getattr(cls, "CATEGORY", None)
        if cat is None:
            raise ValueError(
                f"{cls.__name__}: @register_tester requires a category (positional or class CATEGORY attr)"
            )

        defaults = DEFAULT_METADATA.get(cat, {})

        meta = TesterMetadata(
            category=cat,
            required_capabilities=frozenset(
                required_capabilities
                if required_capabilities is not None
                else defaults.get("required_capabilities", frozenset())
            ),
            applicable_transports=frozenset(
                applicable_transports
                if applicable_transports is not None
                else defaults.get("applicable_transports", _REST_ONLY)
            ),
            requires_clean_state=(
                requires_clean_state
                if requires_clean_state is not None
                else defaults.get("requires_clean_state", False)
            ),
            multi_turn=(
                multi_turn
                if multi_turn is not None
                else defaults.get("multi_turn", False)
            ),
            seed_payload_module=(
                seed_payload_module
                if seed_payload_module is not None
                else defaults.get("seed_payload_module")
            ),
        )
        _REGISTRY[cat] = TesterEntry(cls=cls, metadata=meta)
        return cls

    return decorator


def get_registry() -> dict[RiskCategory, TesterEntry]:
    """Return a copy of the populated registry."""
    return dict(_REGISTRY)


def get_metadata(category: RiskCategory) -> TesterMetadata | None:
    entry = _REGISTRY.get(category)
    return entry.metadata if entry else None


def clear_registry() -> None:
    """Test-only — wipe the registry between unit tests."""
    _REGISTRY.clear()
