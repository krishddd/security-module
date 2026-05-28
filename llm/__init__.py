"""LLM-driven planning, payload synthesis, and finding triage.

All modules in this package are *optional* — the v3 pipeline works without
``ANTHROPIC_API_KEY`` set; only the ``--llm`` CLI path needs them.

Modules:
  client.py             — thin Claude wrapper with prompt-cache contract
  budget.py             — token + USD spend governance
  planner.py            — TestPlanner: AgentProfile -> TestPlan
  payload_synthesizer.py — quality-gated payload mutation
  triage.py             — batched, threshold-gated finding triage
"""

__all__: list[str] = []
