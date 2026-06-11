"""HTML dashboard reporter using Jinja2 templates."""

import logging
from pathlib import Path
from jinja2 import Environment, select_autoescape
from models.enums import Severity, TestStatus
from models.test_result import SecurityReport

# Autoescape ON: probe responses can contain raw HTML (SPA fallback bodies,
# error pages from the target). Without autoescape, those tags are parsed
# by the browser and the cell renders as a blank.
_JINJA_ENV = Environment(autoescape=select_autoescape(default=True))

logger = logging.getLogger(__name__)

HTML_TEMPLATE = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>OWASP ASI Security Report - {{ report.agent_name }}</title>
<style>
:root { --bg: #0f172a; --card: #1e293b; --text: #e2e8f0; --muted: #94a3b8; --border: #334155;
  --critical: #ef4444; --high: #f97316; --medium: #eab308; --low: #22c55e; --info: #3b82f6;
  --passed: #22c55e; --failed: #ef4444; --error: #f97316; }
* { box-sizing: border-box; margin: 0; padding: 0; }
body { font-family: 'Inter', -apple-system, sans-serif; background: var(--bg); color: var(--text); padding: 2rem; }
.container { max-width: 1400px; margin: 0 auto; }
h1 { font-size: 1.8rem; margin-bottom: 0.5rem; }
h2 { font-size: 1.3rem; margin: 1.5rem 0 0.8rem; border-bottom: 1px solid var(--border); padding-bottom: 0.5rem; }
h3 { font-size: 1.1rem; margin: 1rem 0 0.5rem; }
.meta { color: var(--muted); font-size: 0.85rem; margin-bottom: 1.5rem; }
.grid { display: grid; grid-template-columns: repeat(auto-fill, minmax(280px, 1fr)); gap: 1rem; margin: 1rem 0; }
.card { background: var(--card); border-radius: 8px; padding: 1.2rem; border: 1px solid var(--border); }
.score-ring { width: 120px; height: 120px; border-radius: 50%; display: flex; align-items: center; justify-content: center;
  font-size: 2rem; font-weight: 700; margin: 0 auto 1rem; border: 6px solid; }
.score-critical { border-color: var(--critical); color: var(--critical); }
.score-high { border-color: var(--high); color: var(--high); }
.score-medium { border-color: var(--medium); color: var(--medium); }
.score-low { border-color: var(--low); color: var(--low); }
.score-none { border-color: var(--passed); color: var(--passed); }
.badge { display: inline-block; padding: 2px 8px; border-radius: 4px; font-size: 0.75rem; font-weight: 600; }
.badge-critical { background: var(--critical); color: white; }
.badge-high { background: var(--high); color: white; }
.badge-medium { background: var(--medium); color: black; }
.badge-low { background: var(--low); color: black; }
.badge-info { background: var(--info); color: white; }
.badge-passed { background: var(--passed); color: black; }
.badge-failed { background: var(--failed); color: white; }
.badge-error { background: var(--error); color: white; }
table { width: 100%; border-collapse: collapse; margin: 0.5rem 0; font-size: 0.85rem; }
th, td { padding: 8px 12px; text-align: left; border-bottom: 1px solid var(--border); }
th { color: var(--muted); font-weight: 600; }
.stats { display: flex; gap: 1.5rem; flex-wrap: wrap; margin: 0.5rem 0; }
.stat { text-align: center; }
.stat-val { font-size: 1.5rem; font-weight: 700; }
.stat-label { font-size: 0.75rem; color: var(--muted); }
details { margin: 0.5rem 0; }
summary { cursor: pointer; color: var(--info); font-size: 0.85rem; }
pre { background: #0d1117; padding: 0.8rem; border-radius: 4px; overflow-x: auto; font-size: 0.8rem; margin: 0.5rem 0; }
.recommendations { list-style: none; padding: 0; }
.recommendations li { padding: 0.5rem; border-left: 3px solid var(--high); margin: 0.5rem 0; background: var(--card); }
</style>
</head>
<body>
<div class="container">
<h1>OWASP ASI Top 10 Security Assessment</h1>
<div class="meta">
  Agent: <strong>{{ report.agent_name }}</strong> |
  Target: <code>{{ report.target_url }}</code> |
  Scan: {{ report.scan_timestamp[:19] }} |
  Duration: {{ "%.1f"|format(report.duration_seconds) }}s
</div>

<div class="card" style="text-align:center">
  <div class="score-ring {{ score_class }}">{{ "%.1f"|format(report.overall_risk_score) }}</div>
  <p>{{ report.summary }}</p>
</div>

{% if discovered_tools or discovered_capabilities %}
<h2>Attack Surface</h2>
<p style="color: var(--muted); font-size: 0.85rem">
  Statically discovered from the agent's API spec during the <code>discover</code> stage.
  This is the declared surface — distinct from what the agent self-reports over chat
  (see <em>Agent Identity → Tools Discovered</em> below).
</p>
<div class="grid">
  <div class="card">
    <h3>Capabilities ({{ discovered_capabilities|length }})</h3>
    {% if discovered_capabilities %}
      <p>{% for c in discovered_capabilities %}<code>{{ c }}</code>{% if not loop.last %}, {% endif %}{% endfor %}</p>
    {% else %}
      <p style="color: var(--muted)"><em>None inferred</em></p>
    {% endif %}
  </div>
  <div class="card">
    <h3>Endpoints</h3>
    <p>{{ discovered_endpoint_count }} declared</p>
  </div>
</div>
{% if discovered_tools %}
<div class="card" style="margin-top:1rem">
  <h3>Tools ({{ discovered_tools|length }})</h3>
  <table>
    <tr><th>Tool</th><th>Capability</th><th>Description</th></tr>
    {% for t in discovered_tools %}
    <tr>
      <td><code>{{ t.name }}</code></td>
      <td>{{ t.capability }}</td>
      <td style="color: var(--muted); font-size: 0.85rem">{{ t.description[:100] }}</td>
    </tr>
    {% endfor %}
  </table>
</div>
{% endif %}
{% endif %}

{% if fingerprint_evidence %}
<h2>Agent Identity</h2>
{% if fingerprint_regex_only %}
<div class="card" style="border-color: var(--medium); background: #2d2410">
  <strong>Heads up:</strong> Fingerprint generated without LLM. Results may miss
  model aliases, obfuscated names, or non-English signals. Pass <code>--llm</code> for higher fidelity.
</div>
{% endif %}
{% if any_chat_failed %}
<div class="card" style="border-color: var(--medium); background: #2d2410; margin-top:0.5rem">
  <strong>Note:</strong> The chat endpoint returned an HTML page instead of a text reply
  for one or more probes — most likely the agent's chat handler requires additional
  request fields (e.g. <code>mode</code>) or a configured LLM provider that wasn't set up.
  Detected-model and tool-list signals below are therefore unreliable.
</div>
{% endif %}
<div class="grid">
  <div class="card">
    <h3>Detected Model</h3>
    {% if detected_model_family_clean %}
      <p><code>{{ detected_model_family_clean }}</code></p>
    {% else %}
      <p style="color: var(--muted)"><em>Not detected — agent did not return a text reply</em></p>
    {% endif %}
  </div>
  <div class="card">
    <h3>Response Shape</h3>
    {% if response_shape and response_shape != "unknown" %}
      <p><code>{{ response_shape }}</code></p>
    {% else %}
      <p style="color: var(--muted)"><em>Unknown — envelope did not match a known LLM API shape</em></p>
    {% endif %}
  </div>
  <div class="card">
    <h3>Guardrail Strength</h3>
    <p>{% if guardrail_strength %}<code>{{ guardrail_strength }}</code>{% else %}<em>Not assessed (passive fingerprint only)</em>{% endif %}</p>
  </div>
  <div class="card">
    <h3>Tools Discovered</h3>
    {% if detected_tools_clean %}
      <p>{{ detected_tools_clean|length }} tool(s): {{ detected_tools_clean[:8]|join(', ') }}{% if detected_tools_clean|length > 8 %}, …{% endif %}</p>
    {% else %}
      <p style="color: var(--muted)"><em>None discovered</em></p>
    {% endif %}
  </div>
</div>
<div class="card" style="margin-top:1rem">
  <h3>Probes ({{ fingerprint_evidence.probes|length }})</h3>
  <p style="color: var(--muted); font-size: 0.85rem">
    Probe response excerpts shown after redaction. Review carefully before sharing externally.
    Fingerprint cost: ${{ "%.4f"|format(fingerprint_evidence.cost_usd) }} of ${{ "%.4f"|format(fingerprint_evidence.cost_cap_usd) }} cap.
  </p>
  <table>
    <tr><th>Probe</th><th>Tier</th><th>Classifier</th><th>Verdict</th><th>Notes</th></tr>
    {% for p in fingerprint_evidence.probes %}
    <tr>
      <td>{{ p.probe_id }}</td>
      <td><span class="badge badge-{{ 'high' if p.tier == 'aggressive' else 'info' }}">{{ p.tier }}</span></td>
      <td>{{ p.classification_path }}</td>
      <td>
        {% if p.verdict.startswith('no_chat_response') %}
          <span class="badge badge-medium">no chat reply</span>
        {% elif p.verdict == 'unknown' %}
          <span class="badge badge-info">unknown</span>
        {% else %}
          <code>{{ p.verdict[:60] }}</code>
        {% endif %}
      </td>
      <td style="color: var(--muted); font-size: 0.85rem">
        {% if p.verdict.startswith('no_chat_response') %}
          Target returned an HTML page; chat handler likely needs additional payload fields.
        {% elif p.response_excerpt and not p.response_excerpt.lstrip().startswith('<') %}
          {{ p.response_excerpt[:160] }}{% if p.response_excerpt|length > 160 %}…{% endif %}
        {% else %}
          <em>(response was HTML — excerpt suppressed)</em>
        {% endif %}
      </td>
    </tr>
    {% endfor %}
  </table>
</div>
{% endif %}

<h2>Category Results</h2>
<div class="grid">
{% for cat in report.categories %}
<div class="card">
  <h3>{{ cat.category.value }}: {{ cat.category_name }}</h3>
  <div class="stats">
    <div class="stat"><div class="stat-val" style="color:var(--passed)">{{ cat.tests_passed }}</div><div class="stat-label">Held</div></div>
    <div class="stat"><div class="stat-val" style="color:var(--failed)">{{ cat.tests_failed }}</div><div class="stat-label">Vulnerable</div></div>
    <div class="stat"><div class="stat-val" style="color:var(--error)">{{ cat.tests_error }}</div><div class="stat-label">Errors</div></div>
    <div class="stat"><div class="stat-val">{{ "%.1f"|format(cat.risk_score) }}</div><div class="stat-label">Risk</div></div>
  </div>
</div>
{% endfor %}
</div>

<h2>Findings Detail</h2>
{% for cat in report.categories %}
<h3>{{ cat.category.value }}: {{ cat.category_name }} ({{ cat.tests_run }} tests)</h3>
<table>
<tr><th>Test</th><th>Status</th><th>Severity</th><th>CWE</th><th>Latency</th><th>Description</th></tr>
{% for f in cat.findings %}
<tr>
  <td>{{ f.test_name }}</td>
  <td><span class="badge badge-{{ f.status.value|lower }}">{{ f.status.value }}</span></td>
  <td><span class="badge badge-{{ f.severity.value|lower }}">{{ f.severity.value }}</span></td>
  <td>{{ f.cwe_id }}</td>
  <td>{{ "%.0f"|format(f.latency_ms) }}ms</td>
  <td>{{ f.description[:80] }}{% if f.description|length > 80 %}...{% endif %}</td>
</tr>
{% endfor %}
</table>
{% endfor %}

{% if report.recommendations %}
<h2>Recommendations</h2>
<ul class="recommendations">
{% for rec in report.recommendations %}
<li>{{ rec }}</li>
{% endfor %}
</ul>
{% endif %}

<div class="meta" style="margin-top:2rem;text-align:center">
  Generated by OWASP ASI Security Tester v1.0.0 | OWASP GenAI Security Project
</div>
</div>
</body>
</html>"""


def save_html_report(report: SecurityReport, output_path: Path, profile=None) -> Path:
    """Generate HTML dashboard report.

    If ``profile`` is provided and has ``fingerprint_evidence`` populated, an
    "Agent Identity" panel is rendered. Otherwise the panel is omitted.
    """
    score = report.overall_risk_score
    if score >= 7.0:
        score_class = "score-critical"
    elif score >= 4.0:
        score_class = "score-high"
    elif score >= 2.0:
        score_class = "score-medium"
    elif score > 0:
        score_class = "score-low"
    else:
        score_class = "score-none"

    fingerprint_evidence = getattr(profile, "fingerprint_evidence", None)
    fingerprint_regex_only = False
    any_chat_failed = False
    detected_model_family_clean: str | None = None
    detected_tools_clean: list[str] = []
    if fingerprint_evidence is not None and fingerprint_evidence.probes:
        fingerprint_regex_only = all(
            p.classification_path == "regex" for p in fingerprint_evidence.probes
        )
        any_chat_failed = any(
            (p.verdict or "").startswith("no_chat_response")
            for p in fingerprint_evidence.probes
        )

        # Clean detected-model display: drop the sentinel string if present
        raw_model = getattr(profile, "detected_model_family", None)
        if raw_model and not raw_model.startswith("no_chat_response"):
            detected_model_family_clean = raw_model

        # Clean tool list: drop empties and sentinels
        raw_tools = getattr(profile, "detected_tools", []) or []
        for t in raw_tools:
            name = (getattr(t, "name", "") or "").strip()
            if not name or name.startswith("no_chat_response"):
                continue
            if name not in detected_tools_clean:
                detected_tools_clean.append(name)

    # Statically-discovered attack surface (from the profile, independent of the
    # behavioral fingerprint). Shown so the report reflects the tools/capabilities
    # the discover stage found, not just what the agent self-reports over chat.
    discovered_tools = [
        {
            "name": getattr(t, "name", ""),
            "capability": getattr(getattr(t, "inferred_capability", None), "value", "unknown"),
            "description": getattr(t, "description", "") or "",
        }
        for t in (getattr(profile, "tools", []) or [])
    ]
    discovered_capabilities = [
        getattr(c, "value", str(c))
        for c in (getattr(profile, "inferred_capabilities", []) or [])
    ]
    discovered_endpoint_count = len(getattr(profile, "endpoints", []) or [])

    template = _JINJA_ENV.from_string(HTML_TEMPLATE)
    html = template.render(
        report=report,
        score_class=score_class,
        discovered_tools=discovered_tools,
        discovered_capabilities=discovered_capabilities,
        discovered_endpoint_count=discovered_endpoint_count,
        fingerprint_evidence=fingerprint_evidence,
        fingerprint_regex_only=fingerprint_regex_only,
        any_chat_failed=any_chat_failed,
        detected_model_family=getattr(profile, "detected_model_family", None),
        detected_model_family_clean=detected_model_family_clean,
        response_shape=getattr(profile, "response_shape", None),
        guardrail_strength=getattr(profile, "guardrail_strength", None),
        detected_tools=getattr(profile, "detected_tools", []) or [],
        detected_tools_clean=detected_tools_clean,
    )

    output_path.parent.mkdir(parents=True, exist_ok=True)
    with open(output_path, "w", encoding="utf-8") as f:
        f.write(html)
    logger.info(f"HTML report saved: {output_path}")
    return output_path
