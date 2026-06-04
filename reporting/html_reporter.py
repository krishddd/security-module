"""HTML dashboard reporter using Jinja2 templates."""

import logging
from pathlib import Path
from jinja2 import Template
from models.enums import Severity, TestStatus
from models.test_result import SecurityReport

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

{% if fingerprint_evidence %}
<h2>Agent Identity</h2>
{% if fingerprint_regex_only %}
<div class="card" style="border-color: var(--medium); background: #2d2410">
  <strong>Heads up:</strong> Fingerprint generated without LLM. Results may miss
  model aliases, obfuscated names, or non-English signals. Pass <code>--llm</code> for higher fidelity.
</div>
{% endif %}
<div class="grid">
  <div class="card">
    <h3>Detected Model</h3>
    <p><code>{{ detected_model_family or "unknown" }}</code></p>
  </div>
  <div class="card">
    <h3>Response Shape</h3>
    <p><code>{{ response_shape or "unknown" }}</code></p>
  </div>
  <div class="card">
    <h3>Guardrail Strength</h3>
    <p>{% if guardrail_strength %}<code>{{ guardrail_strength }}</code>{% else %}<em>Not assessed (passive fingerprint only)</em>{% endif %}</p>
  </div>
  <div class="card">
    <h3>Tools Discovered</h3>
    <p>{{ detected_tools|length }} tool(s){% if detected_tools %}: {{ detected_tools[:8]|map(attribute='name')|join(', ') }}{% if detected_tools|length > 8 %}, …{% endif %}{% endif %}</p>
  </div>
</div>
<div class="card" style="margin-top:1rem">
  <h3>Probes ({{ fingerprint_evidence.probes|length }})</h3>
  <p style="color: var(--muted); font-size: 0.85rem">
    Probe response excerpts shown after redaction. Review carefully before sharing externally.
    Fingerprint cost: ${{ "%.4f"|format(fingerprint_evidence.cost_usd) }} of ${{ "%.4f"|format(fingerprint_evidence.cost_cap_usd) }} cap.
  </p>
  <table>
    <tr><th>Probe</th><th>Tier</th><th>Classifier</th><th>Verdict</th><th>Response excerpt</th></tr>
    {% for p in fingerprint_evidence.probes %}
    <tr>
      <td>{{ p.probe_id }}</td>
      <td><span class="badge badge-{{ 'high' if p.tier == 'aggressive' else 'info' }}">{{ p.tier }}</span></td>
      <td>{{ p.classification_path }}</td>
      <td><code>{{ p.verdict[:60] }}</code></td>
      <td>{{ p.response_excerpt[:200] }}{% if p.response_excerpt|length > 200 %}…{% endif %}</td>
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
    if fingerprint_evidence is not None and fingerprint_evidence.probes:
        fingerprint_regex_only = all(
            p.classification_path == "regex" for p in fingerprint_evidence.probes
        )

    template = Template(HTML_TEMPLATE)
    html = template.render(
        report=report,
        score_class=score_class,
        fingerprint_evidence=fingerprint_evidence,
        fingerprint_regex_only=fingerprint_regex_only,
        detected_model_family=getattr(profile, "detected_model_family", None),
        response_shape=getattr(profile, "response_shape", None),
        guardrail_strength=getattr(profile, "guardrail_strength", None),
        detected_tools=getattr(profile, "detected_tools", []) or [],
    )

    output_path.parent.mkdir(parents=True, exist_ok=True)
    with open(output_path, "w", encoding="utf-8") as f:
        f.write(html)
    logger.info(f"HTML report saved: {output_path}")
    return output_path
