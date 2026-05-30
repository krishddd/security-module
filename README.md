# security-module

> Agent-agnostic safety and red-team evaluation harness for AI services.

Point this scanner at any agentic-AI service — give it a base URL, an OpenAPI
spec, and an optional bearer token — and it probes the target across **17+
extended threat classes** drawn from OWASP-LLM and bespoke ASI categories,
scoring each probe and recording evidence for audit.

## Features

- **17 ASI-class test suites** under `tests_asi/` covering prompt injection,
  cache poisoning, delivery hijack, tool abuse, schema confusion, and more.
- **Plug-in target adapter** — works against any HTTP-exposed agent or LLM
  endpoint; no SDK lock-in.
- **OWASP-LLM coverage** mapped to the ASI checks.
- **Structured probe log** — every request, response, verdict, and evidence
  blob captured for replay.
- **Reproducible scenarios** — seeds and configs are part of the test
  artefact.

## Tech stack

Python · pytest · requests · structured JSON logging

## Quickstart

```bash
git clone https://github.com/krishddd/security-module.git
cd security-module
pip install -r requirements.txt
cp .env.example .env  # add TARGET_URL, TARGET_TOKEN, etc.
pytest tests_asi/ -v
```

To run a single suite:

```bash
pytest tests_asi/ext16_cache_poisoning.py -v
```

## Project structure

```
tests_asi/     ASI extended test suites (17 modules)
core/          Shared scanner primitives + target adapter
reporting/     JSON / Markdown verdict emitters
```

## Status

Personal portfolio project — designed to be agent-agnostic so it can be aimed
at any production or staging agentic-AI service you own.

## License

MIT
