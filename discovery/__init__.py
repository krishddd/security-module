"""Agent discovery layer.

Converts user-supplied URLs / OpenAPI specs / legacy manifests into a
unified ``AgentProfile``. Three entry points, in priority order:

1. ``openapi_parser.from_url(spec_url)`` — preferred path.
2. ``manifest_loader.from_legacy_config(path)`` — backward compatibility.
3. ``well_known_prober.probe(base_url)`` — heuristic fallback.
"""

from .openapi_parser import OpenAPIParseError, parse_openapi, parse_openapi_url
from .manifest_loader import load_legacy_config
from .well_known_prober import probe_well_known

__all__ = [
    "OpenAPIParseError",
    "parse_openapi",
    "parse_openapi_url",
    "load_legacy_config",
    "probe_well_known",
]
