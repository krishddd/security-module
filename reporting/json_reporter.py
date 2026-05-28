"""JSON reporter — saves structured SecurityReport to disk."""

import json
import logging
from pathlib import Path
from models.test_result import SecurityReport

logger = logging.getLogger(__name__)


def save_json_report(report: SecurityReport, output_path: Path) -> Path:
    """Save full report as formatted JSON."""
    output_path.parent.mkdir(parents=True, exist_ok=True)
    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(report.to_dict(), f, indent=2, ensure_ascii=False)
    logger.info(f"JSON report saved: {output_path}")
    return output_path
