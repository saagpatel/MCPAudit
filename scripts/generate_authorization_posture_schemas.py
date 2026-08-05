"""Generate checked-in authorization-posture input and report schemas."""

from __future__ import annotations

import json
from pathlib import Path

from mcp_audit.authorization_posture_models import (
    AuthorizationPostureReport,
    McpAuthorizationPostureV1,
)


def main() -> None:
    output = Path(__file__).parents[1] / "examples" / "schemas"
    models = {
        "authorization-posture-input-v1.schema.json": McpAuthorizationPostureV1,
        "authorization-posture-report-v1.schema.json": AuthorizationPostureReport,
    }
    for filename, model in models.items():
        rendered = json.dumps(model.model_json_schema(), indent=2, sort_keys=True) + "\n"
        (output / filename).write_text(rendered, encoding="utf-8")


if __name__ == "__main__":
    main()
