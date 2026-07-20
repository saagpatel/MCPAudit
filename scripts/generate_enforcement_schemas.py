"""Generate the checked-in evidence-to-enforcement JSON Schemas."""

from __future__ import annotations

import json
from pathlib import Path

from pydantic import BaseModel

from mcp_audit.evidence_enforcement import (
    ApprovedPolicyIntentV1,
    EffectiveStateV1,
    ObservedEvidenceV1,
    PolicyRecommendationV1,
)

SCHEMAS: dict[str, type[BaseModel]] = {
    "observed-evidence-v1.schema.json": ObservedEvidenceV1,
    "policy-recommendation-v1.schema.json": PolicyRecommendationV1,
    "approved-policy-intent-v1.schema.json": ApprovedPolicyIntentV1,
    "effective-state-v1.schema.json": EffectiveStateV1,
}


def main() -> None:
    output = Path("examples/schemas")
    output.mkdir(parents=True, exist_ok=True)
    for filename, model in SCHEMAS.items():
        rendered = json.dumps(model.model_json_schema(), indent=2, sort_keys=True) + "\n"
        (output / filename).write_text(rendered, encoding="utf-8")


if __name__ == "__main__":
    main()
