"""Risk score category weights and confidence multipliers."""

from mcp_audit.models import Confidence, PermissionCategory

# Higher weight = more dangerous capability
CATEGORY_WEIGHTS: dict[PermissionCategory, float] = {
    PermissionCategory.SHELL_EXEC: 3.0,      # Arbitrary code execution
    PermissionCategory.EXFILTRATION: 2.5,    # Data leaves the machine
    PermissionCategory.FILE_WRITE: 2.0,      # Can modify system state
    PermissionCategory.DESTRUCTIVE: 2.0,     # Can destroy data
    PermissionCategory.NETWORK: 1.5,         # External communication
    PermissionCategory.FILE_READ: 1.0,       # Least risky, still notable
}

# Confidence affects how much a finding contributes to the score
CONFIDENCE_MULTIPLIERS: dict[Confidence, float] = {
    Confidence.DECLARED: 1.0,   # From annotations — most reliable
    Confidence.MANUAL: 1.0,     # User explicitly classified
    Confidence.HIGH: 0.9,       # Multiple strong keyword matches
    Confidence.MEDIUM: 0.6,     # Single strong or multiple moderate
    Confidence.LOW: 0.3,        # Weak/inferred
}

# Composite score formula:
# For each permission category found on a server:
#   category_score = CATEGORY_WEIGHTS[category] * max(CONFIDENCE_MULTIPLIERS[finding.confidence]
#                                                      for finding in category_findings)
# composite = min(10, sum(category_scores))
