"""Instruction-shaped tool-result rules; findings never retain result excerpts."""

import re

# Heuristics, not a semantic verdict. Keep all runtime-result phrases here.
RESULT_INJECTION_RULES: dict[str, re.Pattern[str]] = {
    "result_instruction_override": re.compile(
        r"\b(?:ignore (?:all )?previous|disregard (?:all|previous)|forget (?:all|previous))\b",
        re.IGNORECASE,
    ),
    "result_credential_hunt": re.compile(
        r"\b(?:read|open|cat|collect|retrieve|print|send|dump|inspect|access|extract)\b"
        r"[^\n.!?]{0,160}"
        r"(?:~/(?:\.ssh|\.aws/credentials|\.kube/config|\.[a-z]*_?history)"
        r"|\b(?:environment variables?|env vars?|kubeconfig|shell history|credentials?|api keys?)\b"
        r"|\b(?:os\.environ|process\.env|AWS_SECRET_ACCESS_KEY)\b"
        r"|\$\{?[A-Z_][A-Z0-9_]*\}?)",
        re.IGNORECASE,
    ),
    "result_tool_redirect": re.compile(
        r"\b(?:call|invoke|execute|use)\s+(?:the\s+)?(?:other\s+|another\s+)?"
        r"(?:[\w.-]+\s+)?tools?\b|\btools/call\b",
        re.IGNORECASE,
    ),
}
