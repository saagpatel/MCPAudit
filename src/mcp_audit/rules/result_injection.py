"""Instruction-shaped tool-result rules; findings never retain result excerpts."""

import re

# Generic credential nouns require an explicit agent frame. Concrete secret
# paths/names paired with an imperative are stronger evidence.
_VERBS = (
    r"(?:include|get|fetch|upload|copy|paste|attach|share|send|read|cat|open|collect|retrieve"
    r"|print|dump|inspect|access|extract)"
)
_AGENT = r"\b(?:you|assistant|agent|model)\b"
_NEAR = r"[^\n!?;]{0,160}?"
_SECRET = (
    r"(?:~/(?:\.ssh|\.aws/credentials|\.kube/config|\.[a-z]*_?history)"
    r"|/(?:Users|home)/[^/\s]+/(?:\.ssh|\.aws/credentials|\.kube/config)"
    r"|(?<![\w.])\.env\b|\bid_rsa\b|\bkubeconfig\b"
    r"|(?-i:\b(?:GITHUB_TOKEN|AWS_SECRET_ACCESS_KEY|OPENAI_API_KEY|ANTHROPIC_API_KEY)\b)"
    r"|(?-i:\$\{?(?:[A-Z_][A-Z0-9_]*_)?(?:TOKEN|SECRET|API_KEY|PASSWORD|CREDENTIALS)\}?)"
    r"|\b(?:os\.environ|process\.env|environment variables?|env vars?|shell history)\b)"
)
_IMPERATIVE = rf"(?:^|[.!?;\n]\s*|\b(?:please|now|then|and)\s+)\s*{_VERBS}\b"
_REDIRECT = (
    r"\b(?:call|invoke|execute|use)\s+(?:the\s+)?(?:other\s+|another\s+)?"
    r"(?:[\w.-]+\s+)?tools?\b|\btools/call\b"
)

# Heuristics, not a semantic verdict. Keep all runtime-result phrases here.
RESULT_INJECTION_RULES: dict[str, re.Pattern[str]] = {
    "result_instruction_override": re.compile(
        r"\b(?:ignore (?:all |any |the |your )?(?:previous|prior|above)"
        r"|(?:disregard|forget) (?:all |any |the |your )?(?:previous|prior|above))\b",
        re.IGNORECASE,
    ),
    "result_credential_hunt": re.compile(
        rf"(?:{_IMPERATIVE}{_NEAR}{_SECRET}"
        rf"|{_AGENT}{_NEAR}\b{_VERBS}\b{_NEAR}"
        rf"(?:{_SECRET}|\b(?:credentials?|api keys?)\b)"
        rf"|\b{_VERBS}\b{_NEAR}{_SECRET}{_NEAR}{_AGENT})",
        re.IGNORECASE,
    ),
    "result_tool_redirect": re.compile(
        rf"(?:{_AGENT}{_NEAR}(?:{_REDIRECT})"
        rf"|(?:^|[.!?;\n]\s*|\b(?:please|now|then|and)\s+)\s*(?:{_REDIRECT}))",
        re.IGNORECASE,
    ),
}
