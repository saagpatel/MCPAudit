---
name: Feature request
about: Suggest a new audit check, CLI flag, output format, or other improvement
title: "[feat] "
labels: enhancement
assignees: ''
---

## Summary

A brief description of the feature you'd like to see.

## Audit dimension

Which dimension does this feature relate to? Check all that apply:

- [ ] Permission risk scoring (filesystem, network, shell access)
- [ ] Prompt injection detection (tool descriptions, resource URIs)
- [ ] Schema drift / capability declaration consistency
- [ ] Config discovery (new MCP client locations)
- [ ] Output / reporting (new format, summary, CI integration)
- [ ] Watch mode / continuous auditing
- [ ] LLM-assisted narration (`--llm-explain`)
- [ ] New dimension entirely — describe below
- [ ] Other / not audit-specific

## Motivation

Why is this useful? What threat, gap, or workflow problem does it address?

## Proposed behavior

How should this work? Include example CLI invocations or output if relevant.

```bash
mcp-audit --new-flag
```

## Alternatives considered

Any other approaches you considered and why you prefer this one.

## Additional context

Links, references, related MCP spec sections, or anything else that would help evaluate this request.
