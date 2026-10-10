# Finding reference

<!-- Generated from mcp_audit.taxonomy; run scripts/generate_findings.py. -->

Read any entry offline with `mcp-audit explain MCP007`. No configs are read and no servers are contacted. Time estimates describe initial containment or review, not a guaranteed repair. Check recorded coverage before interpreting an absence of findings.

Suppressions are not implemented by this reference. Permission-category overrides do not remove hidden instructions or suppress individual finding IDs.

## MCP001

Your AI may be able to read files through this server.

What we saw: Config or tool metadata suggests file-reading access.

Why it matters:

1. You enable a file-reading tool.
2. The tool may reach private paths.
3. Those files can enter the AI's context.

How to fix (About 5 minutes to review scope): Limit allowed paths to the project files you need; remove the server if its access is unnecessary.

How sure: A capability inference from config or served metadata, not an observed operation. Use the finding's confidence and evidence; descriptions and annotations can be inaccurate.

see: https://github.com/saagpatel/MCPAudit/blob/main/docs/findings/index.md#mcp001

## MCP002

Your AI may be able to change files through this server.

What we saw: Config or tool metadata suggests file-writing access.

Why it matters:

1. You enable a writing tool.
2. It may change files outside the intended task.
3. Your work could be overwritten.

How to fix (About 5 minutes to restrict scope): Restrict writable paths and review the implementation; disable unnecessary write tools.

How sure: A capability inference from config or served metadata, not an observed operation. Use the finding's confidence and evidence; descriptions and annotations can be inaccurate.

see: https://github.com/saagpatel/MCPAudit/blob/main/docs/findings/index.md#mcp002

## MCP003

Your AI may be able to reach the internet through this server.

What we saw: Config or tool metadata suggests network access; an absent hint alone is not evidence.

Why it matters:

1. You enable a networked tool.
2. It contacts an external service.
3. Workspace data may leave your machine.

How to fix (About 5 minutes to review destinations): Review destinations and the data each tool sends; restrict network access where possible.

How sure: A capability inference from config or served metadata, not an observed operation. Use the finding's confidence and evidence; descriptions and annotations can be inaccurate.

see: https://github.com/saagpatel/MCPAudit/blob/main/docs/findings/index.md#mcp003

## MCP004

Your AI may be able to run commands through this server.

What we saw: Config or tool metadata suggests shell or process execution.

Why it matters:

1. You enable a command-running tool.
2. It can use the server process's permissions.
3. Files or other local programs could be affected.

How to fix (About 1 minute to disable; review time varies): Disable or isolate command execution until you have reviewed its arguments and allowed operations.

How sure: A capability inference from config or served metadata, not an observed operation. Use the finding's confidence and evidence; descriptions and annotations can be inaccurate.

see: https://github.com/saagpatel/MCPAudit/blob/main/docs/findings/index.md#mcp004

## MCP005

Your AI may be able to delete or replace data through this server.

What we saw: Metadata or an explicit annotation suggests a destructive operation.

Why it matters:

1. You enable a destructive tool.
2. A mistaken call could remove data.
3. Recovery may require a backup.

How to fix (About 1 minute to disable): Disable unnecessary destructive tools and restrict their scope; review calls before using them.

How sure: A capability inference from config or served metadata, not an observed operation. Use the finding's confidence and evidence; descriptions and annotations can be inaccurate.

see: https://github.com/saagpatel/MCPAudit/blob/main/docs/findings/index.md#mcp005

## MCP006

Your AI may be able to send private data out through this server.

What we saw: Metadata suggests access to local data combined with an outbound transfer capability.

Why it matters:

1. A tool can access data.
2. It also has a way to transmit data.
3. Private content could reach an external recipient.

How to fix (About 5 minutes to review scope): Restrict data sources, recipients and destinations, or disable the transfer tool.

How sure: A capability inference from config or served metadata, not an observed operation. Use the finding's confidence and evidence; descriptions and annotations can be inaccurate.

see: https://github.com/saagpatel/MCPAudit/blob/main/docs/findings/index.md#mcp006

## MCP007

This tool's text may give your AI hidden instructions.

What we saw: Agent-facing text matched a high-severity instruction pattern; see the matched excerpt and field.

Why it matters:

1. Your AI may read the server's text when using it.
2. It could follow the embedded instruction instead of your task.
3. Depending on its access, it could reveal private data or take an unwanted action.

How to fix (About 1 minute to disable; source review varies): Remove the server from the named config entry, or remove the matched instruction if you own it. Restart the client. Never treat allowing a finding as removing the instruction the AI reads.

How sure: A deterministic text or structural heuristic, not AI judgment or proof of an attack. Quoted examples and legitimate instructions can match. Static checks do not cover every attack.

see: https://github.com/saagpatel/MCPAudit/blob/main/docs/findings/index.md#mcp007

## MCP008

Your AI may read suspicious instructions or hidden text from this server.

What we saw: Metadata or returned content matched an instruction, hidden-character or encoded-content heuristic.

Why it matters:

1. Server text enters the AI's context.
2. Instruction-shaped or hidden text may influence its next action.
3. That action could depart from your intended task.

How to fix (About 5 minutes for an initial review): Review the marked text and its field. Remove unexpected instructions if you own the server; otherwise disable it pending review.

How sure: A deterministic text or structural heuristic, not AI judgment or proof of an attack. Quoted examples and legitimate instructions can match. Static checks do not cover every attack.

see: https://github.com/saagpatel/MCPAudit/blob/main/docs/findings/index.md#mcp008

## MCP009

Your AI's available tools changed since the comparison baseline.

What we saw: A pin or controlled session comparison found a changed, added, removed or identity-conditioned surface.

Why it matters:

1. You reviewed an earlier surface.
2. The current surface differs.
3. Your earlier trust decision may no longer cover it.

How to fix (About 5 minutes for an initial comparison): Review the recorded changes before refreshing any pin. Disable an unexpected surface pending review.

How sure: A comparison with the saved baseline, not proof of compromise. Confirm the baseline's scope and review the specific delta; an intentional update can also trigger this finding.

see: https://github.com/saagpatel/MCPAudit/blob/main/docs/findings/index.md#mcp009

## MCP010

Your audit did not meet your local policy.

What we saw: A reported result or missing coverage violated an explicitly selected policy rule.

Why it matters:

1. You set a local requirement.
2. This scan did not satisfy it.
3. Accepting the result would bypass that requirement.

How to fix (Review time depends on the violated rule): Read the named policy violation; repair the configuration or deliberately review the policy before rechecking.

How sure: A deterministic policy evaluation, not a universal security verdict.

see: https://github.com/saagpatel/MCPAudit/blob/main/docs/findings/index.md#mcp010

## MCP011

Your server may fetch a destination chosen by someone else.

What we saw: A caller-controlled URL or host is paired with evidence of server-side fetching.

Why it matters:

1. A caller supplies a destination.
2. The server may fetch it using its own network access.
3. Internal services or metadata endpoints could become reachable.

How to fix (About 5 minutes to disable; implementation work varies): Restrict destinations to validated hosts; block loopback, link-local and private targets in the server's fetch implementation.

How sure: A capability inference from config or served metadata, not an observed operation. Use the finding's confidence and evidence; descriptions and annotations can be inaccurate.

see: https://github.com/saagpatel/MCPAudit/blob/main/docs/findings/index.md#mcp011

## MCP012

Your server may accept a caller-chosen network destination.

What we saw: A URL-shaped input, host input or remote resource template matched a possible request-routing pattern.

Why it matters:

1. A caller controls part of a request.
2. That input may select a network destination.
3. The server could reach an unintended service.

How to fix (About 5 minutes for an initial review): Check how the named parameter or URI is resolved; restrict it to known destinations if it controls a fetch.

How sure: A capability inference from config or served metadata, not an observed operation. Use the finding's confidence and evidence; descriptions and annotations can be inaccurate.

see: https://github.com/saagpatel/MCPAudit/blob/main/docs/findings/index.md#mcp012

## MCP013

Your AI could read private data and send it out through one server.

What we saw: One server has evidence for file access, untrusted-content ingestion and outbound transfer. The finding names the tools or resources contributing each link.

Why it matters:

1. A tool may read private files.
2. Untrusted content could influence the AI using those files.
3. An outbound tool could send the data to another party.

How to fix (About 5 minutes to choose and disable an optional link): Cut one link: disable optional file access, ingestion or outbound transfer using the named contributors. If none is optional, isolate the server and restrict file paths and destinations.

How sure: A capability inference from config or served metadata, not an observed operation. Use the finding's confidence and evidence; descriptions and annotations can be inaccurate. No successful attack or transfer was observed by this check.

see: https://github.com/saagpatel/MCPAudit/blob/main/docs/findings/index.md#mcp013

## MCP014

Your AI could combine private reads and outbound transfers across servers.

What we saw: The audited fleet covers all three links, but no single server covers them all.

Why it matters:

1. One server may read private files.
2. Another may ingest untrusted content in the same AI session.
3. An outbound capability could complete a transfer path.

How to fix (About 10 minutes to review session scope): Review which servers share an AI session. Remove an optional link or separate them into isolated contexts.

How sure: A capability inference from config or served metadata, not an observed operation. Use the finding's confidence and evidence; descriptions and annotations can be inaccurate. This is a fleet advisory; shared session use is not established.

see: https://github.com/saagpatel/MCPAudit/blob/main/docs/findings/index.md#mcp014

## MCP015

Your AI may see the same tool name from different servers.

What we saw: Multiple servers expose an identical tool name.

Why it matters:

1. The AI chooses a tool by name.
2. More than one server offers that name.
3. Routing could reach a server you did not intend.

How to fix (About 5 minutes to review duplicates): Give tools unique server-specific prefixes, or disable the unintended duplicate after reviewing both sources.

How sure: An exact name comparison; ordering does not establish which server is legitimate.

see: https://github.com/saagpatel/MCPAudit/blob/main/docs/findings/index.md#mcp015

## MCP016

Your AI may confuse tool names that differ only in formatting.

What we saw: Tool names match after case-folding and separator removal.

Why it matters:

1. Two tools look similar.
2. An agent may treat their names as interchangeable.
3. It could choose the wrong server.

How to fix (About 5 minutes to rename or disable a duplicate): Use distinct server-specific prefixes that remain different after normalization.

How sure: A deterministic normalized comparison, not observed misrouting.

see: https://github.com/saagpatel/MCPAudit/blob/main/docs/findings/index.md#mcp016

## MCP017

Your AI may see lookalike tool names from different servers.

What we saw: Non-ASCII confusable characters produce a name skeleton matching another server's tool.

Why it matters:

1. A name looks familiar.
2. Its characters differ from the expected name.
3. A tool choice could reach a different server.

How to fix (About 5 minutes for an initial review): Review both tool sources and remove or rename the unexpected lookalike; do not infer intent from spelling alone.

How sure: A confusable-character comparison; it does not establish deliberate spoofing.

see: https://github.com/saagpatel/MCPAudit/blob/main/docs/findings/index.md#mcp017

## MCP018

Your pinned tool may have gained broader access.

What we saw: Permission evidence or served annotations changed relative to the saved pin.

Why it matters:

1. You pinned an earlier tool surface.
2. New metadata suggests broader access or changed hints.
3. The old review may no longer cover its behavior.

How to fix (About 5 minutes for an initial comparison): Review the gained categories and annotation changes. Keep the old pin until you understand and accept the change.

How sure: A comparison with the saved baseline, not proof of compromise. Confirm the baseline's scope and review the specific delta; an intentional update can also trigger this finding.

see: https://github.com/saagpatel/MCPAudit/blob/main/docs/findings/index.md#mcp018

## MCP019

Your pinned tool now contains new instruction-shaped text.

What we saw: The current description contains injection patterns absent from the saved tool description.

Why it matters:

1. You trusted an earlier description.
2. The updated description adds agent-directed text.
3. Your AI could act on instructions you did not approve.

How to fix (About 1 minute to disable; review time varies): Disable the server pending review of the changed description; do not refresh the pin to erase an unexplained delta.

How sure: A comparison with the saved baseline, not proof of compromise. Confirm the baseline's scope and review the specific delta; an intentional update can also trigger this finding. Pattern matches can be false positives.

see: https://github.com/saagpatel/MCPAudit/blob/main/docs/findings/index.md#mcp019

## MCP020

Your pinned server now launches a different command or transport.

What we saw: The launch command or transport differs from the pinned configuration.

Why it matters:

1. You reviewed one launch target.
2. The config now selects another target or transport.
3. Unchanged tool schemas do not establish the same program.

How to fix (About 5 minutes for an initial comparison): Review the current command and transport against the pin; disable an unexpected target before reconnecting.

How sure: A comparison with the saved baseline, not proof of compromise. Confirm the baseline's scope and review the specific delta; an intentional update can also trigger this finding.

see: https://github.com/saagpatel/MCPAudit/blob/main/docs/findings/index.md#mcp020

## MCP021

Your pinned server now launches with different arguments.

What we saw: The launch argument list differs from the pin.

Why it matters:

1. Arguments select packages, paths or options.
2. An update changes those selections.
3. The process could run with different access or code.

How to fix (About 5 minutes for an initial comparison): Review the redacted argument delta and package or path selections before refreshing the pin.

How sure: A comparison with the saved baseline, not proof of compromise. Confirm the baseline's scope and review the specific delta; an intentional update can also trigger this finding.

see: https://github.com/saagpatel/MCPAudit/blob/main/docs/findings/index.md#mcp021

## MCP022

Your pinned server's remote endpoint changed.

What we saw: The configured remote URL differs from the pin.

Why it matters:

1. You trusted one endpoint.
2. The config now routes to another URL.
3. A different service may receive future requests.

How to fix (About 5 minutes for an initial comparison): Confirm the intended endpoint and its owner; restore the reviewed URL or disable the server pending review.

How sure: A comparison with the saved baseline, not proof of compromise. Confirm the baseline's scope and review the specific delta; an intentional update can also trigger this finding.

see: https://github.com/saagpatel/MCPAudit/blob/main/docs/findings/index.md#mcp022

## MCP023

Your pinned server's credential key names changed.

What we saw: Environment or header key names differ from the pin; values are not captured.

Why it matters:

1. Key names describe credential or configuration inputs.
2. The set of inputs changed.
3. The server's access may need a fresh review.

How to fix (About 5 minutes to review key names): Review which key names were added or removed and whether their scope is needed. Do not paste their values into reports.

How sure: A comparison with the saved baseline, not proof of compromise. Confirm the baseline's scope and review the specific delta; an intentional update can also trigger this finding. Key-name equality cannot verify unchanged secret values.

see: https://github.com/saagpatel/MCPAudit/blob/main/docs/findings/index.md#mcp023

## MCP024

Your pinned launch file changed or could not be verified.

What we saw: The local launch artifact's hash differs from its pin, or the configured artifact cannot be hashed.

Why it matters:

1. You pinned a local file's bytes.
2. The file changed or is unavailable to the verifier.
3. The earlier artifact review cannot establish its current identity.

How to fix (About 5 minutes for an initial review): Review the specific changed or unverified artifact. Retain the baseline until a legitimate change is confirmed.

How sure: A comparison with the saved baseline, not proof of compromise. Confirm the baseline's scope and review the specific delta; an intentional update can also trigger this finding. An unavailable hash is missing evidence, not a proven change.

see: https://github.com/saagpatel/MCPAudit/blob/main/docs/findings/index.md#mcp024

## MCP025

Your pinned package's published hash changed or could not be verified.

What we saw: Registry metadata differs from the saved hash for a package version, or metadata could not be retrieved.

Why it matters:

1. You pinned a package version's published hash.
2. The current registry hash differs or is unavailable.
3. Metadata alone cannot establish the expected package bytes.

How to fix (Review time varies; disabling takes about 1 minute): Review the version and published hash delta before trusting it. Keep the pin on an unavailable check; retry verification only deliberately.

How sure: A comparison with the saved baseline, not proof of compromise. Confirm the baseline's scope and review the specific delta; an intentional update can also trigger this finding. Registry metadata is not a byte-level verification.

see: https://github.com/saagpatel/MCPAudit/blob/main/docs/findings/index.md#mcp025

## MCP026

Your package bytes differ from expectations or could not be verified.

What we saw: Downloaded hashes disagree with published or pinned hashes, a distribution changed, or bytes could not be fetched or hashed.

Why it matters:

1. You expect particular bytes for a version.
2. The downloaded bytes differ, or verification is incomplete.
3. Installation would rely on changed or unverified content.

How to fix (Review time varies; disabling takes about 1 minute): Avoid installing an unexplained mismatch. Review per-file evidence and legitimate release changes before refreshing; retain the pin when retrieval fails.

How sure: Byte comparisons establish only the recorded mismatch. New files can be legitimate; unverified downloads establish no mismatch.

see: https://github.com/saagpatel/MCPAudit/blob/main/docs/findings/index.md#mcp026

## MCP027

Your signed pin could not be trusted.

What we saw: The pin signature is invalid, its contents changed after signing, or its signer is not trusted.

Why it matters:

1. You rely on a signed pin as the reviewed tool-surface baseline.
2. MCPAudit could not verify the signature or trusted signer.
3. Drift comparison against this baseline was skipped.

How to fix (About 5 minutes for an initial review): Do not refresh from this pin file. Restore it from backup or review the server and create a new pin.

How sure: The finding establishes a verification failure, not who changed the pin or why.

see: https://github.com/saagpatel/MCPAudit/blob/main/docs/findings/index.md#mcp027

## MCP040

Your server may send data to a destination you did not allow.

What we saw: A fixed outbound destination is outside the configured allowlist.

Why it matters:

1. A tool can send data.
2. Its destination is outside your selected allowlist.
3. Workspace content could reach an unreviewed host.

How to fix (About 5 minutes to review the destination): Review the destination; deliberately add it to --egress-allowlist if trusted, or disable the outbound capability.

How sure: A capability inference from config or served metadata, not an observed operation. Use the finding's confidence and evidence; descriptions and annotations can be inaccurate.

see: https://github.com/saagpatel/MCPAudit/blob/main/docs/findings/index.md#mcp040

## MCP041

Your server may send data to a caller-chosen destination.

What we saw: A URL or host parameter, or a templated host authority, lets callers choose the outbound target.

Why it matters:

1. The caller supplies a destination.
2. The tool may send data there.
3. An attacker-influenced request could choose the recipient.

How to fix (About 1 minute to disable; implementation work varies): Replace caller-selected hosts with a validated fixed destination set, or disable the capability.

How sure: A capability inference from config or served metadata, not an observed operation. Use the finding's confidence and evidence; descriptions and annotations can be inaccurate.

see: https://github.com/saagpatel/MCPAudit/blob/main/docs/findings/index.md#mcp041

## MCP042

Your trusted host may still send data to the wrong account.

What we saw: An allowlisted host has a multi-tenant API or caller-controlled credential input.

Why it matters:

1. The hostname passes the allowlist.
2. An account or credential can still select another recipient.
3. Data could leave your intended tenant boundary.

How to fix (About 10 minutes for an initial account-boundary review): Review tenant, path and account scope; prevent callers from substituting credentials and limit allowed data.

How sure: A capability inference from config or served metadata, not an observed operation. Use the finding's confidence and evidence; descriptions and annotations can be inaccurate.

see: https://github.com/saagpatel/MCPAudit/blob/main/docs/findings/index.md#mcp042

## MCP043

Your tool's declared safety hint conflicts with its metadata.

What we saw: An explicit annotation contradicts capability keyword evidence at medium confidence or better.

Why it matters:

1. A safety hint describes a restricted tool.
2. Other metadata suggests broader behavior.
3. Trusting the hint alone could grant unintended access.

How to fix (About 5 minutes for an initial review): Review the actual implementation and correct the hint or description; disable the disputed capability until resolved.

How sure: A metadata contradiction, not an executed behavior check. Keyword evidence and hints can both be inaccurate.

see: https://github.com/saagpatel/MCPAudit/blob/main/docs/findings/index.md#mcp043

## MCP044

Your server's protocol needs review: legacy http handshake.

What we saw: The HTTP server negotiated a handshake-era protocol.

Why it matters:

1. The connected server supplies protocol metadata.
2. The observed behavior can affect client compatibility or caching.
3. Review the specific evidence before relying on the server's protocol behavior.

How to fix (About 5 minutes for an initial review): Review legacy session behavior; upgrade the server if modern stateless operation is intended.

How sure: An observed protocol advisory; unavailable evidence produces no finding. Low severity does not certify security or full protocol conformance.

see: https://github.com/saagpatel/MCPAudit/blob/main/docs/findings/index.md#mcp044

## MCP045

Your server's protocol needs review: session id minted.

What we saw: An HTTP response included Mcp-Session-Id; its value was withheld.

Why it matters:

1. The connected server supplies protocol metadata.
2. The observed behavior can affect client compatibility or caching.
3. Review the specific evidence before relying on the server's protocol behavior.

How to fix (About 5 minutes for an initial review): Review session handling and avoid relying on session IDs as authorization.

How sure: An observed protocol advisory; unavailable evidence produces no finding. Low severity does not certify security or full protocol conformance.

see: https://github.com/saagpatel/MCPAudit/blob/main/docs/findings/index.md#mcp045

## MCP046

Your server's protocol needs review: deprecated logging capability.

What we saw: A modern server advertised logging (SEP-2577).

Why it matters:

1. The connected server supplies protocol metadata.
2. The observed behavior can affect client compatibility or caching.
3. Review the specific evidence before relying on the server's protocol behavior.

How to fix (About 5 minutes for an initial review): Remove the deprecated logging capability from the modern server advertisement.

How sure: An observed protocol advisory; unavailable evidence produces no finding. Low severity does not certify security or full protocol conformance.

see: https://github.com/saagpatel/MCPAudit/blob/main/docs/findings/index.md#mcp046

## MCP047

Your server's protocol needs review: required cache hints absent.

What we saw: A completed modern response omitted ttlMs or cacheScope (SEP-2549).

Why it matters:

1. The connected server supplies protocol metadata.
2. The observed behavior can affect client compatibility or caching.
3. Review the specific evidence before relying on the server's protocol behavior.

How to fix (About 5 minutes for an initial review): Return explicit ttlMs and cacheScope on every cacheable result.

How sure: An observed protocol advisory; unavailable evidence produces no finding. Low severity does not certify security or full protocol conformance.

see: https://github.com/saagpatel/MCPAudit/blob/main/docs/findings/index.md#mcp047

## MCP048

Your server's protocol needs review: cache scope differs across pages.

What we saw: Pages of one modern listing used different cacheScope values (SEP-2549).

Why it matters:

1. The connected server supplies protocol metadata.
2. The observed behavior can affect client compatibility or caching.
3. Review the specific evidence before relying on the server's protocol behavior.

How to fix (About 5 minutes for an initial review): Return the same cacheScope on every page of the listing.

How sure: An observed protocol advisory; unavailable evidence produces no finding. Low severity does not certify security or full protocol conformance.

see: https://github.com/saagpatel/MCPAudit/blob/main/docs/findings/index.md#mcp048

## MCP049

Your server's protocol needs review: invalid cache ttl.

What we saw: A server returned an invalid ttlMs; the SDK may reject or clamp it.

Why it matters:

1. The connected server supplies protocol metadata.
2. The observed behavior can affect client compatibility or caching.
3. Review the specific evidence before relying on the server's protocol behavior.

How to fix (About 5 minutes for an initial review): Return an integer ttlMs greater than or equal to zero; repeat the incomplete listing.

How sure: An observed protocol advisory; unavailable evidence produces no finding. Low severity does not certify security or full protocol conformance.

see: https://github.com/saagpatel/MCPAudit/blob/main/docs/findings/index.md#mcp049

## MCP050

Your server's protocol needs review: tool order changed.

What we saw: Two completed tool listings changed order without changing membership.

Why it matters:

1. The connected server supplies protocol metadata.
2. The observed behavior can affect client compatibility or caching.
3. Review the specific evidence before relying on the server's protocol behavior.

How to fix (About 5 minutes for an initial review): Return tools in deterministic order to avoid unstable client caches.

How sure: An observed protocol advisory; unavailable evidence produces no finding. Low severity does not certify security or full protocol conformance.

see: https://github.com/saagpatel/MCPAudit/blob/main/docs/findings/index.md#mcp050

## Configuration health

Your server configuration needs review before you connect.

What we saw: A static configuration check found a launch, source, credential-scope or parsing concern.

Why it matters:

1. Your client uses the configured entry.
2. The reported concern can change its reach or reduce audit coverage.
3. Connecting before review may run unintended code or leave part of the config unchecked.

How to fix (About 5 minutes for an initial review): Follow the finding's manual remediation at the named config entry. If intent is unclear, remove that entry temporarily, restart the client, and review the command and source before restoring it.

How sure: A static config check; it does not establish malicious code or an observed incident.

see: https://github.com/saagpatel/MCPAudit/blob/main/docs/findings/index.md#configuration-health
