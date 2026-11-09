"""Clean filter chain; see Anthropic MCP Git server advisories, Cymulate
EscapeRoute and Snyk toxic flow analysis. Catalog metadata is not verification.
"""

from redteam.chains.templates import Template

TEMPLATE = Template(
    name="git-clean-filter",
    writer_tag="writes_git_config",
    executor_tag="triggers_git_filter",
    artifact=".git/config clean filter and .gitattributes",
    trigger="git add of a matching file",
    writer_actions=("write .git/config clean filter", "write matching .gitattributes"),
    preconditions=("shared filesystem root", "same host and user", "repository exists"),
    automaticity="automatic",
)
