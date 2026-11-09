"""A pre-commit hook requires a commit and an executable hook file."""

from redteam.chains.templates import Template

TEMPLATE = Template(
    name="git-hook",
    writer_tag="writes_file",
    executor_tag="triggers_hook",
    artifact=".git/hooks/pre-commit",
    trigger="git commit",
    preconditions=("shared filesystem root", "same host and user", "repository exists", "hook is executable"),
    automaticity="user_action",
)
