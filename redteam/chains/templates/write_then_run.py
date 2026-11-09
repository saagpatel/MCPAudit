"""Write-then-run chain; Snyk toxic flow analysis is a method reference."""

from redteam.chains.templates import Template

TEMPLATE = Template(
    name="write-then-run",
    writer_tag="writes_file",
    executor_tag="runs_command",
    artifact="a script file written into a shared path",
    trigger="the run tool executes the written script",
    preconditions=("shared path scope", "the run tool accepts an arbitrary path or command"),
    automaticity="user_action",
)
