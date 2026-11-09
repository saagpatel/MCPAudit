"""A written project script can run when a build tool builds the project."""

from redteam.chains.templates import Template

TEMPLATE = Template(
    name="write-then-build",
    writer_tag="writes_file",
    executor_tag="runs_build",
    artifact="a build script or Run Script phase in a project under a shared root",
    trigger="the build tool builds the project",
    preconditions=("shared project root", "the build tool processes project scripts"),
    automaticity="user_action",
)
