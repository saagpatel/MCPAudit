from redteam.chains.labeler import label_server
from redteam.surface import ServerSurface, SurfaceAnnotations, SurfaceTool


def test_heuristics_and_deduplication() -> None:
    surface = ServerSurface(
        server_name="synthetic",
        source="fixture",
        tools=[
            SurfaceTool(name="bash", input_schema={"properties": {"command": {"type": "string"}}}),
            SurfaceTool(name="create_file", input_schema={"properties": {"path": {}, "content": {}}}),
            SurfaceTool(name="lookup", description="Fetch content from a URL"),
            SurfaceTool(name="write_file", description="write a file"),
            SurfaceTool(name="send", annotations=SurfaceAnnotations(open_world_hint=True)),
        ],
    )
    labels = label_server(surface)
    lookup = {(label.tool, label.tag): label for label in labels}
    assert lookup["bash", "runs_command"].confidence == "heuristic"
    assert "inputSchema.properties.command" in lookup["bash", "runs_command"].evidence
    assert lookup["create_file", "writes_file"].confidence == "heuristic"
    assert lookup["create_file", "writes_git_config"].confidence == "conditional"
    assert "description" in lookup["lookup", "fetches_url"].evidence
    assert "PermissionAnalyzer" in lookup["send", "fetches_url"].evidence
    assert lookup["write_file", "writes_file"].confidence == "definite"
    assert "PermissionAnalyzer" in lookup["write_file", "writes_file"].evidence
    assert len(lookup) == len(labels)
    assert all(label.confidence != "definite" for label in labels if label.capability == "execute")


def test_real_surface_specific_labels() -> None:
    filesystem = ServerSurface(
        server_name="Filesystem",
        source="fixture",
        tools=[SurfaceTool(name="write_file"), SurfaceTool(name="edit_file")],
    )
    assert {
        (label.tool, label.tag)
        for label in label_server(filesystem)
        if label.tool in {"write_file", "edit_file"}
    } >= {("write_file", "writes_file"), ("edit_file", "writes_file")}

    machine_room = ServerSurface(
        server_name="machine-room",
        source="catalog",
        tools=[SurfaceTool(name="start_job", description="Start a job that runs a command.")],
    )
    job_label = label_server(machine_room)
    assert any(label.tag == "runs_command" and "description" in label.evidence for label in job_label)

    xcode = ServerSurface(
        server_name="xcodebuildmcp",
        source="catalog",
        tools=[SurfaceTool(name="build_project", description="Build the selected project.")],
    )
    assert any(label.tool == "build_project" and label.tag == "runs_build" for label in label_server(xcode))


def test_playwright_browser_code_is_not_host_execution() -> None:
    playwright = ServerSurface(
        server_name="playwright",
        source="catalog",
        tools=[
            SurfaceTool(
                name="browser_run_code",
                description="Run JavaScript in the browser and navigate to the requested URL.",
                input_schema={
                    "properties": {
                        "code": {"description": "run a command in the browser"},
                        "url": {"description": "URL to visit"},
                    }
                },
            )
        ],
    )
    labels = label_server(playwright)
    assert {(label.capability, label.tag) for label in labels} == {
        ("read", "fetches_url"),
        ("execute", "runs_browser_script"),
    }


def test_browser_and_filesystem_labels_override_generic_inference() -> None:
    surface = ServerSurface(
        server_name="synthetic",
        source="fixture",
        tools=[
            SurfaceTool(name="execute_javascript", description="Execute JavaScript in a browser tab."),
            SurfaceTool(name="create_directory", description="Create a directory at a file path."),
            SurfaceTool(name="move_file", description="Move a file to a path."),
        ],
    )
    labels = {(label.tool, label.tag): label for label in label_server(surface)}
    assert ("execute_javascript", "runs_browser_script") in labels
    assert ("execute_javascript", "runs_command") not in labels
    assert ("create_directory", "writes_file") not in labels
    assert ("create_directory", "creates_directory") in labels
    assert "attacker-controlled" in labels["move_file", "writes_file"].evidence
