from redteam.chains.labeler import label_server
from redteam.surface import ServerSurface, SurfaceAnnotations, SurfaceConfig, SurfaceTool


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
                        "code": {"description": "JavaScript to run in the browser"},
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


def test_playwright_identity_cannot_suppress_host_tool_labels() -> None:
    surface = ServerSurface(
        server_name="synthetic-playwright-wrapper",
        source="catalog",
        provenance="unverified catalog note mentioning Playwright",
        tools=[SurfaceTool(name="run_command"), SurfaceTool(name="write_file")],
    )

    labels = {(label.tool, label.tag) for label in label_server(surface)}

    assert ("run_command", "runs_command") in labels
    assert ("write_file", "writes_file") in labels
    assert ("run_command", "fetches_url") not in labels
    assert ("write_file", "fetches_url") not in labels


def test_playwright_name_with_host_tools_keeps_unknown_provenance_irrelevant() -> None:
    surface = ServerSurface(
        server_name="playwright",
        source="catalog",
        config=SurfaceConfig(command="uvx", args=["synthetic-wrapper"]),
        provenance="Playwright is mentioned in untrusted provenance",
        tools=[SurfaceTool(name="run_command"), SurfaceTool(name="write_file")],
    )

    labels = {(label.tool, label.tag) for label in label_server(surface)}

    assert ("run_command", "runs_command") in labels
    assert ("write_file", "writes_file") in labels


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


def test_browser_prefix_does_not_hide_host_or_file_capabilities() -> None:
    from redteam.chains.pairs import ConfiguredServer, pair_servers

    browser = ServerSurface(
        server_name="browser",
        source="fixture",
        tools=[
            SurfaceTool(
                name="browser_execute_command", description="Execute an arbitrary shell command on the host"
            ),
            SurfaceTool(name="browser_save_file", description="Write a local file to a path"),
        ],
    )
    writer = ServerSurface(server_name="writer", source="fixture", tools=[SurfaceTool(name="write_file")])
    labels = {(label.tool, label.tag) for label in label_server(browser)}
    assert ("browser_execute_command", "runs_command") in labels
    assert ("browser_save_file", "writes_file") in labels
    chains = pair_servers([ConfiguredServer("writer", writer), ConfiguredServer("browser", browser)])
    assert any(
        chain.template.name == "write-then-run" and chain.executor_label.tool == "browser_execute_command"
        for chain in chains
    )


def test_browser_page_scripts_and_mixed_host_evidence() -> None:
    surface = ServerSurface(
        server_name="browser",
        source="fixture",
        tools=[
            SurfaceTool(
                name="execute_javascript", description="Execute JavaScript in the current browser tab"
            ),
            SurfaceTool(name="browser_evaluate", description="Evaluate JavaScript in the page"),
            SurfaceTool(
                name="browser_run", description="Run JavaScript in a page or execute a host shell command"
            ),
        ],
    )
    labels = {(label.tool, label.tag) for label in label_server(surface)}
    for name in ("execute_javascript", "browser_evaluate"):
        assert (name, "runs_browser_script") in labels
        assert (name, "runs_command") not in labels
    assert ("browser_run", "runs_command") in labels


def test_xcode_build_name_does_not_suppress_file_write() -> None:
    surface = ServerSurface(
        server_name="xcodebuildmcp",
        source="fixture",
        tools=[SurfaceTool(name="build_project", description="Write a file to a path and build the project")],
    )
    labels = {(label.tool, label.tag) for label in label_server(surface)}
    assert ("build_project", "runs_build") in labels
    assert ("build_project", "writes_file") in labels
