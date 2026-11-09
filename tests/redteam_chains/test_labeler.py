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
