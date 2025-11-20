"""Parsers for GitHub Actions workflows."""
from models import PipelineGraph


def parse_github_actions(workflow_path: str) -> PipelineGraph:
    """Parse a GitHub Actions workflow file and produce a pipeline graph representation."""
    raise NotImplementedError()
