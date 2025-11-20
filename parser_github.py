"""Parsers for GitHub Actions workflows."""

from pathlib import Path
from typing import Dict, List

import yaml

from models import Edge, Node, PipelineGraph


def parse_github_actions(workflow_path: str) -> PipelineGraph:
    """Parse a GitHub Actions workflow file and produce a pipeline graph representation."""
    workflow_name = Path(workflow_path).name

    nodes: Dict[str, Node] = {
        "code": Node(id="code", type="SourceCode", name="SourceCode"),
        "workflow": Node(id="workflow", type="Workflow", name=workflow_name),
        "runner": Node(id="runner", type="Runner", name="Runner"),
        "secrets": Node(id="secrets", type="Secrets", name="Secrets"),
    }

    edges: List[Edge] = [Edge(source="code", target="workflow")]

    with open(workflow_path, "r", encoding="utf-8") as handle:
        data = yaml.safe_load(handle) or {}

    jobs = data.get("jobs", {}) if isinstance(data, dict) else {}

    for job_name, job_def in jobs.items():
        steps = job_def.get("steps", []) if isinstance(job_def, dict) else []
        if not isinstance(steps, list):
            steps = []

        nodes[job_name] = Node(
            id=job_name,
            type="Job",
            name=job_name,
            metadata={"steps": steps},
        )

        edges.append(Edge(source="runner", target=job_name))
        edges.append(Edge(source="secrets", target=job_name))
        edges.append(Edge(source="workflow", target=job_name))

        if "deploy" in job_name.lower():
            if "deploy_target" not in nodes:
                nodes["deploy_target"] = Node(
                    id="deploy_target",
                    type="DeployTarget",
                    name="DeployTarget",
                )
            edges.append(Edge(source=job_name, target="deploy_target"))

    return PipelineGraph(nodes=nodes, edges=edges)
