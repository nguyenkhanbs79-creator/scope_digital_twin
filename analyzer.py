"""Analysis routines for evaluating CI/CD pipeline risks."""
from models import PipelineGraph, Finding, AttackPath
from typing import List, Tuple


def analyze_pipeline(graph: PipelineGraph) -> Tuple[List[Finding], List[AttackPath]]:
    """Analyze the pipeline graph to derive findings and attack paths."""
    raise NotImplementedError()


def compute_risk_score(findings: List[Finding]) -> int:
    """Compute an aggregated risk score based on findings."""
    raise NotImplementedError()


def classify_risk(score: int) -> str:
    """Classify risk level from the aggregated score."""
    raise NotImplementedError()
