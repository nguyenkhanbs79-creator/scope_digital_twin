"""Analysis routines for evaluating CI/CD pipeline risks."""
import re
from typing import List, Tuple

from models import AttackPath, Finding, PipelineGraph


def analyze_pipeline(graph: PipelineGraph) -> Tuple[List[Finding], List[AttackPath]]:
    """Analyze the pipeline graph to derive findings and attack paths."""
    findings: List[Finding] = []
    attack_paths: List[AttackPath] = []

    job_nodes = [node for node in graph.nodes.values() if node.type == "Job"]

    for job in job_nodes:
        job_id = job.id
        steps = []
        if job.metadata:
            steps = job.metadata.get("steps", []) or []

        for step in steps:
            cmd = step.get("run", "") if isinstance(step, dict) else ""
            if not isinstance(cmd, str):
                cmd = ""

            if _contains_secret_pattern(cmd):
                findings.append(
                    Finding(
                        id=f"{job_id}_secret_exposure",
                        severity="HIGH",
                        title=f"Possible secret exposure in job '{job_id}'",
                        description="Run command appears to expose secrets (hardcoded tokens or credentials).",
                        related_nodes=[job_id],
                        rule_id="SECRET_EXPOSURE",
                    )
                )
                attack_paths.append(
                    AttackPath(
                        id=f"path_{job_id}_secrets",
                        nodes=["code", "workflow", job_id, "secrets"],
                        description=f"Attacker could reach secrets via job '{job_id}' due to exposed secret in run command.",
                    )
                )

            if _contains_dangerous_command(cmd):
                path_nodes = ["code", "workflow", job_id, "runner"]
                if "deploy_target" in graph.nodes:
                    path_nodes.append("deploy_target")

                findings.append(
                    Finding(
                        id=f"{job_id}_dangerous_command",
                        severity="HIGH",
                        title=f"Dangerous command pattern in job '{job_id}'",
                        description="Command uses a potentially dangerous pattern (e.g., curl|bash or wget|sh).",
                        related_nodes=[job_id],
                        rule_id="DANGEROUS_COMMAND",
                    )
                )
                attack_paths.append(
                    AttackPath(
                        id=f"path_{job_id}_runner",
                        nodes=path_nodes,
                        description=f"Attack surface via dangerous command execution in job '{job_id}'.",
                    )
                )

    deploy_jobs = [job.id for job in job_nodes if "deploy" in job.id.lower()]
    test_jobs = [job.id for job in job_nodes if "test" in job.id.lower()]

    if deploy_jobs and not test_jobs:
        primary_deploy = deploy_jobs[0]
        path_nodes = ["code", "workflow", primary_deploy]
        if "deploy_target" in graph.nodes:
            path_nodes.append("deploy_target")

        findings.append(
            Finding(
                id="weak_pipeline_design",
                severity="MEDIUM",
                title="Deploy without explicit test job",
                description="Pipeline contains deployment jobs without dedicated testing stages, increasing release risk.",
                related_nodes=deploy_jobs,
                rule_id="WEAK_PIPELINE_DESIGN",
            )
        )
        attack_paths.append(
            AttackPath(
                id="path_weak_pipeline",
                nodes=path_nodes,
                description="Deployment path lacks preceding explicit tests, reducing assurance before release.",
            )
        )

    return findings, attack_paths


def compute_risk_score(findings: List[Finding]) -> int:
    """Compute an aggregated risk score based on findings."""
    severity_scores = {"HIGH": 30, "MEDIUM": 15, "LOW": 5}
    total = sum(severity_scores.get(finding.severity, 0) for finding in findings)
    return min(total, 100)


def classify_risk(score: int) -> str:
    """Classify risk level from the aggregated score."""
    if score <= 30:
        return "LOW"
    if score <= 70:
        return "MEDIUM"
    return "HIGH"


def _contains_secret_pattern(cmd: str) -> bool:
    """Check if command string likely exposes secrets."""
    lowered = cmd.lower()
    if "api_key=" in cmd or "TOKEN=" in cmd or "password=" in lowered:
        return True
    return bool(re.search(r"[A-Za-z0-9]{20,}", cmd))


def _contains_dangerous_command(cmd: str) -> bool:
    """Detect dangerous download-and-execute command patterns."""
    lowered = cmd.lower()
    return ("curl" in lowered and "bash" in lowered) or ("wget" in lowered and "sh" in lowered)
