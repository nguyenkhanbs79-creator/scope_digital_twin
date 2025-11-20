"""Data models for the CI/CD digital twin project."""
from dataclasses import dataclass
from typing import Optional, Dict, List


@dataclass
class Node:
    """Represents an entity in the CI/CD pipeline graph."""
    id: str
    type: str
    name: str
    metadata: Optional[Dict[str, object]] = None


@dataclass
class Edge:
    """Represents a relationship between two nodes in the graph."""
    source: str
    target: str
    label: Optional[str] = None


@dataclass
class PipelineGraph:
    """Container for nodes and edges describing the pipeline structure."""
    nodes: Dict[str, Node]
    edges: List[Edge]


@dataclass
class Finding:
    """Security finding detected in the pipeline analysis."""
    id: str
    severity: str
    title: str
    description: str
    related_nodes: List[str]
    rule_id: Optional[str] = None


@dataclass
class AttackPath:
    """Sequence of nodes representing a potential attack path."""
    id: str
    nodes: List[str]
    description: str
