from typing import Any, Callable, Dict, List, Literal, Optional, Annotated
from dataclasses import dataclass
from collections import defaultdict, deque
from pydantic import BaseModel, Field 
from langgraph.graph.message import add_messages

class ProductProfile(BaseModel):
    product_name : str
    vendor : str
    version : str
    category : Literal["Developer_Tool", "Open_Source"] 
    repository : Optional[str] = None 
    deployment : Literal["Cloud", "On-prem"]

class AnalysisReport(BaseModel):
    summary: str = Field(description="2-3 sentence summary")
    risk_level: Literal["low", "medium", "high", "critical"]
    risk_score: int = Field(description="0 (no risk) to 100 (severe)")
    findings: List[str] = Field(description="Key findings, most important first")
    evidence_urls: List[str] = Field(description="URLs from the search results that support the findings")


class CVEItem(BaseModel):
    cve_id: str
    severity: Literal["low", "medium", "high", "critical", "unknown"]
    summary: str
    fixed_in: Optional[str]


class CVE_Report(AnalysisReport):
    cves: List[CVEItem]


class VendorAnalysisReport(AnalysisReport):
    vendor_reputation: str
    maintenance_health: str


class ComplianceReport(AnalysisReport):
    license: Optional[str]
    certifications: List[str]
    gaps: List[str]


class ThreatIntelligenceReport(AnalysisReport):
    exploited_in_wild: bool
    threat_notes: List[str]


class ProductRiskReport(AnalysisReport):
    key_drivers: List[str]
    recommendation: Literal["approve", "approve_with_conditions", "reject"]
    confidence: Literal["low", "medium", "high"]
    analyses_considered: List[str]

def merge_dicts(a: Optional[dict], b: Optional[dict]) -> dict:
    return {**(a or {}), **(b or {})}


def last_write(a: Any, b: Any) -> Any:
    return b


class ProductRiskAssessmentState(BaseModel):
    query: str
    product_profile: Optional[ProductProfile] = None
    # parallel branches can write here safely: each adds its own key
    reports: Annotated[Dict[str, Any], merge_dicts] = Field(default_factory=dict)
    messages: Annotated[list, add_messages] = Field(default_factory=list)
    status: Annotated[Literal["running", "rejected"], last_write] = "running"
