
import json
from typing import Any, Callable, Dict, List, Literal, Optional, Annotated
from dataclasses import dataclass
from collections import defaultdict, deque

from pydantic import BaseModel, Field
from langgraph.graph import StateGraph, START, END
from langgraph.types import Command, interrupt
from langgraph.checkpoint.memory import InMemorySaver

from .models import (
    ProductRiskAssessmentState, VendorAnalysisReport, CVE_Report, ThreatIntelligenceReport, 
    ComplianceReport, ProductProfile, ProductRiskReport
)

from .factory import (
    chat_openai_client, tavily_client, decide
)


## HELPERS ## 
def _product_label(state: ProductRiskAssessmentState) -> str:
    p = state.product_profile
    return f"{p.vendor} {p.product_name} {p.version}" if p else state.query


def _search(query: str) -> List[Dict[str, str]]:
    res = tavily_client("search").invoke({"query": query})
    items = res.get("results", []) if isinstance(res, dict) else []
    return [{"title": r.get("title", ""), "url": r.get("url", ""),
             "content": (r.get("content") or "")[:600]} for r in items]


def _context(state: ProductRiskAssessmentState, reports: Optional[dict] = None) -> str:
    """Everything upstream plugins produced, whatever the wiring happens to be."""
    profile = state.product_profile.model_dump() if state.product_profile else None
    return json.dumps({"query": state.query, "product_profile": profile,
                       "reports": state.reports if reports is None else reports},
                      indent=2, default=str)


##
@dataclass
class PluginSpec:
    schema: type
    prompt: str
    search: Optional[str] = None            # query template, {product} is filled in
    effort: Literal["low", "medium", "high"] = "low"


def llm_plugin(key: str, spec: PluginSpec) -> Callable:
    def node(state: ProductRiskAssessmentState) -> dict:
        if state.status == "rejected":
            return {}
        label = _product_label(state)
        evidence = _search(spec.search.format(product=label)) if spec.search else []

        llm = chat_openai_client(spec.effort).with_structured_output(spec.schema)
        report = llm.invoke(
            f"{spec.prompt}\n\n"
            f"## Product\n{label}\n\n"
            f"## Context from earlier steps (may be empty)\n{_context(state)}\n\n"
            f"## Search results\n{json.dumps(evidence, indent=2)}\n\n"
            "Rules: use only the search results and context above. "
            "Do not invent identifiers, URLs or dates. If evidence is thin, say so and lower confidence."
        )
        return {
            "reports": {key: report.model_dump()},
            "messages": [{"role": "assistant", "content": f"[{key}] {report.summary}"}],
        }
    return node


SPECS: Dict[str, PluginSpec] = {
    "cve_analysis": PluginSpec(
        schema=CVE_Report,
        search="{product} known vulnerabilities CVE security advisories",
        effort="medium",
        prompt=("You are a vulnerability analyst. List CVEs that appear in the search results for this "
                "product and version, with severity and fixed version if stated. "
                "Only include a CVE ID if it appears in the search results."),
    ),
    "vendor_analysis": PluginSpec(
        schema=VendorAnalysisReport,
        search="{product} vendor security track record breach incidents support lifecycle",
        prompt=("You are a vendor risk analyst. Assess the vendor's reputation, security track record, "
                "and how actively the product is maintained (release cadence, support, ownership changes)."),
    ),
    "compliance": PluginSpec(
        schema=ComplianceReport,
        search="{product} license SOC 2 ISO 27001 compliance certifications",
        prompt=("You are a compliance analyst. Identify the product's license and any security or "
                "compliance certifications. List gaps an enterprise buyer would care about."),
    ),
    "threat_intelligence": PluginSpec(
        schema=ThreatIntelligenceReport,
        search="{product} actively exploited threat actors exploit in the wild",
        effort="medium",
        prompt=("You are a threat intelligence analyst. Determine whether there is evidence of active "
                "exploitation or targeting of this product, and summarise relevant threat notes."),
    ),
}

def product_profile_plugin(key: str) -> Callable:
    def node(state: ProductRiskAssessmentState) -> dict:
        if state.status == "rejected":
            return {}
        effort = decide(
            state.query, "reasoning",
            "How much reasoning effort does it take to extract a product profile from this query?",
            {"low": "Product, vendor and version are clearly stated",
             "medium": "Some details are missing or ambiguous",
             "high": "Query is vague or could match several products"},
            default="low",
        )
        needs_search = decide(
            state.query, "needs_search",
            "Is the query missing details (vendor, version, category, deployment, repository) "
            "that a web search could fill in?",
            {"true": "Details are missing", "false": "All details are already in the query"},
            default="true",
        ) == "true"
        evidence = _search(state.query) if needs_search else []

        profile = chat_openai_client(effort).with_structured_output(ProductProfile).invoke(
            "Produce a Product Profile for the product in the user query.\n"
            "Use only the query and the search results. If a value is unknown, use \"unknown\" "
            "for strings and null for the repository.\n\n"
            f"## User query\n{state.query}\n\n"
            f"## Search results\n{json.dumps(evidence, indent=2)}"
        )
        return {
            "product_profile": profile,
            "messages": [{"role": "assistant",
                          "content": f"[{key}] {profile.vendor} {profile.product_name} {profile.version}"}],
        }
    return node


def risk_aggregator_plugin(key: str) -> Callable:
    def node(state: ProductRiskAssessmentState) -> dict:
        if state.status == "rejected":
            return {}
        # only real analyses (they carry a risk_level); skips approvals and other non-analysis slots
        analyses = {k: v for k, v in state.reports.items()
                    if isinstance(v, dict) and "risk_level" in v}
        if not analyses:
            return {"reports": {key: {"summary": "No upstream analyses to aggregate."}}}

        report = chat_openai_client("medium").with_structured_output(ProductRiskReport).invoke(
            "You are a risk lead. Combine the analyses below into one overall product risk assessment.\n"
            "Base the verdict ONLY on the analyses present; do not assume anything about analyses that "
            "were not run. Fewer analyses means lower confidence. Put the names of the analyses you "
            "used in analyses_considered.\n\n"
            f"## Product\n{_product_label(state)}\n\n"
            f"## Analyses\n{_context(state, analyses)}"
        )
        return {
            "reports": {key: report.model_dump()},
            "messages": [{"role": "assistant", "content": f"[{key}] {report.recommendation}: {report.summary}"}],
        }
    return node


def hitl_plugin(key: str) -> Callable:
    def node(state: ProductRiskAssessmentState) -> dict:
        if state.status == "rejected":
            return {}
        done = ", ".join(state.reports) or "nothing yet"
        # payload shape matches your render_interrupt()
        answer = interrupt({"action_requests": [{
            "description": f"Approve to continue for '{_product_label(state)}'? Completed so far: {done}"
        }]})
        approved = bool(answer.get("approved")) if isinstance(answer, dict) else bool(answer)
        comment = answer.get("comment", "") if isinstance(answer, dict) else ""
        update: dict = {"reports": {key: {"approved": approved, "comment": comment}}}
        if not approved:
            update["status"] = "rejected"      # every later plugin becomes a no-op
        return update
    return node


##
PLUGIN_REGISTRY: Dict[str, Callable[[str], Callable]] = {
    "product_profile": product_profile_plugin,
    "product_risk": risk_aggregator_plugin,
    "hitl_approval": hitl_plugin,
    **{name: (lambda key, s=spec: llm_plugin(key, s)) for name, spec in SPECS.items()},
}


## 
def parse_blueprint(blueprint: List[Dict[str, Any]]):
    routes: Dict[str, str] = {}                 # route id -> plugin name
    edges: List[tuple] = []

    for item in blueprint:
        if "node" in item:
            n = item["node"]
            if n["node_route"] in routes:
                raise ValueError(f"Duplicate node_route: {n['node_route']}")
            if n["node_name"] not in PLUGIN_REGISTRY:
                raise ValueError(f"Unknown plugin: {n['node_name']}")
            routes[n["node_route"]] = n["node_name"]
        elif "edge" in item:
            e = item["edge"]
            kind = e["edge_type"]
            if kind == "fan_out":
                edges += [(e["source"], t) for t in e["targets"]]
            elif kind == "fan_in":
                edges += [(s, e["target"]) for s in e["sources"]]

            elif kind == "next":                # plain A -> B
                edges.append((e["source"], e["target"]))
            else:
                raise ValueError(f"Unknown edge_type: {kind}")
        else:
            raise ValueError(f"Unknown blueprint item: {item}")

    if not routes:
        raise ValueError("Blueprint has no nodes")
    edges = list(dict.fromkeys(edges))          # dedupe, keep order
    for s, t in edges:
        for r in (s, t):
            if r not in routes:
                raise ValueError(f"Edge references unknown node route: {r}")

    # cycle check (Kahn)
    indeg = {r: 0 for r in routes}
    for _, t in edges:
        indeg[t] += 1
    queue = deque(r for r, d in indeg.items() if d == 0)
    seen = 0
    while queue:
        r = queue.popleft()
        seen += 1
        for s, t in edges:
            if s == r:
                indeg[t] -= 1
                if indeg[t] == 0:
                    queue.append(t)
    if seen != len(routes):
        raise ValueError("Blueprint contains a cycle")

    return routes, edges


def graph_builder(blueprint: List[Dict[str, Any]], checkpointer=None):
    routes, edges = parse_blueprint(blueprint)

    # if the same plugin is dropped twice, give each its own report key
    counts: Dict[str, int] = defaultdict(int)
    for name in routes.values():
        counts[name] += 1

    builder = StateGraph(ProductRiskAssessmentState)
    for route, name in routes.items():
        key = name if counts[name] == 1 else f"{name}:{route}"
        builder.add_node(route, PLUGIN_REGISTRY[name](key))

    incoming: Dict[str, List[str]] = defaultdict(list)
    outgoing: Dict[str, List[str]] = defaultdict(list)
    for s, t in edges:
        incoming[t].append(s)
        outgoing[s].append(t)

    for target, sources in incoming.items():
        # a list of sources is a JOIN: target waits for all of them.
        # separate add_edge calls would fire the target once per source.
        builder.add_edge(sources if len(sources) > 1 else sources[0], target)

    for route in routes:
        if route not in incoming:
            builder.add_edge(START, route)
        if route not in outgoing:
            builder.add_edge(route, END)

    return builder.compile(checkpointer=checkpointer or InMemorySaver())

