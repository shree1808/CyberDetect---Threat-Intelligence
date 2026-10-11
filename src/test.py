import uuid

from langgraph.types import Command

from .dynamic_plugins import graph_builder
from .factory import render_interrupt, render_message
from langchain.messages import AIMessageChunk

blueprint = [
    {"node": {"node_name": "product_profile", "node_route": "node_001"}},
    {"edge": {"edge_type": "next",    "source": "node_001", "target": "node_002"}},
    {"node": {"node_name": "hitl_approval",   "node_route": "node_002"}},
    {"edge": {"edge_type": "fan_out", "source": "node_002", "targets": ["node_003", "node_004"]}},
    {"node": {"node_name": "cve_analysis",    "node_route": "node_003"}},
    {"node": {"node_name": "vendor_analysis", "node_route": "node_004"}},
    {"edge": {"edge_type": "fan_in",  "sources": ["node_003", "node_004"], "target": "node_005"}},
    {"node": {"node_name": "product_risk",    "node_route": "node_005"}},  # UI attaches this after every fan_in
    {"edge": {"edge_type": "next",    "source": "node_005", "target": "node_006"}},
    {"node": {"node_name": "hitl_approval",   "node_route": "node_006"}},
]

if __name__ == "__main__":
    graph = graph_builder(blueprint)
    config = {"configurable": {"thread_id": str(uuid.uuid4())}}

    def run(inputs):
        for chunk in graph.stream(
            inputs, config, stream_mode=["messages", "updates"],
            version = "v2"
            ):
            if chunk["type"] == "messages":
                token, metadata = chunk["data"]
                if isinstance(token, AIMessageChunk):   
                    render_message(token = token)
            
            if chunk["type"] == "updates":
                for source, update in chunk.items():
                    if source == "__interrupt__":   
                        render_interrupt(update[0])
                    else:
                        print(f"--- {update} done")

    run({"query": "Assess risk of using Terraform 1.9 in our on-prem CI"})

    # two HITL nodes in this blueprint -> keep resuming until the graph has nothing pending
    while graph.get_state(config).next:
        answer = input("Approve? [y/n]: ").strip().lower()
        run(Command(resume={"approved": answer != "n", "comment": ""}))

    values = graph.get_state(config).values
    print("status:", values.get("status", "running"))
    print("reports:", sorted(values["reports"]))
    print(values["reports"].get("product_risk"))