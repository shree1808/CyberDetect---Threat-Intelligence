import json
import logging
import uuid
from typing import Annotated, Any, Dict, Iterator, List, Optional, Union

from fastapi import FastAPI, HTTPException, Form
from fastapi.middleware.cors import CORSMiddleware
from fastapi.encoders import jsonable_encoder
from fastapi.responses import StreamingResponse
from langgraph.types import Command
from pydantic import BaseModel, StringConstraints
import warnings
warnings.filterwarnings('ignore')

from .dynamic_plugins import graph_builder

logger = logging.getLogger(__name__)
app = FastAPI()

origins = [
    "http://127.0.0.1:8000"
]

app.add_middleware(
    CORSMiddleware,
    allow_origins = origins,
    allow_credentials = True,
    allow_methods = ["*"],
    allow_headers = ["*"]
)

# workflow_id -> compiled graph (each graph owns its checkpointer, so resume finds the paused state).
# In-memory only: swap for a persistent checkpointer + stored blueprint before running >1 worker.
WORKFLOWS: Dict[str, Any] = {}


## MODELS ##
class AgentRequest(BaseModel):
    user_query: Annotated[str, StringConstraints(strip_whitespace=True, min_length=1)]
    workflow_blueprint: List[Dict[str, Any]]      # the same node/edge list graph_builder takes
    # attachments : Optional[Multipart]


class HitlResumeRequest(BaseModel):
    workflow_id: str
    approved: bool
    comment: str = ""


class StateRequest(BaseModel):
    workflow_id: str


class AgentResponse(BaseModel):
    workflow_id: str
    state: Optional[Union[Dict[str, Any], str]] = None


## HELPERS ##
def _config(workflow_id: str) -> Dict[str, Any]:
    return {"configurable": {"thread_id": workflow_id}}


def _get_graph(workflow_id: str):
    graph = WORKFLOWS.get(workflow_id)
    if graph is None:
        raise HTTPException(status_code=404, detail=f"Unknown workflow_id: {workflow_id}")
    return graph


def _sse(event: Dict[str, Any]) -> str:
    # jsonable_encoder handles pydantic models, dataclasses (Interrupt), tuples
    return f"event: {event['stage']}\ndata: {json.dumps(jsonable_encoder(event))}\n\n"


def _stream_response(events: Iterator[str], workflow_id: str) -> StreamingResponse:
    return StreamingResponse(
        events,
        media_type="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no", "X-Workflow-Id": workflow_id},
    )


## STREAMING ##
def sse_client(graph, workflow_id: str, graph_input: Union[Dict[str, Any], Command],
               first_stage: str = "wf_started") -> Iterator[str]:
    """graph_input is {"query": ...} for a new run, or Command(resume=...) for a HITL resume."""
    config = _config(workflow_id)

    yield _sse({
        "stage": first_stage,
        "node": "NA",
        "workflow_id": workflow_id,
        "content": "NA",
    })           

    interrupts = None
    try:
        for chunk in graph.stream(
            graph_input, config, stream_mode=["messages", "updates"],
            version="v2"
        ):
            if chunk["type"] == "messages":
                token, metadata = chunk["data"]
                content = getattr(token, "content", "")
                if content:                      # structured-output calls stream no text
                    yield _sse({
                        "stage": "node_token",
                        "node": metadata.get("langgraph_node"),
                        "content": content,
                    })

            elif chunk["type"] == "updates":
                # v2 chunks are {"type", "ns", "data"}; the node updates live in chunk["data"]
                for source, update in chunk["data"].items():
                    if source == "__interrupt__":
                        interrupts = update      # emitted below, once we know which node is waiting
                    else:
                        yield _sse({
                            "stage": "node_completed",
                            "node": source,
                            "event": update,
                        })
    except Exception as e:
        logger.exception("workflow %s failed", workflow_id)
        yield _sse({"stage": "error", "node": "NA", "workflow_id": workflow_id, "content": str(e)})
        return

    snapshot = graph.get_state(config)
    if snapshot.next:
        yield _sse({
            "stage": "paused",
            "node": snapshot.next[0],
            "workflow_id": workflow_id,
            "event": interrupts or snapshot.interrupts,
        })
    else:
        yield _sse({
            "stage": "workflow_completed",
            "node": "NA",
            "workflow_id": workflow_id,
            "status": "rejected" if snapshot.values.get("status") == "rejected" else "completed",
        })


## ENDPOINTS ##
from fastapi.responses import FileResponse

@app.get("/")
def ui():
    return FileResponse("workflow_builder.html")

@app.post("/cyber-detect/start", response_class=StreamingResponse)
def start(input_request: AgentRequest):
    # build BEFORE streaming so a bad blueprint is a real HTTP 422, not a broken stream
    try:
        graph = graph_builder(input_request.workflow_blueprint)
    except (ValueError, KeyError, TypeError) as e:
        raise HTTPException(status_code=422, detail=f"Invalid workflow blueprint: {e!r}")

    workflow_id = str(uuid.uuid4())
    WORKFLOWS[workflow_id] = graph
    return _stream_response(
        sse_client(graph, workflow_id, {"query": input_request.user_query}),
        workflow_id,
    )


@app.post("/cyber-detect/hitl_resume", response_class=StreamingResponse)
def hitl_resume(payload: HitlResumeRequest):
    graph = _get_graph(payload.workflow_id)
    if not graph.get_state(_config(payload.workflow_id)).interrupts:
        raise HTTPException(status_code=409, detail="Workflow is not waiting for approval")

    resume = Command(resume={"approved": payload.approved, "comment": payload.comment})
    return _stream_response(
        sse_client(graph, payload.workflow_id, resume, first_stage="wf_resumed"),
        payload.workflow_id,
    )


@app.post("/cyber-detect/get_state", response_model=AgentResponse)
def get_state(payload: StateRequest) -> AgentResponse:
    graph = _get_graph(payload.workflow_id)
    snapshot = graph.get_state(_config(payload.workflow_id))

    if snapshot.interrupts:
        workflow_status = "paused"
    elif snapshot.next:
        workflow_status = "running"
    else:
        workflow_status = "completed"

    return AgentResponse(
        workflow_id=payload.workflow_id,
        state={
            "workflow_status": workflow_status,
            "next": list(snapshot.next),
            "pending_interrupts": jsonable_encoder(snapshot.interrupts),
            "values": jsonable_encoder(snapshot.values),
        },
    )