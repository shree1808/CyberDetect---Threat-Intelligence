import requests
import os 
from dotenv import load_dotenv
from typing import Any, Dict, Literal
from langchain_openai import ChatOpenAI
from langchain_tavily import TavilySearch
from langchain_tavily import TavilyCrawl
from langgraph.types import Interrupt
from langchain.messages import AIMessage, AIMessageChunk, AnyMessage, ToolMessage

load_dotenv() 

## 
def chat_openai_client(reasoning : Literal['low', 'medium', 'high']):
    return ChatOpenAI(
        api_key = os.environ['OPENAI_API_KEY'],
        model = "gpt-5-nano",
        reasoning_effort = reasoning,
        max_retries = 5
    )

## 
def decision_client(payload: Dict[str, Any]) -> Dict[str, Any]:
    # fixes: url was a 1-tuple (trailing comma), body was sent as form data,
    # and only 404 was treated as failure
    try:
        resp = requests.post(
            "https://openrouter.ai/api/alpha/decisions",
            headers={
                "Authorization": f"Bearer {os.environ['OPENROUTER_API_KEY']}",
                "Content-Type": "application/json",
            },
            json={**payload, "model": "inception/mercury-decide:free"},
            timeout=30,
        )
    except requests.RequestException as e:
        return {"status": "failed", "message": str(e), "response": None}
    if not resp.ok:
        return {"status": "failed", "message": resp.reason, "response": None}
    return {"status": "success", "response": resp}


## 
def decide(context: str, qid: str, instructions: str,
           options: Dict[str, str], default: str) -> str:
    """Ask the decision model to pick one option; fall back to `default` on any failure."""
    try:
        out = decision_client({
            "state": context,
            "questions": {qid: {"type": "choice",
                                "instructions": instructions,
                                "criteria": options}},
        })
        if out["status"] != "success":
            return default
        choice = out["response"].json()["answers"][qid]["choice"]
        return choice if choice in options else default
    except Exception:
        return default


## 
def tavily_client(type : Literal['search', 'crawl']) -> TavilyCrawl | TavilySearch:
    api_key = os.environ['TAVILY_API_KEY']

    if type == 'search':
        return TavilySearch(
            max_results=5,
            topic="general",
            api_key = api_key
        )

    else:
        raise NotImplementedError
    
##
def render_interrupt(interrupt : Interrupt):
    interrupts= interrupt.value
    for action in interrupts["action_requests"]:
        print(action['description'])

## 
def render_message(token : AIMessageChunk):
    if token.text:
        print(token.text, end = '|')
    if token.tool_call_chunks:
        print(token.tool_call_chunks)