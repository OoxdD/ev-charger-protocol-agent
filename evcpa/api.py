from __future__ import annotations

from pathlib import Path
from typing import Any, Optional

from fastapi import FastAPI
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

from evcpa.agent import ProtocolAgent
from evcpa.order_report import analyze_order_log, looks_like_order_log

agent = ProtocolAgent()
WEB_DIR = Path(__file__).resolve().parent / "web"

app = FastAPI(
    title="充电桩报文分析",
    description="新能源/单车充电桩报文分析智能体",
    version="0.1.0",
)

if WEB_DIR.is_dir():
    app.mount("/static", StaticFiles(directory=WEB_DIR), name="static")


class AnalyzeRequest(BaseModel):
    hex: Optional[str] = Field(None, description="十六进制报文")
    json_payload: Optional[Any] = Field(None, alias="json", description="JSON 对象或字符串")
    text: Optional[str] = Field(None, description="原始文本/平台日志")
    protocol: Optional[str] = Field(None, description="强制协议 id")

    model_config = {"populate_by_name": True}


@app.get("/")
def index() -> FileResponse:
    return FileResponse(
        WEB_DIR / "index.html",
        headers={"Cache-Control": "no-cache, no-store, must-revalidate"},
    )


@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok"}


@app.get("/protocols")
def protocols() -> list[dict[str, str]]:
    return agent.list_protocols()


@app.post("/analyze")
def analyze(req: AnalyzeRequest) -> dict[str, Any]:
    # 优先：运营平台订单日志 → 输出充电业务数据
    blob = req.text
    if not blob and req.hex and looks_like_order_log(req.hex):
        blob = req.hex
    if not blob and isinstance(req.json_payload, str) and looks_like_order_log(req.json_payload):
        blob = req.json_payload
    if blob and looks_like_order_log(blob):
        return analyze_order_log(blob)

    json_text = None
    if req.json_payload is not None:
        if isinstance(req.json_payload, str):
            json_text = req.json_payload
        else:
            import json

            json_text = json.dumps(req.json_payload, ensure_ascii=False)
    result = agent.analyze(hex_text=req.hex, json_text=json_text, protocol=req.protocol)
    return result.to_pretty_dict()
