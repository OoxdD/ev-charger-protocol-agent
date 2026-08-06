from __future__ import annotations

from pathlib import Path
from typing import Any, Optional

from fastapi import FastAPI, HTTPException, Response
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

from evcpa.agent import ProtocolAgent
from evcpa.auth import (
    OptionalUser,
    RequireUser,
    auth_enabled,
    clear_session_cookie,
    set_session_cookie,
    verify_password,
)
from evcpa.card_query import extract_card_auth_events, summarize_card_auth
from evcpa.history_logs import fetch_device_history_logs, logs_to_text
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
    service_id: Optional[str] = Field(None, description="服务ID(service_Id)，可选，用于多订单筛选")
    trade_no: Optional[str] = Field(None, description="流水号(tradeNo)，可选，用于多订单筛选")

    model_config = {"populate_by_name": True}


class HistoryLogsRequest(BaseModel):
    device_no: str = Field(..., description="设备编号 deviceNo")
    start_time: int = Field(..., description="开始时间戳（毫秒）；上游查询会再往前 1 分钟")
    end_time: int = Field(..., description="结束时间戳（毫秒）；上游查询会再往后 3 分钟")
    cmd: Optional[str] = Field(None, description="报文命令，可选")
    is_send_log: Optional[int] = Field(None, description="1=只查下行，0=上行，不传=全部")
    sort_type: Optional[int] = Field(1, description="排序，默认1正序，<0倒序")


class LoginRequest(BaseModel):
    username: str = Field(..., min_length=1)
    password: str = Field(..., min_length=1)


class CardAuthQueryRequest(BaseModel):
    device_no: Optional[str] = Field(None, description="设备编号；与 text 二选一，优先拉取设备报文")
    start_time: Optional[int] = Field(None, description="开始时间戳（毫秒）")
    end_time: Optional[int] = Field(None, description="结束时间戳（毫秒）")
    cmd: Optional[str] = Field(None, description="报文命令，可选")
    is_send_log: Optional[int] = Field(None, description="1=只查下行，0=上行，不传=全部")
    sort_type: Optional[int] = Field(1, description="排序，默认1正序")
    text: Optional[str] = Field(None, description="直接粘贴的平台日志文本（不拉设备时使用）")


@app.get("/")
def index() -> FileResponse:
    return FileResponse(
        WEB_DIR / "index.html",
        headers={"Cache-Control": "no-cache, no-store, must-revalidate"},
    )


@app.get("/cards")
def cards_page() -> FileResponse:
    return FileResponse(
        WEB_DIR / "cards.html",
        headers={"Cache-Control": "no-cache, no-store, must-revalidate"},
    )


@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok"}


@app.get("/api/me")
def me(user: OptionalUser) -> dict[str, Any]:
    enabled = auth_enabled()
    if not enabled:
        return {"authenticated": True, "username": None, "auth_enabled": False}
    return {
        "authenticated": bool(user),
        "username": user,
        "auth_enabled": True,
    }


@app.post("/api/login")
def login(req: LoginRequest, response: Response) -> dict[str, Any]:
    if not auth_enabled():
        return {"ok": True, "auth_enabled": False, "username": None}
    username = req.username.strip()
    if not verify_password(username, req.password):
        raise HTTPException(status_code=401, detail="用户名或密码错误")
    set_session_cookie(response, username)
    return {"ok": True, "auth_enabled": True, "username": username}


@app.post("/api/logout")
def logout(response: Response) -> dict[str, bool]:
    clear_session_cookie(response)
    return {"ok": True}


@app.get("/protocols")
def protocols(_user: RequireUser) -> list[dict[str, str]]:
    return agent.list_protocols()


@app.post("/history-logs")
def history_logs(req: HistoryLogsRequest, _user: RequireUser) -> dict[str, Any]:
    """代理拉取设备历史报文，拼成文本供页面展示；不自动分析。"""
    try:
        remote = fetch_device_history_logs(
            device_no=req.device_no,
            start_time=req.start_time,
            end_time=req.end_time,
            cmd=req.cmd,
            is_send_log=req.is_send_log,
            sort_type=req.sort_type,
        )
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e)) from e
    except RuntimeError as e:
        raise HTTPException(status_code=502, detail=str(e)) from e

    code = remote.get("code")
    msg = remote.get("msg")
    items = remote.get("data")
    if not isinstance(items, list):
        items = []
    text = logs_to_text(items)
    # 对接方成功码常见为 1 / 0 / 200
    ok = code in (0, "0", 1, "1", 200, "200", None) or bool(items)
    return {
        "ok": bool(ok),
        "code": code,
        "msg": msg,
        "count": len(items),
        "logs": items,
        "text": text,
    }


@app.post("/card-auth-query")
def card_auth_query(req: CardAuthQueryRequest, _user: RequireUser) -> dict[str, Any]:
    """拉取或解析设备报文，提取刷卡/VIN 启动卡号及失败原因。"""
    text = (req.text or "").strip()
    fetch_meta: dict[str, Any] = {}

    device_no = (req.device_no or "").strip()
    if device_no:
        if req.start_time is None or req.end_time is None:
            raise HTTPException(status_code=400, detail="拉取设备报文时需提供 start_time 与 end_time")
        try:
            remote = fetch_device_history_logs(
                device_no=device_no,
                start_time=req.start_time,
                end_time=req.end_time,
                cmd=req.cmd,
                is_send_log=req.is_send_log,
                sort_type=req.sort_type,
            )
        except ValueError as e:
            raise HTTPException(status_code=400, detail=str(e)) from e
        except RuntimeError as e:
            raise HTTPException(status_code=502, detail=str(e)) from e

        code = remote.get("code")
        msg = remote.get("msg")
        items = remote.get("data")
        if not isinstance(items, list):
            items = []
        text = logs_to_text(items)
        ok = code in (0, "0", 1, "1", 200, "200", None) or bool(items)
        fetch_meta = {
            "ok": bool(ok),
            "code": code,
            "msg": msg,
            "count": len(items),
        }

    if not text:
        return {
            "ok": True,
            "events": [],
            "summary": summarize_card_auth([]),
            "text": "",
            "fetch": fetch_meta or None,
        }

    events = extract_card_auth_events(text)
    return {
        "ok": True,
        "events": events,
        "summary": summarize_card_auth(events),
        "text": text,
        "fetch": fetch_meta or None,
    }


@app.post("/analyze")
def analyze(req: AnalyzeRequest, _user: RequireUser) -> dict[str, Any]:
    # 优先：运营平台订单日志 → 输出充电业务数据
    blob = req.text
    if not blob and req.hex and looks_like_order_log(req.hex):
        blob = req.hex
    if not blob and isinstance(req.json_payload, str) and looks_like_order_log(req.json_payload):
        blob = req.json_payload
    if blob and looks_like_order_log(blob):
        return analyze_order_log(
            blob, service_id=req.service_id, trade_no=req.trade_no
        )

    json_text = None
    if req.json_payload is not None:
        if isinstance(req.json_payload, str):
            json_text = req.json_payload
        else:
            import json

            json_text = json.dumps(req.json_payload, ensure_ascii=False)

    # 协议抓包日志（含【上报/下发】）走 text；纯 hex 走 hex
    from evcpa.protocol_log import looks_like_protocol_trace_log

    text_blob = req.text
    hex_blob = req.hex
    if hex_blob and looks_like_protocol_trace_log(hex_blob):
        text_blob = hex_blob
        hex_blob = None

    return agent.analyze_payload(
        hex_text=hex_blob,
        json_text=json_text,
        text=text_blob,
        protocol=req.protocol,
        service_id=req.service_id,
        trade_no=req.trade_no,
    )
