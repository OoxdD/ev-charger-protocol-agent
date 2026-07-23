from __future__ import annotations

import json
from typing import Optional

import typer
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from evcpa.agent import ProtocolAgent

app = typer.Typer(add_completion=False, help="新能源充电桩报文分析智能体")
console = Console()


@app.command("protocols")
def list_protocols() -> None:
    """列出已适配协议。"""
    agent = ProtocolAgent()
    table = Table(title="已注册协议")
    table.add_column("ID")
    table.add_column("名称")
    for p in agent.list_protocols():
        table.add_row(p["id"], p["name"])
    console.print(table)


@app.command("analyze")
def analyze(
    hex: Optional[str] = typer.Option(None, "--hex", help="十六进制报文"),
    json_text: Optional[str] = typer.Option(None, "--json", help="JSON 报文文本"),
    file: Optional[str] = typer.Option(None, "--file", "-f", help="从文件读取报文"),
    protocol: Optional[str] = typer.Option(
        None, "--protocol", "-p", help="强制协议 ID，见 `evcpa protocols`"
    ),
    as_json: bool = typer.Option(False, "--as-json", help="以 JSON 输出结果"),
) -> None:
    """分析一条充电桩报文。"""
    agent = ProtocolAgent()
    payload_hex = hex
    payload_json = json_text

    if file:
        content = open(file, "r", encoding="utf-8").read().strip()
        if content.startswith("{") or content.startswith("["):
            payload_json = content
        else:
            payload_hex = content

    if not payload_hex and not payload_json:
        console.print("[red]请提供 --hex / --json / --file[/red]")
        raise typer.Exit(code=2)

    data = agent.analyze_payload(hex_text=payload_hex, json_text=payload_json, protocol=protocol)
    if as_json:
        console.print_json(json.dumps(data, ensure_ascii=False))
        return

    if data.get("mode") in ("charging_report", "multi_frame"):
        lines = [data.get("summary") or data.get("conclusion") or ""]
        if data.get("verdict"):
            lines.append(str(data["verdict"]))
        frames = (data.get("extras") or {}).get("frames") or []
        if frames:
            lines.append("")
            lines.append(f"帧明细（{len(frames)}）:")
            for i, fr in enumerate(frames, 1):
                lines.append(f"  {i}. {fr.get('frame_type_name') or fr.get('frame_type')}: {fr.get('summary')}")
        console.print(Panel("\n".join(lines), title="分析结果", border_style="cyan"))
        return

    # 单帧：还原 AnalysisResult 展示
    result = agent.analyze(hex_text=payload_hex, json_text=payload_json, protocol=protocol)
    console.print(Panel(agent.explain(result), title="分析结果", border_style="cyan"))
    if result.extras.get("candidates"):
        table = Table(title="协议候选得分")
        table.add_column("协议")
        table.add_column("得分")
        for name, score in result.extras["candidates"]:
            table.add_row(name, f"{score:.2f}")
        console.print(table)


@app.command("serve")
def serve(
    host: str = typer.Option("127.0.0.1", "--host"),
    port: int = typer.Option(8080, "--port"),
) -> None:
    """启动可视化分析页面与 HTTP API。"""
    import uvicorn

    console.print(f"[green]可视化页面[/green] http://{host}:{port}/")
    console.print(f"[green]接口文档[/green]   http://{host}:{port}/docs")
    uvicorn.run("evcpa.api:app", host=host, port=port, reload=False)


if __name__ == "__main__":
    app()
