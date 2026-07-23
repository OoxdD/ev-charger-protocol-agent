from __future__ import annotations

from enum import Enum
from typing import Any

from pydantic import BaseModel, Field, computed_field


class ProtocolId(str, Enum):
    YKC = "ykc"
    XINGXING = "xingxing"
    SHENGHONG = "shenghong"
    HUAWEI = "huawei"
    INFYPOWER = "infypower"
    OCPP = "ocpp"
    CEC = "cec"
    TELD = "teld"
    SGCC = "sgcc"
    CSG = "csg"
    XIAOJU = "xiaoju"
    AONENG = "aoneng"
    PUTIAN = "putian"
    KEHUA = "kehua"
    KSTAR = "kstar"
    ABB = "abb"
    EVERCHARGE = "evercharge"
    KAMAISI = "kamaisi"
    DAKUYUN = "dakuyun"
    YOUYICHONG = "youyichong"
    IEC104 = "iec104"
    NARI = "nari"
    ZHICHONG = "zhichong"
    ANYUE = "anyue"
    WALLBOX = "wallbox"
    PHOENIX = "phoenix"
    LVTONG = "lvtong"
    ASCII68 = "ascii68"
    UNKNOWN = "unknown"


class FieldItem(BaseModel):
    name: str
    value: Any
    offset: int | None = None
    length: int | None = None
    unit: str | None = None
    label: str | None = None  # 中文名，展示为「中文（name）」
    meaning: str | None = None
    raw: str | None = None

    @computed_field  # type: ignore[prop-decorator]
    @property
    def display_name(self) -> str:
        """页面/报告展示名：输出电流（output_current）。"""
        if self.label:
            return f"{self.label}（{self.name}）"
        return self.name

    def display_value(self) -> str:
        """数值 + 单位，如：19.8 A；枚举释义仅在与中文名不同时追加。"""
        text = "-" if self.value is None else str(self.value)
        if self.unit:
            text = f"{text} {self.unit}"
        if self.meaning and (not self.label or self.meaning != self.label):
            text = f"{text} {self.meaning}"
        return text


class WarningItem(BaseModel):
    code: str
    level: str = "info"  # info | warn | error
    message: str


class AnalysisResult(BaseModel):
    protocol: ProtocolId
    protocol_name: str
    confidence: float = Field(ge=0.0, le=1.0)
    frame_type: str | None = None
    frame_type_name: str | None = None
    direction: str | None = None  # pile->platform | platform->pile | unknown
    valid: bool = True
    summary: str
    fields: list[FieldItem] = Field(default_factory=list)
    warnings: list[WarningItem] = Field(default_factory=list)
    raw_hex: str | None = None
    raw_json: dict[str, Any] | None = None
    extras: dict[str, Any] = Field(default_factory=dict)

    def to_pretty_dict(self) -> dict[str, Any]:
        return self.model_dump(mode="json")
