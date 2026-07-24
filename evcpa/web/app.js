(() => {
  const $ = (id) => document.getElementById(id);

  const protocolSel = $("protocol");
  const payload = $("payload");
  const orderFilterInput = $("orderFilter");
  const fileInput = $("file");
  const fileHint = $("fileHint");
  const protocolCount = $("protocolCount");
  const analyzeBtn = $("analyzeBtn");
  const clearBtn = $("clearBtn");
  const copyBtn = $("copyBtn");
  const emptyState = $("emptyState");
  const errorState = $("errorState");
  const resultView = $("resultView");
  const summaryGrid = $("summaryGrid");
  const resultPoints = $("resultPoints");
  const verdictText = $("verdictText");
  const warnBlock = $("warnBlock");
  const warnList = $("warnList");
  const fieldBody = $("fieldBody");
  const candBlock = $("candBlock");
  const candList = $("candList");
  const candTitle = $("candTitle");

  let inputMode = "auto";
  let lastResult = null;

  const DEVICE_FOLLOWUP = "需到设备上核实相关数据，请设备方协助排查。";

  function hasAbnormalResult(data) {
    if (!data) return false;
    if (data.mode === "multi_order_choice") return false;
    if (data.valid === false) return true;
    const warnings = data.warnings || [];
    if (warnings.some((w) => w.level === "error" || w.level === "warn")) return true;
    if (data.extras && data.extras.energy_mismatch) return true;
    return false;
  }

  function withDeviceFollowup(text, data) {
    const base = (text || "").trim();
    if (!hasAbnormalResult(data)) return base;
    if (base.includes("设备上核实") || base.includes("设备方协助")) return base;
    return base ? `${base}\n${DEVICE_FOLLOWUP}` : DEVICE_FOLLOWUP;
  }

  const FIELD_LABELS = {
    start_flag: "起始标志",
    data_length: "数据长度",
    seq: "序列号",
    encrypt_flag: "加密标志",
    frame_type: "帧类型",
    protocol_version: "协议版本",
    body: "消息体",
    body_hex: "消息体十六进制",
    crc16: "帧校验",
    crc16_calc: "计算校验",
    pile_code: "桩编号",
    pile_type: "桩类型",
    gun_count: "充电枪数量",
    gun_no: "枪号",
    gun_status: "枪状态",
    status: "状态",
    trade_no: "交易流水号",
    txn_id: "交易流水号",
    gun_homed: "枪是否归位",
    gun_plugged: "是否插枪",
    output_voltage: "输出电压",
    output_current: "输出电流",
    output_power: "输出功率",
    voltage: "电压",
    current: "电流",
    gun_cable_temp: "枪线温度",
    gun_cable_code: "枪线编码",
    soc: "SOC",
    battery_max_temp: "电池组最高温度",
    charge_time_min: "累计充电时间",
    remain_time_min: "剩余时间",
    charge_energy: "充电度数",
    loss_energy: "计损充电度数",
    charged_amount: "已充金额",
    hardware_fault: "硬件故障",
    start_way: "启动方式",
    vin: "VIN码",
    balance: "账户余额",
    physical_card: "物理卡号",
    logic_card: "逻辑卡号",
    stop_reason: "停止原因",
    raw: "原始数据",
    messageTypeId: "消息类型",
    messageId: "消息ID",
    action: "动作",
    type_id: "类型标识",
    apdu_length: "APDU长度",
    control: "控制域",
    common_address: "公共地址",
    cot: "传送原因",
  };

  function formatFieldName(f) {
    if (f.display_name) return f.display_name;
    if (f.label) return `${f.label}（${f.name}）`;
    const cn = FIELD_LABELS[f.name];
    if (cn) return `${cn}（${f.name}）`;
    if (/[\u4e00-\u9fff]/.test(String(f.name || ""))) return f.name;
    return f.name || "-";
  }

  function formatFieldValue(f) {
    // 例：19.8 A；枚举释义仅在与中文名不同时追加，如「3 充电中」
    let text = fmtValue(f.value);
    if (f.unit) text += ` ${f.unit}`;
    const cn = f.label || FIELD_LABELS[f.name];
    if (f.meaning && (!cn || f.meaning !== cn)) {
      text += ` ${f.meaning}`;
    }
    return text;
  }

  function labelField(name) {
    if (!name) return "-";
    if (FIELD_LABELS[name]) return `${FIELD_LABELS[name]}（${name}）`;
    if (/[\u4e00-\u9fff]/.test(name)) return name;
    return name;
  }

  function fmtValue(v) {
    if (v === null || v === undefined) return "-";
    if (typeof v === "object") return JSON.stringify(v);
    return String(v);
  }

  async function loadProtocols() {
    const res = await fetch("/protocols");
    if (!res.ok) throw new Error("无法加载协议列表");
    const list = await res.json();
    protocolCount.textContent = `已支持 ${list.length} 种协议`;
    for (const p of list) {
      const opt = document.createElement("option");
      opt.value = p.id;
      opt.textContent = `${p.name}（${p.id}）`;
      protocolSel.appendChild(opt);
    }
  }

  function detectPayloadKind(text) {
    const t = text.trim();
    if (!t) return null;
    if (t.startsWith("{") || t.startsWith("[")) return "json";
    return "hex";
  }

  function looksLikeOrderLog(text) {
    const keys = [
      "RemoteCmd",
      "--socInfo:",
      "--chargingInfo:",
      "--recordInfo:",
      "远程启动充电",
      "刷卡启动",
      "刷卡鉴权",
      "VIN验证启动",
      "上报账单",
      "ChargeRecord",
      "ChargingData",
    ];
    let hit = 0;
    for (const k of keys) if (text.includes(k)) hit += 1;
    return hit >= 2 || (text.includes("--socInfo:") && text.includes("--chargingInfo:"));
  }

  function looksLikeProtocolTraceLog(text) {
    const dirHit = (text.match(/【(?:上报|下发)\s*0x[0-9A-Fa-f]{2}】/g) || []).length;
    const tsHit = (text.slice(0, 5000).match(/\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2}/g) || []).length;
    return dirHit >= 2 && tsHit >= 1 && text.includes("68");
  }

  function buildBody() {
    const text = payload.value.trim();
    if (!text) throw new Error("请先输入或导入报文内容");

    const orderFilter = (orderFilterInput && orderFilterInput.value.trim()) || null;
    const filters = {};
    // 合并栏：同一值同时作为服务ID/流水号筛选条件（后端按二者匹配）
    if (orderFilter) {
      filters.service_id = orderFilter;
      filters.trade_no = orderFilter;
    }

    // 平台订单日志：整份文本交给后端抽取充电业务数据
    if (looksLikeOrderLog(text)) {
      return { text, ...filters };
    }
    // 协议抓包日志：按行提取【上报/下发】帧，避免时间戳污染 hex
    if (looksLikeProtocolTraceLog(text)) {
      return { text, protocol: protocolSel.value || null, ...filters };
    }

    const forced = protocolSel.value || null;
    const kind = inputMode === "auto" ? detectPayloadKind(text) : inputMode;
    const body = { protocol: forced, ...filters };

    if (kind === "json") {
      try {
        body.json = JSON.parse(text);
      } catch {
        body.json = text;
      }
    } else {
      body.hex = text;
    }
    return body;
  }

  function showEmpty() {
    emptyState.hidden = false;
    errorState.hidden = true;
    resultView.hidden = true;
    copyBtn.hidden = true;
  }

  function showError(msg) {
    emptyState.hidden = true;
    resultView.hidden = true;
    errorState.hidden = false;
    errorState.textContent = msg;
    copyBtn.hidden = true;
  }

  function showResult(data) {
    lastResult = data;
    emptyState.hidden = true;
    errorState.hidden = true;
    resultView.hidden = false;
    copyBtn.hidden = false;

    const isChoice = data.mode === "multi_order_choice";
    const isCharge = data.mode === "charging_report";
    const isMulti = data.mode === "multi_frame" || (data.extras && data.extras.frame_count > 1);

    if (isChoice || isCharge || data.mode === "multi_frame") {
      const points = data.result_points || [];
      resultPoints.textContent = points.length
        ? points.join("\n")
        : data.summary || data.conclusion || "已生成分析结果";
      verdictText.textContent = isChoice
        ? data.verdict || "该报文有多个订单，请选择并输入服务ID再进行解析"
        : withDeviceFollowup(data.verdict || "", data);

      const pick = (name) => {
        const f = (data.fields || []).find((x) => x.name === name);
        return f ? f.value : "-";
      };
      if (isChoice) {
        summaryGrid.innerHTML = [
          card("订单笔数", pick("订单笔数")),
          card("充电桩", pick("充电桩编号")),
          card("状态", "需选择订单", "bad"),
        ].join("");
      } else if (isCharge) {
        summaryGrid.innerHTML = [
          card("充电桩", pick("充电桩编号")),
          card("枪口", pick("枪口号")),
          card("充电电量", pick("实际充电电量")),
          card("费用合计", pick("费用合计")),
          card("结束原因", pick("设备结束原因")),
          card("状态", data.valid !== false ? "正常" : "需复核", data.valid !== false ? "ok" : "bad"),
        ].join("");
      } else {
        summaryGrid.innerHTML = [
          card("协议", data.protocol_name || data.protocol || "-"),
          card("帧数", String((data.extras && data.extras.frame_count) || (data.fields || []).length)),
          card("类型", data.frame_type_name || "多帧解析"),
          card("校验", data.valid !== false ? "通过" : "异常", data.valid !== false ? "ok" : "bad"),
        ].join("");
      }

      fieldBody.innerHTML = (data.fields || [])
        .map(
          (f) => `<tr>
            <td>${escapeHtml(f.name)}</td>
            <td>${escapeHtml(fmtValue(f.value))}</td>
          </tr>`
        )
        .join("") || `<tr><td colspan="2">无信息</td></tr>`;

      const orders = (data.extras && data.extras.orders) || [];
      if (isChoice && orders.length) {
        candBlock.hidden = false;
        if (candTitle) candTitle.textContent = "点击选择订单（自动填入并重新分析）";
        candList.innerHTML = `<div class="order-pick-list">${orders
          .map((o, i) => {
            const sid = o.service_id || "-";
            const tn = o.trade_no || "-";
            const gun = o.gun != null ? `${o.gun} 枪` : "-";
            const energy = o.energy != null ? `${o.energy} kWh` : "-";
            const money = o.money != null ? `${o.money} 元` : "-";
            return `<button type="button" class="order-pick" data-service-id="${escapeHtml(
              o.service_id || ""
            )}" data-trade-no="${escapeHtml(o.trade_no || "")}">
              <strong>订单 ${o.index || i + 1}</strong>
              <span>服务ID：${escapeHtml(sid)}　流水号：${escapeHtml(tn)}</span>
              <span>枪口：${escapeHtml(gun)}　电量：${escapeHtml(energy)}　费用：${escapeHtml(money)}</span>
            </button>`;
          })
          .join("")}</div>`;
        candList.querySelectorAll(".order-pick").forEach((btn) => {
          btn.addEventListener("click", () => {
            const sid = btn.getAttribute("data-service-id") || "";
            const tn = btn.getAttribute("data-trade-no") || "";
            if (orderFilterInput) orderFilterInput.value = sid || tn;
            analyze();
          });
        });
      } else {
        const frames = (data.extras && data.extras.frames) || [];
        if (frames.length) {
          candBlock.hidden = false;
          if (candTitle) candTitle.textContent = "帧明细";
          candList.innerHTML = frames
            .slice(0, 40)
            .map((fr, i) => {
              const title = escapeHtml(fr.frame_type_name || fr.frame_type || `帧${i + 1}`);
              const ok = fr.valid !== false ? "ok" : "bad";
              return `<div class="cand ${ok}">${i + 1}. ${title}<strong>${fr.valid !== false ? "有效" : "异常"}</strong></div>`;
            })
            .join("");
        } else {
          candBlock.hidden = true;
        }
      }

      const chargeWarnings = data.warnings || [];
      warnBlock.hidden = chargeWarnings.length === 0 && !hasAbnormalResult(data);
      const warnItems = chargeWarnings.map(
        (w) => `<li>[${escapeHtml(w.level || "info")}] ${escapeHtml(w.message || w.code || "")}</li>`
      );
      if (!isChoice && hasAbnormalResult(data)) {
        warnItems.push(`<li class="followup">${escapeHtml(DEVICE_FOLLOWUP)}</li>`);
      }
      warnList.innerHTML = warnItems.join("");
      return;
    }

    // 单帧协议解析
    const conf = Math.round((data.confidence || 0) * 100);
    const valid = data.valid !== false;
    const warnings = data.warnings || [];
    const hasError = warnings.some((w) => w.level === "error");
    resultPoints.textContent = data.summary || data.conclusion || "无摘要";
    if (data.verdict) {
      verdictText.textContent = withDeviceFollowup(data.verdict, data);
    } else if (!valid || hasError) {
      verdictText.textContent = withDeviceFollowup(
        "综合判断：报文存在异常，请结合下方字段与告警核查。",
        data
      );
    } else if (conf >= 70) {
      verdictText.textContent = "综合判断：识别结果可信，报文解析正常。";
    } else {
      verdictText.textContent = "综合判断：已给出解析结果，但置信度偏低，建议人工复核。";
    }

    summaryGrid.innerHTML = [
      card("协议", data.protocol_name || data.protocol || "-"),
      card("置信度", `${conf}%`, conf >= 70 ? "ok" : ""),
      card("帧类型", data.frame_type_name || data.frame_type || "-"),
      card("校验", valid ? "通过" : "异常", valid ? "ok" : "bad"),
    ].join("");

    const showFollowup = hasAbnormalResult(data) || (!valid || hasError);
    warnBlock.hidden = warnings.length === 0 && !showFollowup;
    const warnItems = warnings.map(
      (w) => `<li>[${escapeHtml(w.level || "info")}] ${escapeHtml(w.message || w.code || "")}</li>`
    );
    if (showFollowup) {
      warnItems.push(`<li class="followup">${escapeHtml(DEVICE_FOLLOWUP)}</li>`);
    }
    warnList.innerHTML = warnItems.join("");

    const cands = (data.extras && data.extras.candidates) || [];
    candBlock.hidden = cands.length === 0;
    if (candTitle) candTitle.textContent = "协议候选得分";
    candList.innerHTML = cands
      .slice(0, 12)
      .map(([name, score]) => {
        const pct = Math.round(Number(score) * 100);
        return `<div class="cand">${escapeHtml(String(name))}<strong>${pct}%</strong></div>`;
      })
      .join("");

    fieldBody.innerHTML = (data.fields || []).length
      ? (data.fields || [])
          .map(
            (f) => `<tr>
              <td>${escapeHtml(formatFieldName(f))}</td>
              <td>${escapeHtml(formatFieldValue(f))}</td>
            </tr>`
          )
          .join("")
      : `<tr><td colspan="2">无字段</td></tr>`;
  }

  function card(label, value, cls = "") {
    return `<div class="card"><span class="label">${escapeHtml(label)}</span><div class="value ${cls}">${escapeHtml(String(value))}</div></div>`;
  }

  function escapeHtml(s) {
    return String(s)
      .replaceAll("&", "&amp;")
      .replaceAll("<", "&lt;")
      .replaceAll(">", "&gt;")
      .replaceAll('"', "&quot;");
  }

  async function analyze() {
    analyzeBtn.disabled = true;
    analyzeBtn.textContent = "分析中…";
    try {
      const body = buildBody();
      const res = await fetch("/analyze", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(body),
      });
      const data = await res.json();
      if (!res.ok) {
        throw new Error(data.detail ? JSON.stringify(data.detail) : "分析失败");
      }
      showResult(data);
    } catch (err) {
      showError(err.message || String(err));
    } finally {
      analyzeBtn.disabled = false;
      analyzeBtn.textContent = "开始分析";
    }
  }

  document.querySelectorAll(".tab").forEach((btn) => {
    btn.addEventListener("click", () => {
      document.querySelectorAll(".tab").forEach((b) => b.classList.remove("active"));
      btn.classList.add("active");
      inputMode = btn.dataset.mode;
    });
  });

  fileInput.addEventListener("change", async () => {
    const file = fileInput.files && fileInput.files[0];
    if (!file) return;
    const text = await file.text();
    payload.value = text.trim();
    fileHint.textContent = `已导入：${file.name}（${Math.round(file.size / 1024)} KB）`;
    if (text.trim().startsWith("{") || text.trim().startsWith("[")) {
      document.querySelector('.tab[data-mode="json"]').click();
    } else {
      document.querySelector('.tab[data-mode="hex"]').click();
    }
  });

  clearBtn.addEventListener("click", () => {
    payload.value = "";
    if (orderFilterInput) orderFilterInput.value = "";
    fileInput.value = "";
    fileHint.textContent = "";
    showEmpty();
  });

  copyBtn.addEventListener("click", async () => {
    if (!lastResult) return;
    await navigator.clipboard.writeText(buildShareText(lastResult));
    copyBtn.textContent = "已复制";
    setTimeout(() => (copyBtn.textContent = "分享结果"), 1200);
  });

  function buildShareText(data) {
    if (data.mode === "multi_order_choice" || data.mode === "charging_report") {
      return data.report_text || buildChargingShareText(data);
    }

    const conf = Math.round((data.confidence || 0) * 100);
    const valid = data.valid !== false;
    const warnings = data.warnings || [];
    const errorWarnings = warnings.filter((w) => w.level === "error");

    let verdict = data.verdict;
    if (!verdict) {
      if (!valid || errorWarnings.length) {
        verdict = "综合判断：报文存在异常，请结合下方字段与告警核查。";
      } else if (conf >= 70) {
        verdict = "综合判断：识别结果可信，报文解析正常。";
      } else {
        verdict = "综合判断：已给出解析结果，但置信度偏低，建议人工复核。";
      }
    }
    verdict = withDeviceFollowup(verdict, data);

    const lines = [
      "充电报文分析结果",
      "",
      "【结论】",
      data.conclusion || data.summary || "无摘要",
      verdict,
      "",
      "【基本信息】",
      `协议：${data.protocol_name || data.protocol || "-"}`,
      `置信度：${conf}%`,
      `帧类型：${data.frame_type_name || data.frame_type || "-"}`,
      `通信方向：${formatDirection(data.direction)}`,
      `校验结果：${valid ? "通过" : "异常"}`,
    ];

    const fields = data.fields || [];
    if (fields.length) {
      lines.push("", "【关键字段】");
      for (const f of fields) {
        const name = formatFieldName(f);
        const value = formatFieldValue(f);
        lines.push(`${name}：${value}`);
      }
    }

    if (warnings.length || hasAbnormalResult(data)) {
      lines.push("", "【告警 / 问题】");
      for (const w of warnings) {
        lines.push(`- [${w.level || "info"}] ${w.message || w.code || ""}`);
      }
      if (hasAbnormalResult(data) || !valid || errorWarnings.length) {
        lines.push(`- ${DEVICE_FOLLOWUP}`);
      }
    }

    lines.push("", "（本结果由充电桩报文分析工具生成）");
    return lines.join("\n");
  }

  function buildChargingShareText(data) {
    const lines = [
      "充电订单分析报告",
      "",
      "【结论】",
      data.conclusion || data.summary || "无摘要",
      data.verdict || "",
      "",
    ];

    const groups = [
      {
        title: "【订单信息】",
        names: [
          "充电桩编号",
          "枪口号",
          "订单流水号",
          "手机号",
          "车牌号",
          "启动方式",
          "启动时间",
          "结束时间",
          "充电时长",
          "启动时账户余额",
        ],
      },
      {
        title: "【电气与电量】",
        names: [
          "充电电流（平均）",
          "充电电流（范围）",
          "充电电压（平均）",
          "充电电压（范围）",
          "输出功率（平均）",
          "起始终端表码",
          "结束终端表码",
          "实际充电电量",
          "模块温度（范围）",
        ],
      },
      {
        title: "【分时电量与电价】",
        names: [
          "尖电量",
          "峰电量",
          "平电量",
          "谷电量",
          "尖电价",
          "峰电价",
          "平电价",
          "谷电价",
        ],
      },
      {
        title: "【费用】",
        names: ["电费", "服务费", "占桩费", "费用合计"],
      },
      {
        title: "【停止与占桩】",
        names: ["是否有远程停止指令", "停止原因", "是否占桩计费", "占桩时长"],
      },
    ];

    const fieldMap = {};
    for (const f of data.fields || []) fieldMap[f.name] = f.value;

    for (const g of groups) {
      lines.push(g.title);
      for (const name of g.names) {
        if (fieldMap[name] !== undefined) lines.push(`${name}：${fieldMap[name]}`);
      }
      lines.push("");
    }

    const stageFields = (data.fields || []).filter((f) => String(f.name).startsWith("分时段"));
    if (stageFields.length) {
      lines.push("【分时段明细】");
      for (const f of stageFields) lines.push(`${f.name}：${f.value}`);
      lines.push("");
    }

    lines.push("（本报告依据平台日志中的已解析充电数据生成，可供客户查阅）");
    return lines.join("\n");
  }

  function formatDirection(dir) {
    if (dir === "pile->platform") return "桩 → 平台";
    if (dir === "platform->pile") return "平台 → 桩";
    return "未知";
  }

  analyzeBtn.addEventListener("click", analyze);

  payload.addEventListener("keydown", (e) => {
    if ((e.ctrlKey || e.metaKey) && e.key === "Enter") analyze();
  });

  loadProtocols().catch((err) => {
    protocolCount.textContent = "协议列表加载失败";
    showError(err.message || String(err));
  });
})();
