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
  const downloadPayloadBtn = $("downloadPayloadBtn");
  const downloadReportBtn = $("downloadReportBtn");
  const fetchBtn = $("fetchBtn");
  const fetchHint = $("fetchHint");
  const fetchDeviceNo = $("fetchDeviceNo");
  const fetchService = $("fetchService");
  const fetchStartDate = $("fetchStartDate");
  const fetchStartHour = $("fetchStartHour");
  const fetchStartMinute = $("fetchStartMinute");
  const fetchEndDate = $("fetchEndDate");
  const fetchEndHour = $("fetchEndHour");
  const fetchEndMinute = $("fetchEndMinute");
  const fetchLimit = $("fetchLimit");
  const fetchCmd = $("fetchCmd");
  const fetchDirection = $("fetchDirection");
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
  const loginGate = $("loginGate");
  const mainApp = $("mainApp");
  const loginForm = $("loginForm");
  const loginUser = $("loginUser");
  const loginPass = $("loginPass");
  const loginError = $("loginError");
  const loginBtn = $("loginBtn");
  const loginRemember = $("loginRemember");
  const userBar = $("userBar");
  const userName = $("userName");
  const logoutBtn = $("logoutBtn");

  const REMEMBER_USER_KEY = "evcpa_remember_user";
  const REMEMBER_FLAG_KEY = "evcpa_remember_flag";

  let inputMode = "auto";
  let lastResult = null;
  let authEnabled = false;
  let currentUser = null;

  function loadRememberedUser() {
    try {
      const flag = localStorage.getItem(REMEMBER_FLAG_KEY) === "1";
      const saved = localStorage.getItem(REMEMBER_USER_KEY) || "";
      if (loginRemember) loginRemember.checked = flag;
      if (loginUser && flag && saved) loginUser.value = saved;
    } catch (_) {
      /* ignore */
    }
  }

  function saveRememberedUser(username) {
    try {
      if (loginRemember && loginRemember.checked && username) {
        localStorage.setItem(REMEMBER_FLAG_KEY, "1");
        localStorage.setItem(REMEMBER_USER_KEY, username);
      } else {
        localStorage.removeItem(REMEMBER_FLAG_KEY);
        localStorage.removeItem(REMEMBER_USER_KEY);
      }
    } catch (_) {
      /* ignore */
    }
  }

  async function apiFetch(url, options = {}) {
    const opts = { ...options, credentials: "same-origin" };
    const res = await fetch(url, opts);
    if (res.status === 401 && authEnabled) {
      showLogin("会话已过期，请重新登录");
      throw new Error("未登录或会话已过期");
    }
    return res;
  }

  function showLogin(msg) {
    if (mainApp) {
      mainApp.hidden = true;
      mainApp.setAttribute("aria-hidden", "true");
    }
    if (loginGate) {
      loginGate.hidden = false;
      loginGate.removeAttribute("aria-hidden");
      loginGate.style.display = "";
    }
    if (loginError) {
      if (msg) {
        loginError.hidden = false;
        loginError.textContent = msg;
      } else {
        loginError.hidden = true;
        loginError.textContent = "";
      }
    }
    if (loginPass) loginPass.value = "";
    loadRememberedUser();
    setTimeout(() => {
      if (loginUser && loginUser.value) {
        if (loginPass) loginPass.focus();
      } else if (loginUser) {
        loginUser.focus();
      }
    }, 0);
  }

  function showApp(username) {
    if (loginGate) {
      loginGate.hidden = true;
      loginGate.setAttribute("aria-hidden", "true");
      loginGate.style.display = "none";
    }
    if (mainApp) {
      mainApp.hidden = false;
      mainApp.removeAttribute("aria-hidden");
    }
    currentUser = username || null;
    if (userBar && userName) {
      if (authEnabled && username) {
        userBar.hidden = false;
        userName.textContent = username;
      } else {
        userBar.hidden = true;
        userName.textContent = "";
      }
    }
  }

  async function checkAuth() {
    const res = await fetch("/api/me", { credentials: "same-origin" });
    if (!res.ok) throw new Error("无法检查登录状态");
    const data = await res.json();
    authEnabled = !!data.auth_enabled;
    if (!authEnabled) {
      showApp(null);
      return true;
    }
    if (data.authenticated && data.username) {
      showApp(data.username);
      return true;
    }
    showLogin();
    return false;
  }

  async function doLogin(e) {
    if (e) e.preventDefault();
    const username = (loginUser && loginUser.value || "").trim();
    const password = (loginPass && loginPass.value) || "";
    if (!username || !password) {
      showLogin("请输入用户名和密码");
      return;
    }
    if (loginBtn) {
      loginBtn.disabled = true;
      loginBtn.textContent = "登录中…";
    }
    try {
      const res = await fetch("/api/login", {
        method: "POST",
        credentials: "same-origin",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ username, password }),
      });
      const data = await res.json().catch(() => ({}));
      if (!res.ok) {
        const detail = typeof data.detail === "string" ? data.detail : "用户名或密码错误";
        showLogin(detail);
        return;
      }
      saveRememberedUser(username);
      authEnabled = data.auth_enabled !== false;
      showApp(data.username || username);
      await bootApp();
    } catch (err) {
      showLogin(err.message || String(err));
    } finally {
      if (loginBtn) {
        loginBtn.disabled = false;
        loginBtn.textContent = "登录";
      }
    }
  }

  async function doLogout() {
    try {
      await fetch("/api/logout", { method: "POST", credentials: "same-origin" });
    } catch (_) {
      /* ignore */
    }
    currentUser = null;
    showLogin();
  }

  async function bootApp() {
    setDefaultFetchTime();
    try {
      await loadProtocols();
    } catch (err) {
      protocolCount.textContent = "协议列表加载失败";
      showError(err.message || String(err));
    }
  }

  const DEVICE_FOLLOWUP = "需到设备上核实相关数据，请设备方协助排查。";

  function hasAbnormalResult(data) {
    if (!data) return false;
    if (data.mode === "multi_order_choice") return false;
    if (data.valid === false) return true;
    const ex = data.extras || {};
    if (ex.energy_mismatch || ex.start_mismatch || ex.need_user_confirm) return true;
    const warnings = data.warnings || [];
    // 仅 error，或明确需现场核实的告警；普通 ORDER_FAULT 摘录不自动追加核实文案
    const seriousCodes = new Set([
      "ENERGY_DECREASE",
      "TOU_INACTIVE_CHANGED",
      "START_FAIL",
      "ENERGY_MISMATCH",
      "TOTAL_MISMATCH",
      "TOU_DOM_MISMATCH",
      "METER_MISMATCH",
      "POWER_TIME_MISMATCH",
      "BILL_MISMATCH",
      "ENERGY_SERIES",
      "CRC_FAIL",
      "BAD_START",
      "LEN_MISMATCH",
    ]);
    if (warnings.some((w) => w.level === "error")) return true;
    if (warnings.some((w) => seriousCodes.has(String(w.code || "")))) return true;
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
    requireVoltage: "需求电压",
    requireCurrent: "需求电流",
    need_voltage: "需求电压",
    need_current: "需求电流",
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
    const res = await apiFetch("/protocols");
    if (!res.ok) throw new Error("无法加载协议列表");
    const list = await res.json();
    protocolCount.textContent = `已支持 ${list.length} 种协议`;
    protocolSel.querySelectorAll("option:not([value=''])").forEach((o) => o.remove());
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
    const dirHit = (text.match(/【(?:上报|下发)\s*0x[0-9A-Fa-f]{2,4}】/g) || []).length;
    const cmdHit = (text.match(/\[cmd=(?:0x)?[0-9A-Fa-f]{1,4}\]/gi) || []).length;
    const tsHit = (text.slice(0, 8000).match(/\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2}/g) || []).length;
    const hasFrame = /(?:^|[^0-9A-Fa-f])(68|AAF5|9955BBAA|AABB5599)[0-9A-Fa-f]{6,}/i.test(text);
    if (dirHit >= 2 && tsHit >= 1 && hasFrame) return true;
    if (cmdHit >= 2 && tsHit >= 1 && hasFrame) return true;
    return (dirHit >= 1 || cmdHit >= 1) && hasFrame;
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
    if (downloadReportBtn) downloadReportBtn.hidden = true;
  }

  function showError(msg) {
    emptyState.hidden = true;
    resultView.hidden = true;
    errorState.hidden = false;
    errorState.textContent = msg;
    copyBtn.hidden = true;
    if (downloadReportBtn) downloadReportBtn.hidden = true;
  }

  function showResult(data) {
    lastResult = data;
    emptyState.hidden = true;
    errorState.hidden = true;
    resultView.hidden = false;
    copyBtn.hidden = false;
    if (downloadReportBtn) downloadReportBtn.hidden = false;

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

      const pick = (...names) => {
        for (const name of names) {
          const f = (data.fields || []).find((x) => x.name === name);
          if (f != null && f.value != null && String(f.value) !== "" && String(f.value) !== "-") {
            return f.value;
          }
        }
        return "-";
      };
      if (isChoice) {
        summaryGrid.innerHTML = [
          card("订单笔数", pick("订单笔数")),
          card("充电桩", pick("充电桩编号", "充电桩编码", "设备编号")),
          card("状态", "需选择订单", "bad"),
        ].join("");
      } else if (isCharge) {
        summaryGrid.innerHTML = [
          card("充电桩", pick("充电桩编号", "充电桩编码", "设备编号")),
          card("枪口", pick("枪口号", "枪号")),
          card("充电电量", pick("实际充电电量", "总电量")),
          card("费用合计", pick("费用合计", "充电总费用")),
          card("结束原因", pick("设备结束原因", "停止原因", "结束原因")),
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
      const res = await apiFetch("/analyze", {
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

  function pad2(n) {
    return String(n).padStart(2, "0");
  }

  function fillHourMinuteSelects(hourSel, minuteSel) {
    if (!hourSel || !minuteSel) return;
    if (!hourSel.options.length) {
      for (let h = 0; h < 24; h += 1) {
        const opt = document.createElement("option");
        opt.value = String(h);
        opt.textContent = pad2(h);
        hourSel.appendChild(opt);
      }
    }
    if (!minuteSel.options.length) {
      for (let m = 0; m < 60; m += 1) {
        const opt = document.createElement("option");
        opt.value = String(m);
        opt.textContent = pad2(m);
        minuteSel.appendChild(opt);
      }
    }
  }

  function fillTimeSelects() {
    fillHourMinuteSelects(fetchStartHour, fetchStartMinute);
    fillHourMinuteSelects(fetchEndHour, fetchEndMinute);
  }

  function setDefaultFetchTime() {
    fillTimeSelects();
    const now = new Date();
    const dateStr = `${now.getFullYear()}-${pad2(now.getMonth() + 1)}-${pad2(now.getDate())}`;
    const h = String(now.getHours());
    const m = String(now.getMinutes());
    if (fetchStartDate && !fetchStartDate.value) fetchStartDate.value = dateStr;
    if (fetchStartHour) fetchStartHour.value = h;
    if (fetchStartMinute) fetchStartMinute.value = m;
    if (fetchEndDate && !fetchEndDate.value) fetchEndDate.value = dateStr;
    if (fetchEndHour) fetchEndHour.value = h;
    if (fetchEndMinute) fetchEndMinute.value = m;
  }

  function toUnixMs(dateEl, hourEl, minuteEl) {
    // 日期 + 时 + 分 → 本地毫秒时间戳
    const date = dateEl && dateEl.value;
    if (!date) return null;
    const h = Number(hourEl && hourEl.value);
    const m = Number(minuteEl && minuteEl.value);
    if (!Number.isFinite(h) || !Number.isFinite(m)) return null;
    const ms = Date.parse(`${date}T${pad2(h)}:${pad2(m)}:00`);
    if (Number.isNaN(ms)) return null;
    return ms;
  }

  function toStartTimeUnixMs() {
    return toUnixMs(fetchStartDate, fetchStartHour, fetchStartMinute);
  }

  function toEndTimeUnixMs() {
    return toUnixMs(fetchEndDate, fetchEndHour, fetchEndMinute);
  }

  async function fetchHistoryLogs() {
    if (!fetchBtn) return;
    const deviceNo = (fetchDeviceNo && fetchDeviceNo.value || "").trim();
    const startMs = toStartTimeUnixMs();
    const endMs = toEndTimeUnixMs();
    if (!deviceNo) {
      if (fetchHint) fetchHint.textContent = "请填写设备编号 deviceNo。";
      return;
    }
    if (startMs == null) {
      if (fetchHint) fetchHint.textContent = "请选择开始日期与时刻。";
      return;
    }
    if (endMs == null) {
      if (fetchHint) fetchHint.textContent = "请选择结束日期与时刻。";
      return;
    }
    if (endMs < startMs) {
      if (fetchHint) fetchHint.textContent = "结束时间不能早于开始时间。";
      return;
    }
    const cmd = (fetchCmd && fetchCmd.value || "").trim();
    const dirRaw = fetchDirection && fetchDirection.value;
    const limit = Number((fetchLimit && fetchLimit.value) || 1000);
    const body = {
      device_no: deviceNo,
      start_time: startMs,
      end_time: endMs,
      limit_count: Math.min(15000, Math.max(1, limit || 1000)),
    };
    if (cmd) body.cmd = cmd;
    if (dirRaw !== "" && dirRaw != null) body.is_send_log = Number(dirRaw);

    fetchBtn.disabled = true;
    fetchBtn.textContent = "拉取中…";
    if (fetchHint) fetchHint.textContent = "正在从设备侧拉取历史报文…";
    try {
      const res = await apiFetch("/history-logs", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(body),
      });
      const data = await res.json().catch(() => ({}));
      if (!res.ok) {
        const detail = data.detail != null ? (typeof data.detail === "string" ? data.detail : JSON.stringify(data.detail)) : "拉取失败";
        throw new Error(detail);
      }
      const text = data.text || "";
      payload.value = text;
      document.querySelector('.tab[data-mode="auto"]').click();
      const count = data.count != null ? data.count : 0;
      const msg = data.msg ? `（${data.msg}）` : "";
      if (fetchHint) {
        fetchHint.textContent = count
          ? `已拉取 ${count} 条报文${msg}，已填入下方文本框。确认后点击「开始分析」。`
          : `未查到报文${msg}。请调整设备编号或起止时间后重试。`;
      }
      if (fileHint) fileHint.textContent = count ? `来源：设备历史报文（${count} 条）` : "";
      showEmpty();
    } catch (err) {
      if (fetchHint) fetchHint.textContent = err.message || String(err);
    } finally {
      fetchBtn.disabled = false;
      fetchBtn.textContent = "拉取报文";
    }
  }

  async function fetchServiceLogs() {
    if (!fetchBtn) return;
    const service = (fetchService && fetchService.value || "").trim();
    if (!service) {
      if (fetchHint) fetchHint.textContent = "请填写订单号 / serviceId。";
      return;
    }

    fetchBtn.disabled = true;
    fetchBtn.textContent = "拉取中…";
    if (fetchHint) fetchHint.textContent = "正在按订单拉取报文…";
    try {
      const res = await apiFetch("/service-logs", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ service }),
      });
      const data = await res.json().catch(() => ({}));
      if (!res.ok) {
        const detail = data.detail != null ? (typeof data.detail === "string" ? data.detail : JSON.stringify(data.detail)) : "拉取失败";
        throw new Error(detail);
      }
      const text = data.text || "";
      payload.value = text;
      const sid = data.service_id || data.serviceId || null;
      if (sid && orderFilterInput) {
        orderFilterInput.value = String(sid);
      }
      document.querySelector('.tab[data-mode="auto"]').click();
      const count = data.count != null ? data.count : 0;
      const msg = data.msg ? `（${data.msg}）` : "";
      if (fetchHint) {
        fetchHint.textContent = count
          ? `已拉取 ${count} 条报文${msg}，已填入下方文本框。确认后点击「开始分析」。`
          : `未查到报文${msg}。请核对订单号后重试。`;
      }
      if (fileHint) fileHint.textContent = count ? `来源：订单报文（${service}，${count} 条）` : "";
      showEmpty();
    } catch (err) {
      if (fetchHint) fetchHint.textContent = err.message || String(err);
    } finally {
      fetchBtn.disabled = false;
      fetchBtn.textContent = "拉取报文";
    }
  }

  function onFetchClick() {
    if (fetchService) {
      return fetchServiceLogs();
    }
    return fetchHistoryLogs();
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
    } else if (looksLikeProtocolTraceLog(text) || looksLikeOrderLog(text)) {
      document.querySelector('.tab[data-mode="auto"]').click();
    } else {
      document.querySelector('.tab[data-mode="hex"]').click();
    }
  });

  clearBtn.addEventListener("click", () => {
    payload.value = "";
    if (orderFilterInput) orderFilterInput.value = "";
    if (fetchService) fetchService.value = "";
    fileInput.value = "";
    fileHint.textContent = "";
    if (fetchHint) {
      fetchHint.textContent = fetchService
        ? "输入订单号后拉取，确认内容后再分析。"
        : "拉取后先展示在下方，确认后再分析。";
    }
    showEmpty();
  });

  if (fetchBtn) fetchBtn.addEventListener("click", onFetchClick);
  if (fetchService) {
    fetchService.addEventListener("keydown", (ev) => {
      if (ev.key === "Enter") {
        ev.preventDefault();
        fetchServiceLogs();
      }
    });
  }

  function stampName(prefix, ext) {
    const d = new Date();
    const pad = (n) => String(n).padStart(2, "0");
    const stamp = `${d.getFullYear()}${pad(d.getMonth() + 1)}${pad(d.getDate())}_${pad(d.getHours())}${pad(d.getMinutes())}${pad(d.getSeconds())}`;
    return `${prefix}_${stamp}.${ext}`;
  }

  function downloadTextFile(filename, text) {
    const blob = new Blob([text], { type: "text/plain;charset=utf-8" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = filename;
    document.body.appendChild(a);
    a.click();
    a.remove();
    setTimeout(() => URL.revokeObjectURL(url), 1000);
  }

  function reportFileBase(data) {
    const ex = (data && data.extras) || {};
    const sid = ex.service_id || ex.trade_no || "";
    const device = (fetchDeviceNo && fetchDeviceNo.value || "").trim();
    const tag = String(sid || device || "report").replace(/[^\w\u4e00-\u9fa5-]+/g, "_").slice(0, 40);
    return `解析报告_${tag || "report"}`;
  }

  if (downloadPayloadBtn) {
    downloadPayloadBtn.addEventListener("click", () => {
      const text = (payload.value || "").trim();
      if (!text) {
        const tip = "当前没有可下载的报文内容。";
        if (fetchHint) fetchHint.textContent = tip;
        else if (fileHint) fileHint.textContent = tip;
        return;
      }
      const device = (fetchDeviceNo && fetchDeviceNo.value || "").trim();
      const prefix = device ? `报文_${device}` : "报文";
      downloadTextFile(stampName(prefix, "txt"), text);
      if (fetchHint) fetchHint.textContent = "报文已开始下载。";
      else if (fileHint) fileHint.textContent = "报文已开始下载。";
    });
  }

  if (downloadReportBtn) {
    downloadReportBtn.addEventListener("click", () => {
      if (!lastResult) return;
      const text = buildShareText(lastResult);
      downloadTextFile(stampName(reportFileBase(lastResult), "txt"), text);
    });
  }

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
          "启动结果",
          "启动时间",
          "结束时间",
          "充电时长",
          "SOC",
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
          "需求电流（平均）",
          "需求电流（范围）",
          "需求电压（平均）",
          "需求电压（范围）",
          "输出功率（平均）",
          "起始终端表码",
          "结束终端表码",
          "实际充电电量",
          "模块温度（范围）",
          "功率×时间电量校验",
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

  if (loginForm) loginForm.addEventListener("submit", doLogin);
  if (logoutBtn) logoutBtn.addEventListener("click", doLogout);

  checkAuth()
    .then((ok) => {
      if (ok) return bootApp();
    })
    .catch((err) => {
      showLogin(err.message || String(err));
    });
})();
