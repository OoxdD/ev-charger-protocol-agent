(() => {
  const $ = (id) => document.getElementById(id);

  const payload = $("payload");
  const fetchHint = $("fetchHint");
  const fetchDeviceNo = $("fetchDeviceNo");
  const fetchStartDate = $("fetchStartDate");
  const fetchStartHour = $("fetchStartHour");
  const fetchStartMinute = $("fetchStartMinute");
  const fetchEndDate = $("fetchEndDate");
  const fetchEndHour = $("fetchEndHour");
  const fetchEndMinute = $("fetchEndMinute");
  const queryBtn = $("queryBtn");
  const parseTextBtn = $("parseTextBtn");
  const clearBtn = $("clearBtn");
  const emptyState = $("emptyState");
  const errorState = $("errorState");
  const resultView = $("resultView");
  const summaryGrid = $("summaryGrid");
  const eventBody = $("eventBody");
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
  const protocolCount = $("protocolCount");

  const REMEMBER_USER_KEY = "evcpa_remember_user";
  const REMEMBER_FLAG_KEY = "evcpa_remember_flag";

  let authEnabled = false;

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
    const username = ((loginUser && loginUser.value) || "").trim();
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
      setDefaultFetchTime();
      await loadProtocolCount();
    } catch (err) {
      showLogin(err.message || String(err));
    } finally {
      if (loginBtn) {
        loginBtn.disabled = false;
        loginBtn.textContent = "登录";
      }
    }
  }

  async function loadProtocolCount() {
    if (!protocolCount) return;
    try {
      const res = await apiFetch("/protocols");
      if (!res.ok) throw new Error("加载失败");
      const list = await res.json();
      protocolCount.textContent = `已支持 ${Array.isArray(list) ? list.length : 0} 种协议`;
    } catch (_) {
      protocolCount.textContent = "协议列表加载失败";
    }
  }

  async function doLogout() {
    try {
      await fetch("/api/logout", { method: "POST", credentials: "same-origin" });
    } catch (_) {
      /* ignore */
    }
    showLogin();
  }

  function showEmpty() {
    if (emptyState) emptyState.hidden = false;
    if (errorState) {
      errorState.hidden = true;
      errorState.textContent = "";
    }
    if (resultView) resultView.hidden = true;
  }

  function showError(msg) {
    if (emptyState) emptyState.hidden = true;
    if (resultView) resultView.hidden = true;
    if (errorState) {
      errorState.hidden = false;
      errorState.textContent = msg || "查询失败";
    }
  }

  function esc(s) {
    return String(s == null ? "" : s)
      .replace(/&/g, "&amp;")
      .replace(/</g, "&lt;")
      .replace(/>/g, "&gt;")
      .replace(/"/g, "&quot;");
  }

  function renderResult(data) {
    const events = Array.isArray(data.events) ? data.events : [];
    const summary = data.summary || {};

    if (data.text && payload) payload.value = data.text;

    if (!events.length) {
      showEmpty();
      if (fetchHint) {
        const count = data.fetch && data.fetch.count;
        fetchHint.textContent = count
          ? `已拉取 ${count} 条报文，未识别到刷卡/VIN 卡号记录。`
          : "未查到卡号记录。可调整时间范围，或粘贴报文后「从文本解析」。";
      }
      return;
    }

    if (emptyState) emptyState.hidden = true;
    if (errorState) errorState.hidden = true;
    if (resultView) resultView.hidden = false;

    if (summaryGrid) {
      summaryGrid.className = "summary-grid compact-5";
      summaryGrid.innerHTML = [
        ["合计", summary.total ?? events.length],
        ["成功", summary.success ?? 0],
        ["失败", summary.failed ?? 0],
        ["刷卡", summary.card_start ?? summary.ic_card ?? 0],
        ["VIN", summary.vin_start ?? summary.vin_card ?? 0],
      ]
        .map(
          ([k, v]) =>
            `<div class="summary-item"><span class="summary-k">${esc(k)}</span><span class="summary-v">${esc(v)}</span></div>`
        )
        .join("");
    }

    if (eventBody) {
      eventBody.innerHTML = events
        .map((e) => {
          const ok = !!e.ok;
          const status = ok
            ? '<span class="pill ok">成功</span>'
            : '<span class="pill fail">失败</span>';
          const card = e.cardNo || e.card_no || "—";
          const cardType = e.card_type || e.start_type || "—";
          const timeText = ((e.swipe_time || e.time || "").slice(0, 19)) || "—";
          const rowClass = ok ? "is-ok" : "is-fail";
          const reasonHtml = ok
            ? ""
            : `<div class="card-event-reason"><span class="card-event-label">原因</span><span>${esc(e.reason || "—")}</span></div>`;
          return `<article class="card-event ${rowClass}">
            <div class="card-event-top">
              ${status}
              <span class="card-event-way">${esc(cardType)}</span>
              <span class="card-event-time mono">${esc(timeText)}</span>
            </div>
            <div class="card-event-no">
              <span class="card-event-label">卡号</span>
              <span class="card-event-value mono" title="${esc(card)}">${esc(card)}</span>
            </div>
            ${reasonHtml}
          </article>`;
        })
        .join("");
    }

    if (fetchHint) {
      const count = data.fetch && data.fetch.count;
      const msg = data.fetch && data.fetch.msg ? `（${data.fetch.msg}）` : "";
      fetchHint.textContent = count != null
        ? `已拉取 ${count} 条报文${msg}，识别到 ${events.length} 条卡号记录。`
        : `识别到 ${events.length} 条卡号记录。`;
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
    const date = dateEl && dateEl.value;
    if (!date) return null;
    const h = Number(hourEl && hourEl.value);
    const m = Number(minuteEl && minuteEl.value);
    if (!Number.isFinite(h) || !Number.isFinite(m)) return null;
    const ms = Date.parse(`${date}T${pad2(h)}:${pad2(m)}:00`);
    if (Number.isNaN(ms)) return null;
    return ms;
  }

  async function queryByDevice() {
    const deviceNo = ((fetchDeviceNo && fetchDeviceNo.value) || "").trim();
    const startMs = toUnixMs(fetchStartDate, fetchStartHour, fetchStartMinute);
    const endMs = toUnixMs(fetchEndDate, fetchEndHour, fetchEndMinute);
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

    queryBtn.disabled = true;
    queryBtn.textContent = "查询中…";
    if (fetchHint) fetchHint.textContent = "正在拉取报文并解析卡号…";
    try {
      const res = await apiFetch("/card-auth-query", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          device_no: deviceNo,
          start_time: startMs,
          end_time: endMs,
        }),
      });
      const data = await res.json().catch(() => ({}));
      if (!res.ok) {
        const detail =
          data.detail != null
            ? typeof data.detail === "string"
              ? data.detail
              : JSON.stringify(data.detail)
            : "查询失败";
        throw new Error(detail);
      }
      renderResult(data);
    } catch (err) {
      showError(err.message || String(err));
      if (fetchHint) fetchHint.textContent = err.message || String(err);
    } finally {
      queryBtn.disabled = false;
      queryBtn.textContent = "查询卡号";
    }
  }

  async function queryByText() {
    const text = (payload && payload.value || "").trim();
    if (!text) {
      if (fetchHint) fetchHint.textContent = "请先粘贴报文文本。";
      return;
    }
    if (parseTextBtn) {
      parseTextBtn.disabled = true;
      parseTextBtn.textContent = "解析中…";
    }
    try {
      const res = await apiFetch("/card-auth-query", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ text }),
      });
      const data = await res.json().catch(() => ({}));
      if (!res.ok) {
        const detail =
          data.detail != null
            ? typeof data.detail === "string"
              ? data.detail
              : JSON.stringify(data.detail)
            : "解析失败";
        throw new Error(detail);
      }
      renderResult(data);
    } catch (err) {
      showError(err.message || String(err));
      if (fetchHint) fetchHint.textContent = err.message || String(err);
    } finally {
      if (parseTextBtn) {
        parseTextBtn.disabled = false;
        parseTextBtn.textContent = "从文本解析";
      }
    }
  }

  if (loginForm) loginForm.addEventListener("submit", doLogin);
  if (logoutBtn) logoutBtn.addEventListener("click", doLogout);
  if (queryBtn) queryBtn.addEventListener("click", queryByDevice);
  if (parseTextBtn) parseTextBtn.addEventListener("click", queryByText);
  if (clearBtn) {
    clearBtn.addEventListener("click", () => {
      if (payload) payload.value = "";
      if (fetchHint) {
        fetchHint.textContent = "将解析刷卡启动与 VIN 启动的卡号；失败会附带原因。";
      }
      showEmpty();
    });
  }

  (async () => {
    loadRememberedUser();
    try {
      const ok = await checkAuth();
      if (ok) {
        setDefaultFetchTime();
        await loadProtocolCount();
      } else fillTimeSelects();
    } catch (err) {
      showLogin(err.message || String(err));
      fillTimeSelects();
    }
    showEmpty();
  })();
})();
