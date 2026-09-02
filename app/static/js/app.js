const $ = (s) => document.querySelector(s);
const $$ = (s) => document.querySelectorAll(s);

let currentLevel = 1;
let currentFilter = "all";
let levelsCache = [];
let progressCurrent = 1;
let nextLevelAfterSolve = null;
let lastHistoryId = null;
let lastPayload = { username: "", password: "" };
let shareLevelMeta = { id: 1, name: "", diff: "easy", epic: "" };
let shareStyle = "1";
const SHARE_REPO = "https://github.com/you-in-you/sqli-playground";
const SHARE_REPO_HOST = "github.com/you-in-you/sqli-playground";

async function api(path, opts = {}) {
  const res = await fetch(path, {
    headers: { "Content-Type": "application/json", ...(opts.headers || {}) },
    ...opts,
  });
  const data = await res.json().catch(() => ({}));
  if (!res.ok) {
    const err = new Error(data.error || res.statusText);
    err.status = res.status;
    err.data = data;
    throw err;
  }
  return data;
}

function getDiffLabel(d) {
  return (d || "easy").toUpperCase();
}

function escapeHtml(s) {
  return String(s)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;");
}

async function loadDashboard() {
  const data = await api("/api/levels");
  levelsCache = data.levels;
  progressCurrent = data.progress.current_level || 1;
  $("#progress-count").textContent = data.progress.solved_count;
  renderLevels();
  await loadSolved();
}

function renderLevels() {
  const grid = $("#levels-grid");
  grid.innerHTML = "";
  const filtered =
    currentFilter === "all"
      ? levelsCache
      : levelsCache.filter((l) => l.diff === currentFilter);

  filtered.forEach((level) => {
    const card = document.createElement("div");
    const isLocked = !level.unlocked && !level.solved;
    const isSolved = !!level.solved;
    const isCurrent = !isLocked && !isSolved && level.id === progressCurrent;
    let cls = "level-card";
    if (isSolved) cls += " solved";
    if (isLocked) cls += " locked";
    if (isCurrent) cls += " current";
    card.className = cls;
    if (level.diff) card.dataset.diff = level.diff;
    card.dataset.id = level.id;

    let statusCode = "200";
    let statusMsg = "OK";
    if (isLocked) {
      statusCode = "403";
      statusMsg = "Access Denied";
    } else if (isSolved) {
      statusCode = "200";
      statusMsg = "OK";
    } else if (isCurrent) {
      statusCode = "202";
      statusMsg = "Found";
    }

    const face = isLocked
      ? ""
      : `<div class="card-face">
        <div class="level-num">LEVEL ${String(level.id).padStart(2, "0")}</div>
        <div class="level-name">${escapeHtml(level.name || "—")}</div>
        <span class="level-diff">${getDiffLabel(level.diff)}</span>
      </div>`;

    // Locked: only status face (dim until hover, same pattern as before)
    if (isLocked) {
      card.innerHTML = `
        <div class="card-status card-status-static">
          <div class="status-code">${statusCode}</div>
          <div class="status-msg">${statusMsg}</div>
        </div>`;
    } else {
      card.innerHTML = `
        ${face}
        <div class="card-status">
          <div class="status-code">${statusCode}</div>
          <div class="status-msg">${statusMsg}</div>
        </div>`;
      card.addEventListener("click", () => openLevel(level.id));
    }
    grid.appendChild(card);
  });
}

async function loadSolved() {
  const data = await api("/api/solved");
  const el = $("#solved-flags");
  if (!data.solved.length) {
    el.innerHTML = `<p class="empty-state">No flags captured yet.</p>`;
    return;
  }
  el.innerHTML = data.solved
    .map(
      (s) => `
    <div class="solved-item" data-level="${s.id}">
      <span class="solved-level">Level ${String(s.id).padStart(2, "0")} — ${s.name}</span>
      <span class="solved-flag">${s.flag}</span>
    </div>`
    )
    .join("");

  el.querySelectorAll(".solved-item").forEach((item) => {
    item.addEventListener("click", () => openHistory(Number(item.dataset.level)));
  });
}

async function openHistory(levelId) {
  const title = $("#history-title");
  const body = $("#history-body");
  title.textContent = `Level ${String(levelId).padStart(2, "0")} — Attack History`;
  body.innerHTML = `<p class="empty-state">Loading...</p>`;
  $("#history-overlay").classList.remove("hidden");

  try {
    const data = await api(`/api/level/${levelId}/history`);
    title.textContent = `${data.name} — Attack History`;
    if (!data.history.length) {
      body.innerHTML = `<p class="empty-state">No attempts recorded for this level.</p>`;
      return;
    }
    body.innerHTML = data.history
      .map((h) => {
        const win = h.is_winning ? `<div class="hist-win-tag">Winning payload</div>` : "";
        const user = escapeHtml(h.username_payload || "");
        const pass = escapeHtml(h.password_payload || "");
        const resp = escapeHtml(h.response_raw || h.response_message || "");
        return `
          <div class="history-item${h.is_winning ? " winning" : ""}">
            ${win}
            <div class="hist-label">Payload</div>
            <div class="hist-payload">user: ${user || "(empty)"}<br>pass: ${pass || "(empty)"}</div>
            <div class="hist-label">Response</div>
            <div class="hist-response">${resp || "(none)"}</div>
          </div>`;
      })
      .join("");
  } catch (e) {
    body.innerHTML = `<p class="empty-state">${escapeHtml(e.message || "Failed")}</p>`;
  }
}

async function openLevel(id) {
  try {
    const meta = await api(`/api/level/${id}`);
    currentLevel = id;
    lastHistoryId = null;
    document.body.dataset.diff = meta.diff || "easy";

    $("#level-badge").textContent = `LEVEL ${String(id).padStart(2, "0")}`;
    $("#level-title").textContent = meta.name;
    $("#level-difficulty").textContent = getDiffLabel(meta.diff);
    $("#level-desc").textContent = meta.desc;
    $("#hint-indirect-text").textContent = meta.hint_i;
    $("#hint-technical-text").textContent = meta.hint_t;
    shareLevelMeta = {
      id,
      name: meta.name || "",
      diff: meta.diff || "easy",
      epic: meta.hint_i || "",
    };
    $("#hint-technical").classList.add("hidden");

    $("#payload-input").value = "";
    $("#payload-pass").value = "";
    $("#response-area").classList.add("hidden");
    $("#response-content").textContent = "";
    $("#flag-input").value = "";
    $("#flag-message").className = "flag-message hidden";

    $("#dashboard").classList.remove("active");
    $("#level-page").classList.add("active");
    window.scrollTo(0, 0);
  } catch (e) {
    if (e.status === 403) alert("403 Access Denied");
    else alert(e.message || "Failed");
  }
}

$("#hint-indirect").addEventListener("click", () => {
  $("#hint-technical").classList.toggle("hidden");
});

$("#btn-send-payload").addEventListener("click", async () => {
  const username = $("#payload-input").value;
  const password = $("#payload-pass").value;
  const area = $("#response-area");
  const content = $("#response-content");
  area.classList.remove("hidden");
  content.textContent = "Executing...";

  try {
    lastPayload = { username, password };
    const res = await api(`/api/level/${currentLevel}/attack`, {
      method: "POST",
      body: JSON.stringify({ username, password }),
    });
    if (res.history_id) lastHistoryId = res.history_id;
    let out = "";
    if (res.message) out += res.message + "\n\n";
    if (res.raw) out += res.raw;
    if (res.error && !res.raw) out += "Error: " + res.error;
    content.textContent = out || JSON.stringify(res, null, 2);
  } catch (e) {
    content.textContent = e.message || "Request failed";
  }
});

$("#btn-submit-flag").addEventListener("click", async () => {
  const flag = $("#flag-input").value.trim();
  const msg = $("#flag-message");
  msg.classList.remove("hidden");

  try {
    const body = { flag };
    if (lastHistoryId) body.history_id = lastHistoryId;
    const res = await api(`/api/level/${currentLevel}/submit`, {
      method: "POST",
      body: JSON.stringify(body),
    });
    if (res.ok) {
      msg.className = "flag-message success";
      msg.textContent = res.message;
      nextLevelAfterSolve = res.next_level;
      setTimeout(() => {
        $("#success-flag-text").textContent = res.flag;
        $("#success-overlay").classList.remove("hidden");
      }, 400);
    } else {
      msg.className = "flag-message error";
      msg.textContent = res.message || "Wrong flag";
    }
  } catch (e) {
    msg.className = "flag-message error";
    msg.textContent = e.message || "Submit failed";
  }
});

$("#flag-input").addEventListener("keydown", (e) => {
  if (e.key === "Enter") $("#btn-submit-flag").click();
});

$("#btn-next-level").addEventListener("click", async () => {
  $("#success-overlay").classList.add("hidden");
  await loadDashboard();
  if (nextLevelAfterSolve && nextLevelAfterSolve <= 60) openLevel(nextLevelAfterSolve);
  else showDashboard();
});

$("#btn-back-dashboard").addEventListener("click", () => {
  $("#success-overlay").classList.add("hidden");
  showDashboard();
});

$("#btn-back").addEventListener("click", () => showDashboard());

$("#btn-close-history").addEventListener("click", () => {
  $("#history-overlay").classList.add("hidden");
});

$("#history-overlay").addEventListener("click", (e) => {
  if (e.target.id === "history-overlay") $("#history-overlay").classList.add("hidden");
});

function showDashboard() {
  $("#level-page").classList.remove("active");
  $("#dashboard").classList.add("active");
  loadDashboard();
}

$$(".tab").forEach((tab) => {
  tab.addEventListener("click", () => {
    $$(".tab").forEach((t) => {
      t.classList.remove("active");
      t.removeAttribute("data-active-diff");
    });
    tab.classList.add("active");
    const filter = tab.dataset.filter;
    currentFilter = filter;
    if (filter && filter !== "all") {
      tab.setAttribute("data-active-diff", filter);
    }
    renderLevels();
  });
});


/* Solved Flags accordion */
const solvedToggle = $("#solved-toggle");
if (solvedToggle) {
  solvedToggle.addEventListener("click", () => {
    const panel = $("#solved-flags");
    const open = solvedToggle.getAttribute("aria-expanded") === "true";
    solvedToggle.setAttribute("aria-expanded", open ? "false" : "true");
    panel.classList.toggle("collapsed", open);
  });
}


function shareGhLink() {
  return `<a class="scard-gh" href="${SHARE_REPO}" target="_blank" rel="noopener noreferrer"><svg width="12" height="12" viewBox="0 0 16 16" aria-hidden="true"><path fill="currentColor" d="M8 0C3.58 0 0 3.58 0 8c0 3.54 2.29 6.53 5.47 7.59.4.07.55-.17.55-.38 0-.19-.01-.82-.01-1.49-2.01.37-2.53-.49-2.69-.94-.09-.23-.48-.94-.82-1.13-.28-.15-.68-.52-.01-.53.63-.01 1.08.58 1.23.82.72 1.21 1.87.87 2.33.66.07-.52.28-.87.51-1.07-1.78-.2-3.64-.89-3.64-3.95 0-.87.31-1.59.82-2.15-.08-.2-.36-1.02.08-2.12 0 0 .67-.21 2.2.82.64-.18 1.32-.27 2-.27.68 0 1.36.09 2 .27 1.53-1.04 2.2-.82 2.2-.82.44 1.1.16 1.92.08 2.12.51.56.82 1.27.82 2.15 0 3.07-1.87 3.75-3.65 3.95.29.25.54.73.54 1.48 0 1.07-.01 1.93-.01 2.2 0 .21.15.46.55.38A8.013 8.013 0 0016 8c0-4.42-3.58-8-8-8z"/></svg> ${SHARE_REPO_HOST}</a>`;
}

function formatSharePayloadHtml(raw) {
  const t = (raw || "").trim() || "—";
  const lines = t.split("\n");
  return lines
    .map((line) => {
      const body = escapeHtml(line);
      return `<span class="scard-sh">$</span><span class="scard-cmd">${body}</span>`;
    })
    .join("<br>");
}

function buildShareCardHtml(style, payload) {
  const id = shareLevelMeta.id;
  const name = escapeHtml(shareLevelMeta.name || "—");
  const diff = getDiffLabel(shareLevelMeta.diff);
  const epic = escapeHtml(shareLevelMeta.epic || "");
  const pl = formatSharePayloadHtml(payload);
  const lvl = String(id).padStart(2, "0");
  const gh = shareGhLink();

  if (style === "2") {
    return `<div class="scard scard-v2" id="share-card-export" data-diff="${(shareLevelMeta.diff || "easy")}">
      <div class="scard-side"><div class="scard-lvl">L${lvl}</div><div class="scard-diff">${diff}</div></div>
      <div class="scard-body">
        <div class="scard-title">${name}</div>
        <div class="scard-epic">${epic}</div>
        <div class="scard-payload">${pl}</div>
        <div class="scard-foot">${gh}</div>
      </div>
    </div>`;
  }
  if (style === "3") {
    return `<div class="scard scard-v3" id="share-card-export" data-diff="${(shareLevelMeta.diff || "easy")}">
      <div class="scard-bar"><div class="scard-dots"><i></i><i></i><i></i></div>${gh}</div>
      <div class="scard-body">
        <div class="scard-line"><span class="g">✓</span> LEVEL ${lvl} CLEARED · ${name}</div>
        <div class="scard-epic">${epic}</div>
        <div class="scard-payload">${pl}</div>
        <div class="scard-line">${diff} · ${id}/60</div>
      </div>
    </div>`;
  }
  if (style === "4") {
    return `<div class="scard scard-v4" id="share-card-export" data-diff="${(shareLevelMeta.diff || "easy")}">
      <div class="scard-head">
        <div class="scard-row1"><div class="scard-lvl">LEVEL ${lvl}</div><div class="scard-cleared">Cleared</div></div>
        <div class="scard-name">${name} · ${diff}</div>
        ${gh}
      </div>
      <div class="scard-body">
        <div class="scard-label">Epic</div>
        <div class="scard-epic">${epic}</div>
        <div class="scard-label">Payload</div>
        <div class="scard-payload">${pl}</div>
      </div>
    </div>`;
  }
  if (style === "5") {
    return `<div class="scard scard-v5" id="share-card-export" data-diff="${(shareLevelMeta.diff || "easy")}">
      <div class="scard-art">
        <div class="scard-ring">✓</div>
        <span class="scard-lvl">LEVEL ${lvl}</span>
        <div class="scard-name">${name}</div>
      </div>
      <div class="scard-body">
        <div class="scard-epic">${epic}</div>
        <div class="scard-payload">${pl}</div>
        <div class="scard-foot">${gh}</div>
      </div>
    </div>`;
  }
  if (style === "6") {
    return `<div class="scard scard-v6" id="share-card-export" data-diff="${(shareLevelMeta.diff || "easy")}">
      <div class="scard-accent"></div>
      <div class="scard-inner">
        <div class="scard-toprow"><div class="scard-lvl">LEVEL ${lvl}</div><span class="scard-cleared">Cleared</span></div>
        <div class="scard-title">${name}</div>
        <div class="scard-epic">${epic}</div>
        <div class="scard-payload">${pl}</div>
        <div class="scard-foot">${gh}</div>
      </div>
    </div>`;
  }
  return `<div class="scard scard-v1" id="share-card-export" data-diff="${(shareLevelMeta.diff || "easy")}">
    <div class="scard-art">
      <div class="scard-lvl">LEVEL ${lvl}</div>
      <div class="scard-sub">Cleared · SQLi Playground</div>
    </div>
    <div class="scard-body">
      <div class="scard-title">${name} — solved</div>
      <div class="scard-epic">${epic}</div>
      <div class="scard-payload">${pl}</div>
      <div class="scard-foot">${gh}</div>
    </div>
  </div>`;
}

function renderSharePreview() {
  const root = $("#share-card-root");
  if (!root) return;
  const payload = $("#share-payload") ? $("#share-payload").value : "";
  root.innerHTML = buildShareCardHtml(shareStyle, payload);
}

function openShareModal() {
  const ta = $("#share-payload");
  let pre = lastPayload.username || "";
  if (lastPayload.password) pre += (pre ? "\n" : "") + lastPayload.password;
  if (ta) ta.value = pre;
  shareStyle = "1";
  $$(".share-style-tab").forEach((t) => t.classList.toggle("active", t.dataset.style === "1"));
  renderSharePreview();
  $("#share-overlay").classList.remove("hidden");
}

function closeShareModal() {
  $("#share-overlay").classList.add("hidden");
}

function shareCaptionText() {
  const id = shareLevelMeta.id;
  const name = shareLevelMeta.name || "level";
  return (
    `Cleared Level ${id} on SQLi Playground — ${name}\n` +
    `${id}/60 · local SQLi CTF lab\n` +
    SHARE_REPO
  );
}

const _btnShareClear = $("#btn-share-clear");
if (_btnShareClear) {
  _btnShareClear.addEventListener("click", () => openShareModal());
}
const _btnCloseShare = $("#btn-close-share");
if (_btnCloseShare) {
  _btnCloseShare.addEventListener("click", () => closeShareModal());
}
const _shareOverlay = $("#share-overlay");
if (_shareOverlay) {
  _shareOverlay.addEventListener("click", (e) => {
    if (e.target.id === "share-overlay") closeShareModal();
  });
}
$$(".share-style-tab").forEach((tab) => {
  tab.addEventListener("click", () => {
    shareStyle = tab.dataset.style || "1";
    $$(".share-style-tab").forEach((t) => t.classList.remove("active"));
    tab.classList.add("active");
    renderSharePreview();
  });
});
const _sharePayload = $("#share-payload");
if (_sharePayload) {
  _sharePayload.addEventListener("input", () => renderSharePreview());
}
const _btnShareCopy = $("#btn-share-copy");
if (_btnShareCopy) {
  _btnShareCopy.addEventListener("click", async () => {
    try {
      await navigator.clipboard.writeText(shareCaptionText());
      _btnShareCopy.textContent = "COPIED";
      setTimeout(() => { _btnShareCopy.textContent = "COPY TEXT"; }, 1200);
    } catch (_) {}
  });
}
const _btnShareDl = $("#btn-share-download");
if (_btnShareDl) {
  _btnShareDl.addEventListener("click", async () => {
    const node = $("#share-card-export");
    if (!node || typeof html2canvas !== "function") {
      alert("Export unavailable");
      return;
    }
    _btnShareDl.textContent = "…";
    try {
      const canvas = await html2canvas(node, {
        backgroundColor: "#0a0a10",
        scale: 2,
        useCORS: true,
      });
      const a = document.createElement("a");
      const id = String(shareLevelMeta.id).padStart(2, "0");
      a.download = `sqli-playground-level-${id}.png`;
      a.href = canvas.toDataURL("image/png");
      a.click();
    } catch (e) {
      console.error(e);
      alert("PNG export failed");
    }
    _btnShareDl.textContent = "DOWNLOAD PNG";
  });
}

loadDashboard()
  .then(() => checkForUpdate())
  .catch((e) => {
    console.error(e);
    $("#levels-grid").innerHTML =
      `<p class="empty-state">Backend not ready. Edit config.json and run setup_db.py</p>`;
  });


/* ── Update check (async, non-blocking) ───────────────────────── */
const UPDATE_DISMISS_KEY = "sqli_update_dismissed";

function dismissUpdateModal(remoteVer) {
  $("#update-overlay").classList.add("hidden");
  if (remoteVer) {
    try {
      sessionStorage.setItem(UPDATE_DISMISS_KEY, String(remoteVer));
    } catch (_) {}
  }
}

function showUpdateModal(data) {
  const remote = data.remote || "";
  try {
    if (sessionStorage.getItem(UPDATE_DISMISS_KEY) === String(remote)) return;
  } catch (_) {}

  $("#update-local").textContent = data.local || "—";
  $("#update-remote").textContent = remote || "—";
  const released = data.released ? `Released ${data.released}` : "";
  $("#update-released").textContent = released;

  const ul = $("#update-changes");
  ul.innerHTML = "";
  (data.changes || []).forEach((item) => {
    const li = document.createElement("li");
    li.textContent = item;
    ul.appendChild(li);
  });

  const notes = data.notes || "";
  $("#update-notes").textContent = notes;
  $("#update-notes").style.display = notes ? "" : "none";

  const repo = data.repo || "https://github.com/you-in-you/sqli-playground";
  $("#btn-update-repo").href = repo;

  $("#update-overlay").classList.remove("hidden");
}

async function checkForUpdate() {
  try {
    const data = await api("/api/version/check");
    if (data && data.update) showUpdateModal(data);
  } catch (_) {
    /* offline / timeout — silent */
  }
}

const _btnCloseUpdate = $("#btn-close-update");
if (_btnCloseUpdate) {
  _btnCloseUpdate.addEventListener("click", () => {
    const remote = $("#update-remote").textContent;
    dismissUpdateModal(remote);
  });
}
const _btnDismissUpdate = $("#btn-dismiss-update");
if (_btnDismissUpdate) {
  _btnDismissUpdate.addEventListener("click", () => {
    const remote = $("#update-remote").textContent;
    dismissUpdateModal(remote);
  });
}
const _updateOverlay = $("#update-overlay");
if (_updateOverlay) {
  _updateOverlay.addEventListener("click", (e) => {
    if (e.target.id === "update-overlay") {
      const remote = $("#update-remote").textContent;
      dismissUpdateModal(remote);
    }
  });
}
