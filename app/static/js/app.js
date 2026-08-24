const $ = (s) => document.querySelector(s);
const $$ = (s) => document.querySelectorAll(s);

let currentLevel = 1;
let currentFilter = "all";
let levelsCache = [];
let nextLevelAfterSolve = null;
let lastHistoryId = null;

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
    card.className = `level-card${level.solved ? " solved" : ""}${isLocked ? " locked" : ""}`;
    if (level.diff) card.dataset.diff = level.diff;
    card.dataset.id = level.id;

    if (isLocked) {
      card.innerHTML = `
        <div class="locked-content">
          <div class="locked-code">403</div>
          <div class="locked-msg">Access Denied</div>
        </div>`;
    } else {
      card.innerHTML = `
        <div class="level-num">LEVEL ${String(level.id).padStart(2, "0")}</div>
        <div class="level-name">${level.name || "—"}</div>
        <span class="level-diff">${getDiffLabel(level.diff)}</span>`;
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

loadDashboard().catch((e) => {
  console.error(e);
  $("#levels-grid").innerHTML =
    `<p class="empty-state">Backend not ready. Edit config.json and run setup_db.py</p>`;
});
