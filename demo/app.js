/* SQLi Playground — static live demo (no backend)
 * Level 01 interactive mock · 02–60 visual only
 */

const $ = (s) => document.querySelector(s);
const $$ = (s) => document.querySelectorAll(s);

const DEMO_FLAG = "CTF{sql1_l01_demo_flag}";
const SHARE_REPO = "https://github.com/you-in-you/sqli-playground";
const SHARE_REPO_HOST = "github.com/you-in-you/sqli-playground";
const STORAGE_KEY = "sqli_demo_progress_v2";

const NAMES = {
  1: "Auth Bypass", 2: "No Comments", 3: "Numeric Bypass", 4: "Column Count",
  5: "UNION Types", 6: "Schema under Filter", 7: "Constrained Schema", 8: "Error-Based",
  9: "IF Extraction", 10: "Boolean Proof", 11: "Budget Search", 12: "ORD / SUBSTRING",
  13: "Time + Proof", 14: "Time Threshold", 15: "Blacklist Bypass", 16: "Typed UNION",
  17: "UNION under LIMIT", 18: "Second-Order", 19: "Cookie Injection", 20: "Header Injection",
  21: "JSON Field SQLi", 22: "Time under Filter", 23: "ORDER BY Injection", 24: "HAVING Injection",
  25: "Stacked Queries", 26: "Side-Channel Surface", 27: "Keyword WAF", 28: "Double Encoding",
  29: "Numeric Tricks", 30: "Inline Comments", 31: "Boolean Channel", 32: "Filtered Time",
  33: "Second-Order II", 34: "Regex WAF", 35: "Silent Result", 36: "INSERT Injection",
  37: "UPDATE Injection", 38: "LIMIT Injection", 39: "Partial Prepared", 40: "Quote Stripping",
  41: "Dual Fields", 42: "OR Chain", 43: "Blind on Secrets", 44: "Layered Filters",
  45: "Conditional Error", 46: "WAF Obfuscation", 47: "Stacked + DML Filter", 48: "No UNION Word",
  49: "No Spaces", 50: "No Comment Syntax", 51: "Blind under WAF", 52: "Clean Extraction",
  53: "No Quotes (Numeric)", 54: "Bit Channel", 55: "Second-Order Chain", 56: "Comment-Split Keywords",
  57: "Open Surface", 58: "Login Surface", 59: "Strict Charset", 60: "Final Gate",
};

const LEVEL_META = {
  1: {
    name: "Auth Bypass",
    diff: "easy",
    desc: "A login form concatenates your input into SQL. Bypass authentication and surface the flag.",
    hint_i: "Bypass login and become admin.",
    hint_t: "Classic quote break: admin'-- or OR 1=1. UNION SELECT can also pull secrets.",
  },
};

function getDiff(id) {
  if (id <= 15) return "easy";
  if (id <= 30) return "medium";
  if (id <= 45) return "hard";
  if (id <= 55) return "expert";
  return "insane";
}

function getMeta(id) {
  if (LEVEL_META[id]) return LEVEL_META[id];
  return {
    name: NAMES[id] || `Level ${id}`,
    diff: getDiff(id),
    desc: "UI preview only in this demo. Run the full lab locally for real SQLi.",
    hint_i: "The full story waits in the local lab.",
    hint_t: "Clone the repo and use ./run.sh for interactive levels.",
  };
}

function getDiffLabel(d) {
  return (d || "easy").toUpperCase();
}

const DIFF_STICKERS = {
  easy: ":)",
  medium: ":|",
  hard: ":(",
  expert: ">:)",
  insane: "X_X",
};

function setDifficultyTag(diff) {
  const el = $("#level-difficulty");
  if (!el) return;
  const d = (diff || "easy").toLowerCase();
  const label = getDiffLabel(d);
  const sticker = DIFF_STICKERS[d] || ":)";
  el.innerHTML =
    '<span class="diff-text">' + label + '</span>' +
    '<span class="diff-sticker" aria-hidden="true">' + sticker + '</span>';
}

function escapeHtml(s) {
  return String(s)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;");
}

function loadProgress() {
  try {
    const raw = localStorage.getItem(STORAGE_KEY);
    if (!raw) return { solved: [], current: 1, attempts: {}, history: {} };
    const data = JSON.parse(raw);
    return {
      solved: Array.isArray(data.solved) ? data.solved.map(Number) : [],
      current: Number(data.current) || 1,
      attempts: data.attempts && typeof data.attempts === "object" ? data.attempts : {},
      history: data.history && typeof data.history === "object" ? data.history : {},
    };
  } catch {
    return { solved: [], current: 1, attempts: {}, history: {} };
  }
}

function saveProgress(p) {
  const data = p || progress;
  localStorage.setItem(STORAGE_KEY, JSON.stringify({
    solved: data.solved || [],
    current: data.current || 1,
    attempts: data.attempts || {},
    history: data.history || {},
  }));
}

let progress = loadProgress();
let currentLevel = 1;
let currentFilter = "all";
let levelsCache = [];
let lastPayload = { username: "", password: "" };
let shareLevelMeta = { id: 1, name: "", diff: "easy", epic: "" };
let shareStyle = "1";

function buildLevelsCache() {
  const solved = new Set(progress.solved);
  levelsCache = [];
  for (let i = 1; i <= 60; i++) {
    const unlocked = i <= progress.current || solved.has(i);
    const meta = getMeta(i);
    levelsCache.push({
      id: i,
      name: meta.name,
      diff: meta.diff,
      unlocked,
      solved: solved.has(i),
    });
  }
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
    const isCurrent = !isLocked && !isSolved && level.id === progress.current;
    let cls = "level-card";
    if (isSolved) cls += " solved";
    if (isLocked) cls += " locked";
    if (isCurrent) cls += " current";
    card.className = cls;
    card.dataset.diff = level.diff;
    card.dataset.id = level.id;

    let statusCode = "200";
    let statusMsg = "OK";
    if (isLocked) {
      statusCode = "403";
      statusMsg = "Access Denied";
    } else if (isCurrent) {
      statusCode = "202";
      statusMsg = "Accepted";
    }

    if (isLocked) {
      card.innerHTML = `
        <div class="card-status card-status-static">
          <div class="status-code">${statusCode}</div>
          <div class="status-msg">${statusMsg}</div>
        </div>`;
    } else {
      card.innerHTML = `
        <div class="card-face">
          <div class="level-num">LEVEL ${String(level.id).padStart(2, "0")}</div>
          <div class="level-name">${escapeHtml(level.name || "—")}</div>
          <span class="level-diff">${getDiffLabel(level.diff)}</span>
        </div>
        <div class="card-status">
          <div class="status-code">${statusCode}</div>
          <div class="status-msg">${statusMsg}</div>
        </div>`;
      card.addEventListener("click", () => openLevel(level.id));
    }
    grid.appendChild(card);
  });
}

function renderSolved() {
  const el = $("#solved-flags");
  const solvedIds = progress.solved.slice().sort((a, b) => a - b);
  if (!solvedIds.length) {
    el.innerHTML = `<p class="empty-state">No flags captured yet.</p>`;
    return;
  }
  el.innerHTML = solvedIds
    .map((id) => {
      const meta = getMeta(id);
      const flag = id === 1 ? DEMO_FLAG : `CTF{demo_l${String(id).padStart(2, "0")}}`;
      const n = Number((progress.attempts || {})[String(id)]) || 0;
      const attemptsLabel = n === 1 ? "1 payload tested" : `${n} payloads tested`;
      return `<div class="solved-item" data-level="${id}" data-diff="${meta.diff || "easy"}">
        <div class="solved-left">
          <span class="solved-level">Level ${String(id).padStart(2, "0")} — ${escapeHtml(meta.name)}</span>
          <span class="solved-attempts">${attemptsLabel}</span>
        </div>
        <span class="solved-flag">${escapeHtml(flag)}</span>
      </div>`;
    })
    .join("");
  el.querySelectorAll(".solved-item").forEach((item) => {
    item.addEventListener("click", () => openHistory(Number(item.dataset.level)));
  });
}

function openHistory(levelId) {
  const overlay = document.getElementById("history-overlay");
  const title = document.getElementById("history-title");
  const body = document.getElementById("history-body");
  if (!overlay || !title || !body) return;

  const meta = getMeta(levelId);
  title.textContent = (meta.name || ("Level " + levelId)) + " — Attack History";
  body.innerHTML = '<p class="empty-state">Loading...</p>';
  overlay.classList.remove("hidden");

  const list = (progress.history && progress.history[String(levelId)]) || [];
  if (!list.length) {
    body.innerHTML = '<p class="empty-state">No attempts recorded for this level.</p>';
    return;
  }
  const total = list.length;
  let html = '<p class="history-meta">' + total + " attempt" + (total === 1 ? "" : "s") + " recorded</p>";
  list.forEach(function (h, i) {
    const user = escapeHtml(h.username_payload || "");
    const pass = escapeHtml(h.password_payload || "");
    const resp = escapeHtml(h.response_raw || h.response_message || "");
    const time = h.created_at ? escapeHtml(String(h.created_at)) : "";
    const win = h.is_winning === 1 || h.is_winning === true || h.is_winning === "1";
    const ok = h.ok === 1 || h.ok === true || h.ok === "1";
    let badges = "";
    if (win) badges += '<span class="hist-win-tag">Winning</span>';
    badges += ok ? '<span class="hist-ok-tag">OK</span>' : '<span class="hist-fail-tag">Fail</span>';
    if (time) badges += '<span class="hist-time">' + time + "</span>";
    html +=
      '<div class="history-item' + (win ? " winning" : "") + '">' +
        '<div class="hist-head">' +
          '<span class="hist-idx">Attempt ' + (i + 1) + " / " + total + "</span>" +
          '<div class="hist-badges">' + badges + "</div>" +
        "</div>" +
        '<div class="hist-label">Payload</div>' +
        '<div class="hist-payload">' +
          "<div><span class=\"hist-k\">username</span> <span class=\"hist-v\">" + (user || "(empty)") + "</span></div>" +
          "<div><span class=\"hist-k\">password</span> <span class=\"hist-v\">" + (pass || "(empty)") + "</span></div>" +
        "</div>" +
        '<div class="hist-label">Response</div>' +
        '<div class="hist-response">' + (resp || "(none)") + "</div>" +
      "</div>";
  });
  body.innerHTML = html;
}

function loadDashboard() {
  buildLevelsCache();
  $("#progress-count").textContent = String(progress.solved.length);
  renderLevels();
  renderSolved();
}

function openLevel(id) {
  const meta = getMeta(id);
  const unlocked = id <= progress.current || progress.solved.includes(id);
  if (!unlocked) {
    alert("403 Access Denied");
    return;
  }
  currentLevel = id;
  document.body.dataset.diff = meta.diff || "easy";
  shareLevelMeta = { id, name: meta.name, diff: meta.diff, epic: meta.hint_i || "" };

  $("#level-badge").textContent = `LEVEL ${String(id).padStart(2, "0")}`;
  const titleEl = $("#level-title");
  titleEl.textContent = meta.name;
  titleEl.setAttribute("data-text", meta.name || "—");
  setDifficultyTag(meta.diff);
    updateBugLink(id, meta.name, meta.diff);
  const _fr = document.querySelector(".flag-row");
  if (_fr) _fr.classList.remove("flag-open");
  $("#level-desc").textContent = meta.desc || "One shot. Make it count.";
  $("#hint-indirect-text").textContent = meta.hint_i || "";
  $("#hint-technical-text").textContent = meta.hint_t || "";
  const swap = $("#hint-swap");
  if (swap) swap.classList.remove("open");
  if (typeof window.lockHintHeight === "function") {
    requestAnimationFrame(() => window.lockHintHeight());
  }

  const demoOnly = id !== 1;
  $("#demo-only-note").classList.toggle("hidden", !demoOnly);
  $("#btn-send-payload").disabled = demoOnly;
  $("#payload-input").disabled = demoOnly;
  $("#payload-pass").disabled = demoOnly;
  $("#btn-submit-flag").disabled = demoOnly;
  $("#flag-input").disabled = demoOnly;

  $("#payload-input").value = "";
  $("#payload-pass").value = "";
  $("#response-area").classList.add("hidden");
  $("#response-content").textContent = "";
  $("#flag-input").value = "";
  $("#flag-message").className = "flag-message hidden";

  $("#dashboard").classList.remove("active");
  $("#level-page").classList.add("active");
  window.scrollTo(0, 0);
}

function mockAttack(username, password) {
  const u = username || "";
  const inj = /('|--|#|\/\*|\bor\b|\bunion\b|\bselect\b)/i.test(u + " " + password);
  if (inj) {
    return {
      ok: true,
      message: "Login bypassed (demo). Flag is in the secrets table — try UNION or read the response.",
      raw: `Result: [{user:'admin', role:'admin'}, {user:'flag', role:'${DEMO_FLAG}'}]`,
    };
  }
  if (u === "admin" && password === "admin") {
    return { ok: true, message: "Logged in as admin (no flag here).", raw: "Result: [{user:'admin'}]" };
  }
  return { ok: false, message: "Invalid credentials.", raw: "Result: (empty)" };
}

$("#btn-back").addEventListener("click", () => {
  $("#level-page").classList.remove("active");
  $("#dashboard").classList.add("active");
  loadDashboard();
});

/* hint-swap handled below */

$("#btn-send-payload").addEventListener("click", () => {
  if (currentLevel !== 1) return;
  const username = $("#payload-input").value;
  const password = $("#payload-pass").value;
  lastPayload = { username, password };
  if (!progress.attempts) progress.attempts = {};
  progress.attempts[String(currentLevel)] = (Number(progress.attempts[String(currentLevel)]) || 0) + 1;
  const res = mockAttack(username, password);
  if (!progress.history) progress.history = {};
  const key = String(currentLevel);
  if (!Array.isArray(progress.history[key])) progress.history[key] = [];
  progress.history[key].push({
    username_payload: username,
    password_payload: password,
    response_message: res.message || "",
    response_raw: res.raw || "",
    ok: res.ok ? 1 : 0,
    is_winning: 0,
    created_at: new Date().toISOString().replace("T", " ").slice(0, 19),
  });
  saveProgress();
  const area = $("#response-area");
  const content = $("#response-content");
  area.classList.remove("hidden");
  area.classList.remove("scan", "booting");
  void area.offsetWidth;
  area.classList.add("booting", "scan");
  const lines = [];
  if (res.message) lines.push(res.message);
  if (res.raw) lines.push(res.raw);
  content.innerHTML = lines.map((t) => `<div class="resp-line">${escapeHtml(t)}</div>`).join("");
  setTimeout(() => area.classList.remove("scan", "booting"), 800);
  const btn = $("#btn-send-payload");
  btn.classList.remove("fired");
  void btn.offsetWidth;
  btn.classList.add("fired");
  setTimeout(() => btn.classList.remove("fired"), 500);
});

$("#btn-submit-flag").addEventListener("click", () => {
  const sb = $("#btn-submit-flag");
  if (sb) {
    sb.classList.remove("fired");
    void sb.offsetWidth;
    sb.classList.add("fired");
    setTimeout(() => sb.classList.remove("fired"), 500);
  }

  if (currentLevel !== 1) return;
  const flag = ($("#flag-input").value || "").trim();
  const msg = $("#flag-message");
  if (flag === DEMO_FLAG) {
    if (!progress.solved.includes(1)) progress.solved.push(1);
    progress.current = Math.max(progress.current, 2);
    // mark last attempt as winning if any
    if (!progress.history) progress.history = {};
    const arr = progress.history["1"] || [];
    if (arr.length) {
      arr.forEach((h) => { h.is_winning = 0; });
      arr[arr.length - 1].is_winning = 1;
      arr[arr.length - 1].ok = 1;
    }
    saveProgress(progress);
    msg.className = "flag-message success";
    msg.textContent = "Correct!";
    $("#success-flag-text").textContent = DEMO_FLAG;
    $("#success-overlay").classList.remove("hidden");
  } else {
    msg.className = "flag-message error";
    msg.textContent = "Wrong flag.";
  }
});

$("#flag-input").addEventListener("keydown", (e) => {
  if (e.key === "Enter") $("#btn-submit-flag").click();
});

$("#btn-next-level").addEventListener("click", () => {
  $("#success-overlay").classList.add("hidden");
  openLevel(2);
});

$("#btn-back-dashboard").addEventListener("click", () => {
  $("#success-overlay").classList.add("hidden");
  $("#level-page").classList.remove("active");
  $("#dashboard").classList.add("active");
  loadDashboard();
});

const solvedToggle = $("#solved-toggle");
if (solvedToggle) {
  solvedToggle.addEventListener("click", () => {
    const panel = $("#solved-flags");
    const open = solvedToggle.getAttribute("aria-expanded") === "true";
    solvedToggle.setAttribute("aria-expanded", open ? "false" : "true");
    panel.classList.toggle("collapsed", open);
  });
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
    if (filter && filter !== "all") tab.setAttribute("data-active-diff", filter);
    renderLevels();
  });
});

/* Share */
function shareGhLink() {
  const icon = `<svg width="12" height="12" viewBox="0 0 16 16" aria-hidden="true"><path fill="currentColor" d="M8 0C3.58 0 0 3.58 0 8c0 3.54 2.29 6.53 5.47 7.59.4.07.55-.17.55-.38 0-.19-.01-.82-.01-1.49-2.01.37-2.53-.49-2.69-.94-.09-.23-.48-.94-.82-1.13-.28-.15-.68-.52-.01-.53.63-.01 1.08.58 1.23.82.72 1.21 1.87.87 2.33.66.07-.52.28-.87.51-1.07-1.78-.2-3.64-.89-3.64-3.95 0-.87.31-1.59.82-2.15-.08-.2-.36-1.02.08-2.12 0 0 .67-.21 2.2.82.64-.18 1.32-.27 2-.27.68 0 1.36.09 2 .27 1.53-1.04 2.2-.82 2.2-.82.44 1.1.16 1.92.08 2.12.51.56.82 1.27.82 2.15 0 3.07-1.87 3.75-3.65 3.95.29.25.54.73.54 1.48 0 1.07-.01 1.93-.01 2.2 0 .21.15.46.55.38A8.013 8.013 0 0016 8c0-4.42-3.58-8-8-8z"/></svg>`;
  const label =
    `<span class="scard-gh-text">` +
    `<span class="gh-host">github.com/</span>` +
    `<span class="gh-user">you-in-you</span>` +
    `<span class="gh-sep">/</span>` +
    `<span class="gh-repo">sqli-playground</span>` +
    `</span>`;
  return `<a class="scard-gh" href="${SHARE_REPO}" target="_blank" rel="noopener noreferrer">${icon}${label}</a>`;
}

function buildBugIssueUrl(levelId, levelName, diff) {
  const id = String(levelId || 1).padStart(2, "0");
  const name = levelName || "—";
  const d = (diff || "easy").toUpperCase();
  const title = `Bug: Level ${id} — ${name}`;
  const body = [
    `**Level:** ${id} (${name})`,
    `**Difficulty:** ${d}`,
    ``,
    `### Description`,
    `<!-- What went wrong? -->`,
    ``,
    `### Steps to reproduce`,
    `1. `,
    `2. `,
    ``,
    `### Expected`,
    ``,
    `### Actual`,
    ``,
  ].join("\n");
  const base = "https://github.com/you-in-you/sqli-playground/issues/new";
  return (
    base +
    "?title=" + encodeURIComponent(title) +
    "&body=" + encodeURIComponent(body)
  );
}

function updateBugLink(levelId, levelName, diff) {
  const href = buildBugIssueUrl(levelId, levelName, diff);
  document.querySelectorAll("a.btn-bug").forEach((a) => {
    a.href = href;
  });
}

function formatSharePayloadHtml(raw) {
  const t = (raw || "").trim() || "—";
  return t.split("\n").map((line) => {
    return `<span class="scard-sh">$</span><span class="scard-cmd">${escapeHtml(line)}</span>`;
  }).join("<br>");
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
    return `<div class="scard scard-v2" id="share-card-export">
      <div class="scard-side"><div class="scard-lvl">L${lvl}</div><div class="scard-diff">${diff}</div></div>
      <div class="scard-body"><div class="scard-title">${name}</div><div class="scard-epic">${epic}</div><div class="scard-payload">${pl}</div><div class="scard-foot">${gh}</div></div>
    </div>`;
  }
  if (style === "3") {
    return `<div class="scard scard-v3" id="share-card-export">
      <div class="scard-bar"><div class="scard-dots"><i></i><i></i><i></i></div>${gh}</div>
      <div class="scard-body"><div class="scard-line"><span class="g">✓</span> LEVEL ${lvl} CLEARED · ${name}</div><div class="scard-epic">${epic}</div><div class="scard-payload">${pl}</div><div class="scard-line">${diff} · ${id}/60</div></div>
    </div>`;
  }
  if (style === "4") {
    return `<div class="scard scard-v4" id="share-card-export">
      <div class="scard-head"><div class="scard-row1"><div class="scard-lvl">LEVEL ${lvl}</div><div class="scard-cleared">Cleared</div></div><div class="scard-name">${name} · ${diff}</div>${gh}</div>
      <div class="scard-body"><div class="scard-label">Epic</div><div class="scard-epic">${epic}</div><div class="scard-label">Payload</div><div class="scard-payload">${pl}</div></div>
    </div>`;
  }
  if (style === "5") {
    return `<div class="scard scard-v5" id="share-card-export">
      <div class="scard-art"><div class="scard-ring">✓</div><span class="scard-lvl">LEVEL ${lvl}</span><div class="scard-name">${name}</div></div>
      <div class="scard-body"><div class="scard-epic">${epic}</div><div class="scard-payload">${pl}</div><div class="scard-foot">${gh}</div></div>
    </div>`;
  }
  if (style === "6") {
    return `<div class="scard scard-v6" id="share-card-export">
      <div class="scard-accent"></div>
      <div class="scard-inner"><div class="scard-toprow"><div class="scard-lvl">LEVEL ${lvl}</div><span class="scard-cleared">Cleared</span></div><div class="scard-title">${name}</div><div class="scard-epic">${epic}</div><div class="scard-payload">${pl}</div><div class="scard-foot">${gh}</div></div>
    </div>`;
  }
  return `<div class="scard scard-v1" id="share-card-export">
    <div class="scard-art"><div class="scard-lvl">LEVEL ${lvl}</div><div class="scard-sub">Cleared · SQLi Playground</div></div>
    <div class="scard-body"><div class="scard-title">${name} — solved</div><div class="scard-epic">${epic}</div><div class="scard-payload">${pl}</div><div class="scard-foot">${gh}</div></div>
  </div>`;
}

function renderSharePreview() {
  const root = $("#share-card-root");
  if (!root) return;
  root.innerHTML = buildShareCardHtml(shareStyle, $("#share-payload").value);
}

function openShareModal() {
  let pre = lastPayload.username || "";
  if (lastPayload.password) pre += (pre ? "\n" : "") + lastPayload.password;
  $("#share-payload").value = pre;
  shareStyle = "1";
  $$(".share-style-tab").forEach((t) => t.classList.toggle("active", t.dataset.style === "1"));
  renderSharePreview();
  $("#share-overlay").classList.remove("hidden");
}

$("#btn-share-clear").addEventListener("click", () => openShareModal());
$("#btn-close-share").addEventListener("click", () => $("#share-overlay").classList.add("hidden"));
$("#share-overlay").addEventListener("click", (e) => {
  if (e.target.id === "share-overlay") $("#share-overlay").classList.add("hidden");
});
$$(".share-style-tab").forEach((tab) => {
  tab.addEventListener("click", () => {
    shareStyle = tab.dataset.style || "1";
    $$(".share-style-tab").forEach((t) => t.classList.remove("active"));
    tab.classList.add("active");
    renderSharePreview();
  });
});
$("#share-payload").addEventListener("input", () => renderSharePreview());
$("#btn-share-copy").addEventListener("click", async () => {
  const text =
    `Cleared Level ${shareLevelMeta.id} on SQLi Playground — ${shareLevelMeta.name}\n` +
    `${shareLevelMeta.id}/60 · local SQLi CTF lab\n` +
    SHARE_REPO;
  try {
    await navigator.clipboard.writeText(text);
    $("#btn-share-copy").textContent = "COPIED";
    setTimeout(() => { $("#btn-share-copy").textContent = "COPY TEXT"; }, 1200);
  } catch (_) {}
});
$("#btn-share-download").addEventListener("click", async () => {
  const node = $("#share-card-export");
  if (!node || typeof html2canvas !== "function") {
    alert("Export unavailable");
    return;
  }
  const btn = $("#btn-share-download");
  btn.textContent = "…";
  try {
    const canvas = await html2canvas(node, { backgroundColor: "#0a0a10", scale: 2, useCORS: true });
    const a = document.createElement("a");
    a.download = `sqli-playground-level-${String(shareLevelMeta.id).padStart(2, "0")}.png`;
    a.href = canvas.toDataURL("image/png");
    a.click();
  } catch (e) {
    console.error(e);
    alert("PNG export failed");
  }
  btn.textContent = "DOWNLOAD PNG";
});

loadDashboard();


/* ── Thin circuit blink + zen level UI + live shell (synced with main UI) ───────────── */
(function () {
  const DEFAULT_QUERY =
    "SELECT id, username, role FROM users WHERE username = 'admin'-- -";

  const SEGS = [
    [19, 5, 19, 29], [19, 29, 44, 29], [44, 17, 44, 40], [44, 40, 69, 40],
    [69, 10, 69, 40], [69, 40, 69, 68], [54, 68, 69, 68], [54, 68, 54, 95],
    [30, 72, 54, 72], [30, 40, 30, 72], [5, 40, 30, 40], [44, 17, 70, 17],
    [5, 67, 54, 67], [54, 10, 54, 40],
  ];

  function randomLevelSegs() {
    const segs = [];
    const n = 10 + Math.floor(Math.random() * 6); // 10–15 traces
    for (let i = 0; i < n; i++) {
      const vertical = Math.random() > 0.45;
      if (vertical) {
        const x = 8 + Math.random() * 84;
        const y1 = 5 + Math.random() * 40;
        const y2 = y1 + 15 + Math.random() * 40;
        segs.push([x, y1, x, Math.min(95, y2)]);
      } else {
        const y = 8 + Math.random() * 84;
        const x1 = 5 + Math.random() * 40;
        const x2 = x1 + 15 + Math.random() * 40;
        segs.push([x1, y, Math.min(95, x2), y]);
      }
    }
    // a few L-corners for circuit feel
    for (let i = 0; i < 3; i++) {
      const x = 12 + Math.random() * 70;
      const y = 12 + Math.random() * 70;
      const x2 = x + (Math.random() > 0.5 ? 12 : -12) * (1 + Math.random());
      const y2 = y + (Math.random() > 0.5 ? 12 : -12) * (1 + Math.random());
      segs.push([x, y, Math.max(5, Math.min(95, x2)), y]);
      segs.push([Math.max(5, Math.min(95, x2)), y, Math.max(5, Math.min(95, x2)), Math.max(5, Math.min(95, y2))]);
    }
    return segs;
  }

  function buildTraces(svgId, segs) {
    const svg = document.getElementById(svgId);
    if (!svg) return [];
    while (svg.firstChild) svg.removeChild(svg.firstChild);
    const lines = [];
    const use = segs || SEGS;
    use.forEach((s, i) => {
      const line = document.createElementNS("http://www.w3.org/2000/svg", "line");
      line.setAttribute("x1", s[0]);
      line.setAttribute("y1", s[1]);
      line.setAttribute("x2", s[2]);
      line.setAttribute("y2", s[3]);
      const col = i % 3 === 0 ? "#d500f9" : "#ff0055";
      line.setAttribute("stroke", col);
      line.setAttribute("stroke-opacity", "0.35");
      line.setAttribute("stroke-width", "0.28");
      line.dataset.color = col;
      line.dataset.phase = String(Math.random() * Math.PI * 2);
      line.dataset.next = String(0.3 + Math.random() * 2);
      line.dataset.blinkStart = "-1";
      line.dataset.blinkDur = "0.7";
      svg.appendChild(line);
      lines.push(line);
    });
    return lines;
  }

  let all = buildTraces("circuit-dash", SEGS).concat(buildTraces("circuit-level", randomLevelSegs()));

  window.rerollLevelCircuit = function () {
    const levelLines = buildTraces("circuit-level", randomLevelSegs());
    all = buildTraces("circuit-dash", SEGS).concat(levelLines);
  };

  const t0 = performance.now() / 1000;
  function tick() {
    const t = performance.now() / 1000 - t0;
    if (!all.length) {
      all = buildTraces("circuit-dash", SEGS).concat(buildTraces("circuit-level", randomLevelSegs()));
    }
    all.forEach((line) => {
      if (!line.isConnected) return;
      const phase = parseFloat(line.dataset.phase);
      const next = parseFloat(line.dataset.next);
      let blinkStart = parseFloat(line.dataset.blinkStart);
      let blinkDur = parseFloat(line.dataset.blinkDur);
      if (t >= next) {
        blinkDur = 0.5 + Math.random() * 0.6;
        blinkStart = t;
        line.dataset.blinkStart = String(blinkStart);
        line.dataset.blinkDur = String(blinkDur);
        line.dataset.next = String(t + blinkDur + 3 + Math.random() * 6);
      }
      let op = 0.28 + 0.05 * Math.sin(t * 0.3 + phase);
      line.style.filter = "none";
      if (blinkStart >= 0 && t >= blinkStart && t < blinkStart + blinkDur) {
        const u = (t - blinkStart) / blinkDur;
        const envelope = Math.sin(u * Math.PI);
        op = 0.28 + 0.55 * envelope;
        if (envelope > 0.25) {
          line.style.filter =
            "drop-shadow(0 0 " + (1.5 + envelope * 3).toFixed(1) + "px " + line.dataset.color + ")";
        }
      }
      line.setAttribute("stroke-opacity", op.toFixed(3));
    });
    requestAnimationFrame(tick);
  }
  requestAnimationFrame(tick);

  function bindTitleGlitch(el) {
    if (!el || el.dataset.glitchBound === "1") return;
    el.dataset.glitchBound = "1";
    el.addEventListener("mouseenter", function () {
      if (el.dataset.glitchLock === "1") return;
      el.dataset.glitchLock = "1";
      el.classList.add("glitching");
      setTimeout(function () {
        el.classList.remove("glitching");
        el.dataset.glitchLock = "0";
      }, 260);
    });
  }

  function measure(el) {
    if (!el) return 0;
    const prev = {
      pos: el.style.position,
      vis: el.style.visibility,
      op: el.style.opacity,
    };
    el.style.position = "static";
    el.style.visibility = "hidden";
    el.style.opacity = "1";
    const h = el.offsetHeight;
    el.style.position = prev.pos || "absolute";
    el.style.visibility = prev.vis || "";
    el.style.opacity = prev.op || "";
    return h;
  }

  window.lockHintHeight = function () {
    const body = document.getElementById("hint-body");
    const epic = document.getElementById("hint-indirect-text");
    const tech = document.getElementById("hint-technical-text");
    if (!body || !epic || !tech) return;
    const h = Math.max(measure(epic), measure(tech), 40);
    body.style.height = h + "px";
    body.style.minHeight = h + "px";
  };

  window.setupZenLevelUI = function () {
    const swap = document.getElementById("hint-swap");
    const body = document.getElementById("hint-body");
    const hintHint = document.getElementById("hint-hint-label");
    const title = document.getElementById("level-title");
    if (title) {
      title.dataset.glitchBound = "0";
      bindTitleGlitch(title);
    }
    if (swap && swap.dataset.bound !== "1") {
      swap.dataset.bound = "1";
      swap.addEventListener("mouseenter", function () {
        if (swap.classList.contains("open")) return;
        swap.classList.add("open");
        if (body) {
          body.classList.add("glitching");
          setTimeout(function () {
            body.classList.remove("glitching");
          }, 320);
        }
        if (hintHint) hintHint.style.marginTop = "8px";
      });
      swap.addEventListener("mouseleave", function () {
        swap.classList.remove("open");
        if (body) body.classList.remove("glitching");
        if (hintHint) hintHint.style.marginTop = "4px";
      });
    }
    window.lockHintHeight();
  };

  function updateLiveShell() {
    const cmd = document.getElementById("live-cmd");
    const u = document.getElementById("payload-input");
    const p = document.getElementById("payload-pass");
    if (!cmd || !u || !p) return;
    const parts = [];
    if (u.value) parts.push(u.value);
    if (p.value) parts.push(p.value);
    if (!parts.length) {
      cmd.textContent = DEFAULT_QUERY;
      cmd.classList.add("ghost");
    } else {
      cmd.textContent = parts.join("  ·  ");
      cmd.classList.remove("ghost");
    }
  }

  const u = document.getElementById("payload-input");
  const p = document.getElementById("payload-pass");
  if (u) u.addEventListener("input", updateLiveShell);
  if (p) p.addEventListener("input", updateLiveShell);
  updateLiveShell();

  window.setupZenLevelUI();

  // rebuild traces when page shown (hidden SVG can have 0 size initially)
  const dashPage = document.getElementById("dashboard");
  const levelPage = document.getElementById("level-page");
  const obs = new MutationObserver(function () {
    all = buildTraces("circuit-dash", SEGS).concat(
      buildTraces("circuit-level", randomLevelSegs())
    );
  });
  if (dashPage) obs.observe(dashPage, { attributes: true, attributeFilter: ["class"] });
  if (levelPage) obs.observe(levelPage, { attributes: true, attributeFilter: ["class"] });

  // Hook openLevel to refresh zen UI + circuit + live shell
  const _openLevel = openLevel;
  openLevel = function (id) {
    _openLevel(id);
    requestAnimationFrame(function () {
      if (typeof window.rerollLevelCircuit === "function") window.rerollLevelCircuit();
      if (typeof window.setupZenLevelUI === "function") window.setupZenLevelUI();
      updateLiveShell();
    });
  };

  window.addEventListener("resize", function () {
    if (typeof window.lockHintHeight === "function") window.lockHintHeight();
  });
})();


/* ── Button sweep/pulse + hero title swap ───────────────────── */
(function () {
  const SEL = ".btn-attack, .btn-submit, .btn-share, .btn-ghost";

  function pulse(el) {
    if (!el || !el.classList) return;
    el.classList.remove("fired");
    void el.offsetWidth;
    el.classList.add("fired");
    setTimeout(function () { el.classList.remove("fired"); }, 450);
  }
  function sweep(el) {
    if (!el || !el.classList) return;
    el.classList.remove("sweep");
    void el.offsetWidth;
    el.classList.add("sweep");
    setTimeout(function () { el.classList.remove("sweep"); }, 520);
  }
  window.pulseBtn = pulse;

  document.addEventListener("mouseover", function (e) {
    const btn = e.target && e.target.closest ? e.target.closest(SEL) : null;
    if (!btn) return;
    const from = e.relatedTarget;
    if (from && btn.contains(from)) return; // still inside same button
    sweep(btn);
  });
  document.addEventListener(
    "click",
    function (e) {
      const btn = e.target && e.target.closest ? e.target.closest(SEL) : null;
      if (btn) pulse(btn);
    },
    true
  );

  const title = document.getElementById("hero-title");
  if (title) {
    const NORMAL = "SQL Injection Lab";
    const POWERED_HTML = 'powered by <span class="hero-edis">Edis</span>';
    let lock = false;
    title.addEventListener("mouseenter", function () {
      if (lock) return;
      lock = true;
      title.classList.add("glitching");
      setTimeout(function () {
        title.classList.remove("glitching");
        title.classList.add("powered-mode");
        title.innerHTML = POWERED_HTML;
        title.setAttribute("data-text", "powered by Edis");
        lock = false;
      }, 180);
    });
    title.addEventListener("mouseleave", function () {
      title.classList.add("glitching");
      setTimeout(function () {
        title.classList.remove("glitching");
        title.classList.remove("powered-mode");
        title.textContent = NORMAL;
        title.setAttribute("data-text", NORMAL);
      }, 120);
    });
  }
})();

/* Flag input: collapsed until SUBMIT hover, then stays open */
(function () {
  const row = document.querySelector(".flag-row");
  const btn = document.getElementById("btn-submit-flag");
  const input = document.getElementById("flag-input");
  if (!row || !btn) return;
  function openFlag() {
    row.classList.add("flag-open");
  }
  btn.addEventListener("mouseenter", openFlag);
  btn.addEventListener("focus", openFlag);
  if (input) {
    input.addEventListener("focus", openFlag);
  }
})();

(function () {
  const ov = document.getElementById("history-overlay");
  const btn = document.getElementById("btn-close-history");
  function closeHistory() {
    if (!ov) return;
    ov.classList.add("hidden");
  }
  if (btn) btn.addEventListener("click", closeHistory);
  if (ov) {
    ov.addEventListener("click", (e) => {
      if (e.target === ov) closeHistory();
    });
  }
})();

