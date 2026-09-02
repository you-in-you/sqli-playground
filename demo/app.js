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
    if (!raw) return { solved: [], current: 1 };
    const data = JSON.parse(raw);
    return {
      solved: Array.isArray(data.solved) ? data.solved.map(Number) : [],
      current: Number(data.current) || 1,
    };
  } catch {
    return { solved: [], current: 1 };
  }
}

function saveProgress(p) {
  localStorage.setItem(STORAGE_KEY, JSON.stringify(p));
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
      statusMsg = "Found";
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
      return `<div class="solved-item" data-level="${id}">
        <span class="solved-level">Level ${String(id).padStart(2, "0")} — ${escapeHtml(meta.name)}</span>
        <span class="solved-flag">${escapeHtml(flag)}</span>
      </div>`;
    })
    .join("");
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
  $("#level-title").textContent = meta.name;
  $("#level-difficulty").textContent = getDiffLabel(meta.diff);
  $("#level-desc").textContent = meta.desc;
  $("#hint-indirect-text").textContent = meta.hint_i;
  $("#hint-technical-text").textContent = meta.hint_t;
  $("#hint-technical").classList.add("hidden");

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

$("#hint-indirect").addEventListener("click", () => {
  $("#hint-technical").classList.toggle("hidden");
});

$("#btn-send-payload").addEventListener("click", () => {
  if (currentLevel !== 1) return;
  const username = $("#payload-input").value;
  const password = $("#payload-pass").value;
  lastPayload = { username, password };
  const res = mockAttack(username, password);
  $("#response-area").classList.remove("hidden");
  let out = "";
  if (res.message) out += res.message + "\n\n";
  if (res.raw) out += res.raw;
  $("#response-content").textContent = out;
});

$("#btn-submit-flag").addEventListener("click", () => {
  if (currentLevel !== 1) return;
  const flag = ($("#flag-input").value || "").trim();
  const msg = $("#flag-message");
  if (flag === DEMO_FLAG) {
    if (!progress.solved.includes(1)) progress.solved.push(1);
    progress.current = Math.max(progress.current, 2);
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
  return `<a class="scard-gh" href="${SHARE_REPO}" target="_blank" rel="noopener noreferrer"><svg width="12" height="12" viewBox="0 0 16 16" aria-hidden="true"><path fill="currentColor" d="M8 0C3.58 0 0 3.58 0 8c0 3.54 2.29 6.53 5.47 7.59.4.07.55-.17.55-.38 0-.19-.01-.82-.01-1.49-2.01.37-2.53-.49-2.69-.94-.09-.23-.48-.94-.82-1.13-.28-.15-.68-.52-.01-.53.63-.01 1.08.58 1.23.82.72 1.21 1.87.87 2.33.66.07-.52.28-.87.51-1.07-1.78-.2-3.64-.89-3.64-3.95 0-.87.31-1.59.82-2.15-.08-.2-.36-1.02.08-2.12 0 0 .67-.21 2.2.82.64-.18 1.32-.27 2-.27.68 0 1.36.09 2 .27 1.53-1.04 2.2-.82 2.2-.82.44 1.1.16 1.92.08 2.12.51.56.82 1.27.82 2.15 0 3.07-1.87 3.75-3.65 3.95.29.25.54.73.54 1.48 0 1.07-.01 1.93-.01 2.2 0 .21.15.46.55.38A8.013 8.013 0 0016 8c0-4.42-3.58-8-8-8z"/></svg> ${SHARE_REPO_HOST}</a>`;
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
