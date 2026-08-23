/* SQLi Playground — Static Live Demo (no backend)
 * Level 01: interactive mock SQLi
 * Levels 02–60: UI demo only
 */

const $ = (s) => document.querySelector(s);
const $$ = (s) => document.querySelectorAll(s);

const DEMO_FLAG = "CTF{sql1_l01_demo_flag}";

const LEVEL_META = {
  1: {
    name: "Error-Based Basic",
    diff: "easy",
    desc: "A simple login form is vulnerable to SQL injection. Extract the flag from the secrets table.",
    hint_i: "No soldiers guard the castle gates.",
    hint_t: "Input is concatenated into the query. Try UNION on table secrets (3 columns) or trigger an error.",
  },
};

const NAMES = {
  2: "Error-Based String", 3: "Error-Based Numeric", 4: "Union Basic", 5: "Union Column Count",
  6: "Union Extract Flag", 7: "Comment Techniques", 8: "Basic Auth Bypass", 9: "Error Messages Leak",
  10: "Simple Blind Intro", 11: "Boolean Logic", 12: "String Length Extraction", 13: "Character Extraction",
  14: "Time-Based Intro", 15: "Basic Filter Bypass", 16: "Union with Types", 17: "Union + Limit",
  18: "Second-Order Basic", 19: "Cookie Injection", 20: "Header Injection", 21: "JSON Body SQLi",
  22: "Blind Time + Filter", 23: "Order By Injection", 24: "Group By / Having", 25: "Stacked Queries",
  26: "Out-of-Band Surface", 27: "WAF Simple Keywords", 28: "Double Encoding", 29: "Scientific Notation",
  30: "Inline Comments Bypass", 31: "Advanced Boolean Blind", 32: "Time-Based Heavy Filter",
  33: "Second-Order Advanced", 34: "WAF Regex Bypass", 35: "No Error, No Time", 36: "INSERT Injection",
  37: "UPDATE Injection", 38: "Limit & Offset Abuse", 39: "Prepared Statement Bypass", 40: "Quote Stripping",
  41: "JSON + Dual Fields", 42: "Header + Cookie Chain", 43: "Blind Extraction", 44: "Filter + Encoding Maze",
  45: "Conditional Error Blind", 46: "WAF + Obfuscation", 47: "Stacked + Filter", 48: "No UNION Keyword",
  49: "No Spaces", 50: "No Comments", 51: "Blind + Heavy WAF", 52: "Polyglot Payload",
  53: "No Quotes Allowed", 54: "Bit-by-Bit Advanced", 55: "Chained Contexts", 56: "Full Chain Expert",
  57: "Protocol Surface", 58: "Race Surface", 59: "Almost Impossible Filter", 60: "The Final Gate",
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
    desc: "Demo preview only. Full vulnerable backend runs in the local lab after you clone the repo.",
    hint_i: "This level is visual demo only.",
    hint_t: "Clone the repository and run it locally for real SQLi challenges.",
  };
}

let currentLevel = 1;
let currentFilter = "all";
let solved = {}; // id -> flag
let history = {}; // id -> attempts[]

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

function isUnlocked(id) {
  if (id === 1) return true;
  return !!solved[id - 1];
}

function renderLevels() {
  const grid = $("#levels-grid");
  grid.innerHTML = "";
  const all = [];
  for (let i = 1; i <= 60; i++) {
    all.push({
      id: i,
      name: getMeta(i).name,
      diff: getDiff(i),
      unlocked: isUnlocked(i),
      solved: !!solved[i],
    });
  }
  const filtered =
    currentFilter === "all" ? all : all.filter((l) => l.diff === currentFilter);

  filtered.forEach((level) => {
    const card = document.createElement("div");
    const locked = !level.unlocked && !level.solved;
    card.className = `level-card${level.solved ? " solved" : ""}${locked ? " locked" : ""}`;
    card.dataset.diff = level.diff;
    if (locked) {
      card.innerHTML = `
        <div class="locked-content">
          <div class="locked-code">403</div>
          <div class="locked-msg">Access Denied</div>
        </div>`;
    } else {
      card.innerHTML = `
        <div class="level-num">LEVEL ${String(level.id).padStart(2, "0")}</div>
        <div class="level-name">${level.name}</div>
        <span class="level-diff">${getDiffLabel(level.diff)}</span>`;
      card.addEventListener("click", () => openLevel(level.id));
    }
    grid.appendChild(card);
  });
  $("#progress-count").textContent = Object.keys(solved).length;
}

function renderSolved() {
  const el = $("#solved-flags");
  const ids = Object.keys(solved).map(Number).sort((a, b) => a - b);
  if (!ids.length) {
    el.innerHTML = `<p class="empty-state">No flags captured yet.</p>`;
    return;
  }
  el.innerHTML = ids
    .map(
      (id) => `
    <div class="solved-item" data-level="${id}">
      <span class="solved-level">Level ${String(id).padStart(2, "0")} — ${getMeta(id).name}</span>
      <span class="solved-flag">${solved[id]}</span>
    </div>`
    )
    .join("");
  el.querySelectorAll(".solved-item").forEach((item) => {
    item.addEventListener("click", () => openHistory(Number(item.dataset.level)));
  });
}

function openHistory(levelId) {
  const title = $("#history-title");
  const body = $("#history-body");
  title.textContent = `${getMeta(levelId).name} — Attack History`;
  const rows = history[levelId] || [];
  if (!rows.length) {
    body.innerHTML = `<p class="empty-state">No attempts recorded.</p>`;
  } else {
    body.innerHTML = rows
      .map((h) => {
        const win = h.winning ? `<div class="hist-win-tag">Winning payload</div>` : "";
        return `
          <div class="history-item${h.winning ? " winning" : ""}">
            ${win}
            <div class="hist-label">Payload</div>
            <div class="hist-payload">user: ${escapeHtml(h.user || "(empty)")}<br>pass: ${escapeHtml(h.pass || "(empty)")}</div>
            <div class="hist-label">Response</div>
            <div class="hist-response">${escapeHtml(h.response || "")}</div>
          </div>`;
      })
      .join("");
  }
  $("#history-overlay").classList.remove("hidden");
}

function openLevel(id) {
  currentLevel = id;
  const meta = getMeta(id);
  document.body.dataset.diff = meta.diff;

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
}

/** Mock Level 01 SQLi — educational simulation only */
function mockLevel01(user, pass) {
  const q = `SELECT id, username, role FROM users WHERE username = '${user}' AND password = '${pass}'`;

  // UNION extract flag (3 columns)
  if (/union/i.test(user) && /secrets/i.test(user) && /flag/i.test(user)) {
    return {
      message: `Welcome, ${DEMO_FLAG} (admin)`,
      raw: `Query: ${q}\n\nResult: [{'id': 1, 'username': '${DEMO_FLAG}', 'role': 'admin'}]`,
    };
  }

  // Auth bypass
  if (/'\s*or\s+'/i.test(user) || /or\s+1\s*=\s*1/i.test(user) || /or\s+'1'\s*=\s*'1/i.test(user)) {
    return {
      message: "Welcome, admin (admin)",
      raw: `Query: ${q}\n\nResult: [{'id': 1, 'username': 'admin', 'role': 'admin'}, {'id': 2, 'username': 'alice', 'role': 'user'}]\n\n(Hint: login bypass works — now extract from secrets via UNION)`,
    };
  }

  // Syntax error leak
  if (user.includes("'") || user.includes("--") || user.includes("#")) {
    return {
      message: "Database error",
      raw: `Query: ${q}\n\nError: ProgrammingError: (1064, "You have an error in your SQL syntax...")\n\nTables: users, secrets\nsecrets columns: id, name, flag`,
    };
  }

  if (user === "admin" && pass === "admin123") {
    return {
      message: "Welcome, admin (admin)",
      raw: `Query: ${q}\n\nResult: [{'id': 1, 'username': 'admin', 'role': 'admin'}]\n\nNo flag here — dump secrets.`,
    };
  }

  return {
    message: "Login failed. Invalid username or password.",
    raw: `Query: ${q}\n\nNo matching rows.`,
  };
}

$("#hint-indirect").addEventListener("click", () => {
  $("#hint-technical").classList.toggle("hidden");
});

$("#btn-send-payload").addEventListener("click", () => {
  const user = $("#payload-input").value;
  const pass = $("#payload-pass").value;
  const area = $("#response-area");
  const content = $("#response-content");
  area.classList.remove("hidden");

  let result;
  if (currentLevel === 1) {
    result = mockLevel01(user, pass);
  } else {
    result = {
      message: "Demo mode",
      raw:
        "This is a static UI demo.\n\n" +
        `Level ${String(currentLevel).padStart(2, "0")} has a full vulnerable backend only in the local lab.\n` +
        "Clone the repo, run setup_db.py + Flask, and play all 60 real challenges.",
    };
  }

  const text = `${result.message}\n\n${result.raw}`;
  content.textContent = text;

  if (!history[currentLevel]) history[currentLevel] = [];
  history[currentLevel].push({ user, pass, response: text, winning: false });
});

$("#btn-submit-flag").addEventListener("click", () => {
  const flag = $("#flag-input").value.trim();
  const msg = $("#flag-message");
  msg.classList.remove("hidden");

  if (currentLevel !== 1) {
    msg.className = "flag-message error";
    msg.textContent = "Demo only — flags work in the full local lab.";
    return;
  }

  if (flag === DEMO_FLAG) {
    msg.className = "flag-message success";
    msg.textContent = "Correct! Flag accepted.";
    solved[1] = DEMO_FLAG;
    const list = history[1] || [];
    if (list.length) list[list.length - 1].winning = true;
    renderLevels();
    renderSolved();
    setTimeout(() => {
      $("#success-flag-text").textContent = DEMO_FLAG;
      $("#success-overlay").classList.remove("hidden");
    }, 400);
  } else {
    msg.className = "flag-message error";
    msg.textContent = "Wrong flag. Try again.";
  }
});

$("#flag-input").addEventListener("keydown", (e) => {
  if (e.key === "Enter") $("#btn-submit-flag").click();
});

$("#btn-next-level").addEventListener("click", () => {
  $("#success-overlay").classList.add("hidden");
  // In demo, level 2 is visual-only but unlocked after solve
  if (solved[1]) openLevel(2);
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
  renderLevels();
  renderSolved();
}

$$(".tab").forEach((tab) => {
  tab.addEventListener("click", () => {
    $$(".tab").forEach((t) => t.classList.remove("active"));
    tab.classList.add("active");
    currentFilter = tab.dataset.filter;
    renderLevels();
  });
});

renderLevels();
renderSolved();
