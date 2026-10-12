let riskChart = null;

const $ = (id) => document.getElementById(id);

// Create an element safely (text goes in via textContent -> no XSS)
function make(tag, text, className) {
  const el = document.createElement(tag);
  if (text !== undefined) el.textContent = text;
  if (className) el.className = className;
  return el;
}

function badge(level) {
  return make("span", level, "badge " + level.toLowerCase());
}

// Small fetch wrapper: throws an Error with the server's message on failure
async function api(path, options) {
  const res = await fetch("/api" + path, options);
  let data = null;
  try { data = await res.json(); } catch (e) { /* e.g. 204 No Content */ }
  if (!res.ok) throw new Error((data && data.error) || "Request failed (" + res.status + ")");
  return data;
}

// ---------------- Navigation ----------------
function showPage(name) {
  document.querySelectorAll(".page").forEach(p => p.classList.toggle("active", p.id === "page-" + name));
  document.querySelectorAll(".nav-btn").forEach(b => b.classList.toggle("active", b.dataset.page === name));
  if (name === "dashboard") loadDashboard();
  if (name === "history") loadHistory();
}
document.querySelectorAll(".nav-btn").forEach(b =>
  b.addEventListener("click", () => showPage(b.dataset.page)));

// ---------------- Dashboard ----------------
function fillList(containerId, scans) {
  const box = $(containerId);
  box.replaceChildren();
  if (scans.length === 0) { box.appendChild(make("p", "No scans yet.", "empty")); return; }
  scans.forEach(s => {
    const row = make("div", undefined, "row");
    row.appendChild(make("span", s.url, "url"));
    row.appendChild(badge(s.riskLevel));
    box.appendChild(row);
  });
}

async function loadDashboard() {
  try {
    const s = await api("/dashboard/stats");
    $("statTotal").textContent = s.total;
    $("statLow").textContent = s.low;
    $("statMedium").textContent = s.medium;
    $("statHigh").textContent = s.high;
    $("statCritical").textContent = s.critical;
    fillList("recentList", s.recent);
    fillList("highestList", s.highest);
    drawChart(s);
  } catch (e) { console.error(e); }
}

function drawChart(s) {
  if (typeof Chart === "undefined") return;      // CDN not reachable
  if (riskChart) riskChart.destroy();
  riskChart = new Chart($("riskChart"), {
    type: "doughnut",
    data: {
      labels: ["Low", "Medium", "High", "Critical"],
      datasets: [{
        data: [s.low, s.medium, s.high, s.critical],
        backgroundColor: ["#22c55e", "#eab308", "#f97316", "#ef4444"],
        borderWidth: 0
      }]
    },
    options: { plugins: { legend: { labels: { color: "#e5e7eb" } } } }
  });
}

// ---------------- Scan ----------------
function renderResult(r) {
  $("result").classList.remove("hidden");
  $("resScore").textContent = r.riskScore + "/100";
  const levelEl = $("resLevel");
  levelEl.textContent = r.riskLevel;
  levelEl.className = "badge " + r.riskLevel.toLowerCase();
  $("resHost").textContent = r.hostname || "-";
  $("resHttps").textContent = r.https ? "Yes" : "No";
  $("resUrl").textContent = r.url;
  $("resRecommendation").textContent = r.recommendation;

  const box = $("resIssues");
  box.replaceChildren();
  if (r.issues.length === 0) {
    box.appendChild(make("div", "No heuristic issues detected.", "issue ok"));
  } else {
    r.issues.forEach(i => box.appendChild(make("div", i, "issue")));
  }
}

async function scanUrl() {
  const url = $("urlInput").value;
  $("scanError").textContent = "";
  $("scanBtn").disabled = true;
  try {
    const result = await api("/scan", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ url: url })
    });
    renderResult(result);
  } catch (e) {
    $("scanError").textContent = e.message;
    $("result").classList.add("hidden");
  } finally {
    $("scanBtn").disabled = false;
  }
}
$("scanBtn").addEventListener("click", scanUrl);
$("urlInput").addEventListener("keydown", e => { if (e.key === "Enter") scanUrl(); });

// ---------------- History ----------------
async function loadHistory() {
  const params = new URLSearchParams({
    q: $("searchInput").value,
    level: $("levelFilter").value,
    sort: $("sortSelect").value
  });
  const body = $("historyBody");
  try {
    const scans = await api("/scan/history?" + params);
    body.replaceChildren();
    if (scans.length === 0) {
      const tr = make("tr"); const td = make("td", "No scans found.", "empty");
      td.colSpan = 5; tr.appendChild(td); body.appendChild(tr);
      return;
    }
    scans.forEach(s => {
      const tr = make("tr");
      tr.appendChild(make("td", s.url, "url-cell"));
      tr.appendChild(make("td", s.riskScore + "/100"));
      const levelTd = make("td"); levelTd.appendChild(badge(s.riskLevel)); tr.appendChild(levelTd);
      tr.appendChild(make("td", new Date(s.scannedAt).toLocaleString()));

      const actions = make("td");
      const viewBtn = make("button", "View", "small");
      viewBtn.addEventListener("click", () => viewScan(s.id));
      const delBtn = make("button", "Delete", "small danger");
      delBtn.addEventListener("click", () => deleteScan(s.id));
      actions.append(viewBtn, " ", delBtn);
      tr.appendChild(actions);
      body.appendChild(tr);
    });
  } catch (e) { console.error(e); }
}

async function viewScan(id) {
  try {
    const scan = await api("/scan/" + id);
    showPage("scan");
    $("urlInput").value = scan.url;
    $("scanError").textContent = "";
    renderResult(scan);
  } catch (e) { alert(e.message); }
}

async function deleteScan(id) {
  if (!confirm("Delete this scan?")) return;
  try { await api("/scan/" + id, { method: "DELETE" }); loadHistory(); }
  catch (e) { alert(e.message); }
}

$("clearBtn").addEventListener("click", async () => {
  if (!confirm("Delete ALL scan history?")) return;
  try { await api("/scan/history", { method: "DELETE" }); loadHistory(); }
  catch (e) { alert(e.message); }
});

$("searchInput").addEventListener("input", loadHistory);
$("levelFilter").addEventListener("change", loadHistory);
$("sortSelect").addEventListener("change", loadHistory);

// ---------------- Start ----------------
loadDashboard();