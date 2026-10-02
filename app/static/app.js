const views = ["dashboard", "investigate", "cases", "about"];
const $ = (id) => document.getElementById(id);

function showView(name) {
  views.forEach(v => $(`${v}-view`).classList.toggle("hidden", v !== name));
  document.querySelectorAll(".nav-btn").forEach(btn => btn.classList.toggle("active", btn.dataset.view === name));
  const titles = {
    dashboard: "Investigation Dashboard",
    investigate: "New Investigation",
    cases: "Case Archive",
    about: "About PHISHTRACE AI"
  };
  $("page-title").textContent = titles[name];
  if (name === "cases") loadCases();
}

document.querySelectorAll(".nav-btn").forEach(btn => btn.addEventListener("click", () => showView(btn.dataset.view)));
document.querySelectorAll("[data-view-target]").forEach(btn => btn.addEventListener("click", () => showView(btn.dataset.viewTarget)));
$("new-case-btn").onclick = () => showView("investigate");
$("hero-investigate").onclick = () => showView("investigate");

function escapeHtml(value) {
  return String(value ?? "").replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#039;'}[c]));
}

function renderCases(cases, target) {
  if (!cases.length) {
    target.innerHTML = `<div class="hint">No investigations yet. Start a new case above.</div>`;
    return;
  }
  target.innerHTML = cases.map(c => `
    <div class="case-row">
      <div class="case-id">${escapeHtml(c.id)}</div>
      <div class="case-title">${escapeHtml(c.title)}</div>
      <div class="risk ${c.risk_level}">${escapeHtml(c.risk_level)}</div>
      <div><button class="ghost-btn" onclick="openCase('${encodeURIComponent(c.id)}')">Open</button></div>
    </div>`).join("");
}

async function loadCases() {
  const res = await fetch("/api/cases");
  const cases = await res.json();
  renderCases(cases, $("all-cases"));
  renderCases(cases.slice(0,5), $("recent-cases"));
  $("stat-cases").textContent = cases.length;
  $("stat-high").textContent = cases.filter(c => c.risk_level === "HIGH").length;
  $("stat-urls").textContent = cases.filter(c => c.source_type === "url").length;
}

async function openCase(encoded) {
  const id = decodeURIComponent(encoded);
  const res = await fetch(`/api/cases/${encodeURIComponent(id)}`);
  if (!res.ok) return;
  const c = await res.json();
  showView("investigate");
  renderResult({
    case: {id:c.id},
    source_type:c.source_type,
    risk_level:c.risk_level,
    score:c.score,
    summary:c.summary,
    indicators: [
      ...(c.evidence.email?.indicators || []),
      ...((c.evidence.urls || []).flatMap(u => u.indicators || []))
    ],
    graph:c.graph,
    urls:c.evidence.urls || []
  });
}

function graphHtml(graph, data) {
  if (!graph || !graph.nodes?.length) return "";

  const nodes = graph.nodes;

  return `
    <div class="graph-flow">
      ${nodes.map((n, i) => `
        <button
          class="node node-clickable"
          data-node-id="${escapeHtml(n.id)}"
          data-node-type="${escapeHtml(n.type)}"
        >
          <div class="type">${escapeHtml(n.label.toUpperCase())}</div>
          <div class="detail">${escapeHtml(n.detail)}</div>
          <div class="node-hint">Click to inspect</div>
        </button>
        ${i < nodes.length - 1 ? `<div class="arrow">→</div>` : ""}
      `).join("")}
    </div>

    <div id="evidence-panel" class="node-evidence">
      <div class="evidence-empty">
        Select an entity above to inspect its evidence.
      </div>
    </div>
  `;
}
function showNodeEvidence(nodeId, data) {
  const panel = document.getElementById("evidence-panel");
  if (!panel) return;

  const node = (data.graph?.nodes || []).find(n => n.id === nodeId);

  if (!node) {
    panel.innerHTML = `
      <div class="evidence-empty">
        No evidence was found for this entity.
      </div>
    `;
    return;
  }

  let title = node.label;
  let content = "";

  if (node.type === "email") {
    const email = data.email || {};
    const headers = email.headers || {};

    content = `
      <div class="evidence-grid">
        <div>
          <span>FROM</span>
          <strong>${escapeHtml(headers.from || "Unknown")}</strong>
        </div>

        <div>
          <span>TO</span>
          <strong>${escapeHtml(headers.to || "Unknown")}</strong>
        </div>

        <div>
          <span>SUBJECT</span>
          <strong>${escapeHtml(headers.subject || "No subject")}</strong>
        </div>

        <div>
          <span>REPLY-TO</span>
          <strong>${escapeHtml(headers.reply_to || "Not present")}</strong>
        </div>
      </div>

      <div class="evidence-description">
        <span>BODY PREVIEW</span>
        <p>${escapeHtml(email.body_preview || "No body preview available.")}</p>
      </div>
    `;
  }

  else if (node.type === "url") {
    const index = Number((node.id || "").split("-")[1]);
    const url = data.urls?.[index];

    if (url) {
      content = `
        <div class="evidence-grid">
          <div>
            <span>FULL URL</span>
            <strong>${escapeHtml(url.url)}</strong>
          </div>

          <div>
            <span>HOST</span>
            <strong>${escapeHtml(url.host || "Unknown")}</strong>
          </div>

          <div>
            <span>SCHEME</span>
            <strong>${escapeHtml(url.scheme || "Unknown")}</strong>
          </div>

          <div>
            <span>PATH</span>
            <strong>${escapeHtml(url.path || "/")}</strong>
          </div>
        </div>

        <div class="evidence-description">
          <span>URL INDICATORS</span>

          ${
            url.indicators?.length
              ? url.indicators.map(i => `
                  <div class="mini-indicator">
                    <b>${escapeHtml(i.name)}</b>
                    <span>+${escapeHtml(i.points)}</span>
                    <p>${escapeHtml(i.detail)}</p>
                  </div>
                `).join("")
              : `<p>No URL-specific indicators were recorded.</p>`
          }
        </div>
      `;
    }
  }

  else if (node.type === "domain") {
    const index = Number((node.id || "").split("-")[1]);
    const url = data.urls?.[index];

    content = `
      <div class="evidence-grid">
        <div>
          <span>DOMAIN</span>
          <strong>${escapeHtml(node.detail)}</strong>
        </div>

        <div>
          <span>ASSOCIATED URL</span>
          <strong>${escapeHtml(url?.url || "Unknown")}</strong>
        </div>
      </div>

      <div class="evidence-description">
        <span>DOMAIN OBSERVATION</span>
        <p>
          This domain was extracted from the submitted evidence.
          PHISHTRACE did not automatically browse to the destination.
        </p>
      </div>
    `;
  }

  panel.innerHTML = `
    <div class="evidence-header">
      <div>
        <div class="eyebrow">SELECTED ENTITY</div>
        <h3>${escapeHtml(title)}</h3>
      </div>

      <span class="evidence-type">
        ${escapeHtml(node.type.toUpperCase())}
      </span>
    </div>

    ${content}
  `;
}
function renderResult(data) {
  const indicators = data.indicators || [];
  $("result").classList.remove("hidden");
  $("result").innerHTML = `
    <div class="result-wrap">
      <div class="result-top">
        <div class="panel">
          <div class="panel-header">
            <div><h3>Investigation Result</h3><p>Case ${escapeHtml(data.case.id)}</p></div>
            <div class="risk ${data.risk_level}">${escapeHtml(data.risk_level)} RISK</div>
          </div>
          <div class="summary">${escapeHtml(data.summary)}</div>
          <h3>Explainable indicators</h3>
          ${indicators.length ? indicators.map(i => `
            <div class="indicator">
              <div class="severity-dot ${escapeHtml(i.severity)}"></div>
              <div><strong>${escapeHtml(i.name)}</strong><small>${escapeHtml(i.detail)}</small></div>
              <strong>+${escapeHtml(i.points)}</strong>
            </div>`).join("") : `<div class="hint">No significant heuristic indicators were found.</div>`}
        </div>
        <div class="panel score-card">
          <div class="eyebrow">RISK SCORE</div>
          <div class="score ${data.risk_level}">${escapeHtml(data.score)}</div>
          <div class="hint">out of 100</div>
          <div class="actions">
            <a class="primary-btn" href="/api/cases/${encodeURIComponent(data.case.id)}/report" target="_blank">PDF Report</a>
          </div>
        </div>
      </div>
      <div class="panel" style="margin-top:16px">
        <div class="panel-header"><div>
        <div class="case-summary-card">

  <div class="case-summary-header">
    <div>
      <span class="eyebrow">CASE SUMMARY</span>
      <h3>Investigation Overview</h3>
    </div>

    <span class="case-id-badge">
      ${escapeHtml(data.case?.id || "UNKNOWN")}
    </span>
  </div>

  <div class="case-summary-grid">

    <div class="summary-stat">
      <span>SOURCE</span>
      <strong>
        ${escapeHtml(data.source_type || "UNKNOWN")}
      </strong>
    </div>

    <div class="summary-stat">
      <span>RISK SCORE</span>
      <strong>
        ${escapeHtml(String(data.score ?? 0))}/100
      </strong>
    </div>

    <div class="summary-stat">
      <span>URLS FOUND</span>
      <strong>
        ${escapeHtml(String(data.urls?.length || 0))}
      </strong>
    </div>

    <div class="summary-stat">
      <span>INDICATORS</span>
      <strong>
        ${escapeHtml(String(data.indicators?.length || 0))}
      </strong>
    </div>

  </div>

  <div class="case-summary-description">

    <span>INVESTIGATION SUMMARY</span>

    <p>
      ${escapeHtml(
        data.summary ||
        "No investigation summary is available."
      )}
    </p>

  </div>

</div><h3>Digital crime scene</h3><p>Relationship view derived from submitted evidence.</p></div></div>
        <div class="graph">${graphHtml(data.graph,data)}</div>
        <div class="investigation-timeline">
        <div class="timeline-title">
  <div class="case-timeline-id">
    CASE: ${escapeHtml(data.case?.id || "UNKNOWN")}
  </div>
        

  <div class="timeline-title">
    <span class="eyebrow">INVESTIGATION TIMELINE</span>
    <h3>Digital Forensic Activity</h3>
  </div>

  <div class="timeline">

    <div class="timeline-item">
      <div class="timeline-dot"></div>
      <div class="timeline-content">
        <span>STEP 01</span>
        <strong>CASE CREATED</strong>
        <p>
          A new PHISHTRACE investigation case was created.
        </p>
      </div>
    </div>

    <div class="timeline-item">
      <div class="timeline-dot"></div>
      <div class="timeline-content">
        <span>STEP 02</span>
        <strong>EMAIL PARSED</strong>
        <p>
          Email headers and message content were examined.
        </p>
      </div>
    </div>

    <div class="timeline-item">
      <div class="timeline-dot"></div>
      <div class="timeline-content">
        <span>STEP 03</span>
        <strong>URL EXTRACTION</strong>
        <p>
  ${escapeHtml(
    `${data.urls?.length || 0} URL(s) extracted from the submitted evidence.`
  )}
</p>

      </div>
    </div>

    <div class="timeline-item">
      <div class="timeline-dot"></div>
      <div class="timeline-content">
        <span>STEP 04</span>
        <strong>INDICATORS ANALYZED</strong>
        <p>
  ${escapeHtml(
    `${data.indicators?.length || 0} indicator(s) contributed to the investigation.`
  )}
</p>
      </div>
    </div>

    <div class="timeline-item">
      <div class="timeline-dot"></div>
      <div class="timeline-content">
        <span>STEP 05</span>
        <strong>RISK CALCULATED</strong>
        <p>
  Final assessment:
  <b>${escapeHtml(data.risk_level || "UNKNOWN")}</b>
  — ${escapeHtml(String(data.score ?? 0))}/100.
</p>
      </div>
    </div>

    <div class="timeline-item">
      <div class="timeline-dot"></div>
      <div class="timeline-content">
        <span>STEP 06</span>
        <strong>CASE REPORT READY</strong>
        <p>
          Investigation evidence is available for review and reporting.
        </p>
      </div>
    </div>

  </div>
</div>
      </div>
    </div>`;
      document
    .querySelectorAll(".node-clickable")
    .forEach(node => {

      node.addEventListener("click", () => {

        document
          .querySelectorAll(".node-clickable")
          .forEach(n => {
            n.classList.remove("selected");
          });

        node.classList.add("selected");

        showNodeEvidence(
          node.dataset.nodeId,
          data
        );

      });

    });
  window.scrollTo({top: document.body.scrollHeight, behavior:"smooth"});
}

$("url-form").addEventListener("submit", async (e) => {
  e.preventDefault();
  const form = new FormData();
  form.append("url", $("url-input").value);
  const btn = e.submitter; btn.disabled = true; btn.textContent = "Analyzing...";
  try {
    const res = await fetch("/api/investigate/url", {method:"POST", body:form});
    const data = await res.json();
    if (!res.ok) throw new Error(data.error || "Investigation failed");
    renderResult(data);
    await loadCases();
  } catch(err) {
    alert(err.message);
  } finally {
    btn.disabled = false; btn.textContent = "Analyze URL";
  }
});

$("email-form").addEventListener("submit", async (e) => {
  e.preventDefault();
  const file = $("email-input").files[0];
  if (!file) return;
  const form = new FormData();
  form.append("file", file);
  const btn = e.submitter; btn.disabled = true; btn.textContent = "Investigating...";
  try {
    const res = await fetch("/api/investigate/email", {method:"POST", body:form});
    const data = await res.json();
    if (!res.ok) throw new Error(data.error || "Investigation failed");
    renderResult(data);
    await loadCases();
  } catch(err) {
    alert(err.message);
  } finally {
    btn.disabled = false; btn.textContent = "Investigate Email";
  }
});

loadCases();
