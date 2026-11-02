(() => {
  const $ = (s) => document.querySelector(s);
  const STATUS = {
    expired: "Expired",
    critical: "7 days or less",
    warning: "30 days or less",
    ok: "Healthy",
    error: "No SSL",
  };
  const ORDER = ["expired", "critical", "warning", "ok", "error"];
  const state = { domain: "", rows: [], filter: "all", search: "", sortKey: "expires_at", sortDir: 1, jobId: null, timer: null };

  // ---------- helpers
  const el = (tag, cls, text) => {
    const n = document.createElement(tag);
    if (cls) n.className = cls;
    if (text !== undefined) n.textContent = text;
    return n;
  };
  const day = (iso) => (iso ? iso.slice(0, 10) : "");

  function setError(msg) { $("#form-error").textContent = msg || ""; }

  // ---------- start a scan
  $("#scan-form").addEventListener("submit", async (e) => {
    e.preventDefault();
    setError("");
    const domain = $("#domain").value.trim();
    if (!domain) { setError("Enter a website address, for example example.com."); $("#domain").focus(); return; }
    stop();
    $("#scan-btn").disabled = true;
    $("#results").hidden = true;
    $("#warnings").hidden = true;
    state.rows = []; state.filter = "all"; state.search = ""; $("#search").value = "";
    showProgress("Starting scan…", null);
    try {
      const r = await fetch("/api/scan", {
        method: "POST", headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ domain, deep: $("#deep").checked }),
      });
      const data = await r.json();
      if (!r.ok) throw new Error(data.error || "Could not start the scan.");
      state.jobId = data.id;
      poll();
    } catch (err) {
      $("#progress").hidden = true;
      $("#scan-btn").disabled = false;
      setError(err.message);
    }
  });

  function stop() { clearTimeout(state.timer); }

  function showProgress(text, pct) {
    $("#progress").hidden = false;
    const bar = document.querySelector(".bar");
    bar.classList.toggle("indeterminate", pct === null);
    $("#bar-fill").style.width = pct === null ? "" : pct + "%";
    if (pct !== null) bar.setAttribute("aria-valuenow", Math.round(pct)); else bar.removeAttribute("aria-valuenow");
    $("#progress-text").textContent = text;
  }

  async function poll() {
    try {
      const r = await fetch(`/api/scan/${state.jobId}`);
      const snap = await r.json();
      if (!r.ok) throw new Error(snap.error || "Lost track of the scan.");
      render(snap);
      if (snap.phase === "done") return finish(snap);
      if (snap.phase === "failed") throw new Error(snap.error || "The scan failed.");
      state.timer = setTimeout(poll, 1000);
    } catch (err) {
      $("#progress").hidden = true;
      $("#scan-btn").disabled = false;
      setError(err.message);
    }
  }

  function finish(snap) {
    $("#progress").hidden = true;
    $("#scan-btn").disabled = false;
    for (const [id, ext] of [["#dl-xlsx", "xlsx"], ["#dl-pdf", "pdf"]]) {
      const a = $(id);
      a.href = `/api/scan/${snap.id}/export.${ext}`;
      a.setAttribute("aria-disabled", "false");
    }
    $("#results-sub").textContent = `Checked ${snap.total} hostname${snap.total === 1 ? "" : "s"}. Soonest expiry first.`;
  }

  // ---------- render
  function render(snap) {
    state.rows = snap.results;
    state.domain = snap.domain;
    if (snap.phase === "discovering" || snap.phase === "queued") {
      showProgress(`Searching certificate logs for subdomains of ${snap.domain}…`, null);
    } else if (snap.phase === "scanning") {
      const pct = snap.total ? (snap.done / snap.total) * 100 : 0;
      showProgress(`Checking certificates: ${snap.done} of ${snap.total} hostnames`, pct);
    }
    const w = $("#warnings");
    w.replaceChildren(...snap.warnings.map((t) => el("p", "", t)));
    w.hidden = snap.warnings.length === 0;

    $("#results").hidden = snap.phase === "discovering" || snap.phase === "queued";
    $("#results-title").textContent = `Certificates for ${snap.domain}`;
    if (snap.phase !== "done") {
      $("#results-sub").textContent = "Results appear as each hostname is checked.";
      for (const id of ["#dl-xlsx", "#dl-pdf"]) { $(id).setAttribute("aria-disabled", "true"); $(id).removeAttribute("href"); }
    }
    renderChips(snap.summary);
    renderRows();
  }

  function renderChips(summary) {
    const box = $("#chips");
    const defs = [["all", "All", summary.total], ...ORDER.map((k) => [k, STATUS[k], summary[k]])];
    box.replaceChildren(...defs.filter(([k, , n]) => k === "all" || n > 0).map(([k, label, n]) => {
      const b = el("button", "chip");
      b.type = "button"; b.dataset.status = k;
      b.setAttribute("aria-pressed", String(state.filter === k));
      b.append(el("span", "", label), el("span", "n", String(n)));
      b.addEventListener("click", () => { state.filter = k; renderChips(summary); renderRows(); });
      return b;
    }));
  }

  function compare(a, b) {
    const k = state.sortKey;
    // hosts without a certificate always sit at the bottom of date/number sorts
    if ((k === "expires_at" || k === "days_left") && (a[k] === null || b[k] === null)) {
      if (a[k] === b[k]) return a.host.localeCompare(b.host);
      return a[k] === null ? 1 : -1;
    }
    let x = a[k], y = b[k];
    if (k === "status") { x = ORDER.indexOf(x); y = ORDER.indexOf(y); }
    if (x === y) return a.host.localeCompare(b.host);
    return (x > y ? 1 : -1) * state.sortDir;
  }

  function renderRows() {
    const q = state.search.toLowerCase();
    const rows = state.rows
      .filter((r) => (state.filter === "all" || r.status === state.filter) && (!q || r.host.includes(q)))
      .sort(compare);
    $("#rows").replaceChildren(...rows.map(rowEl));
    $("#empty").hidden = rows.length > 0;
  }

  function rowEl(r) {
    const tr = el("tr");
    const hostTd = el("td", "host", r.host);
    if (r.host === state.domain) hostTd.append(el("span", "note", "Main domain"));
    tr.append(hostTd);

    const st = el("td");
    st.append(el("span", `pill ${r.status}`, STATUS[r.status]));
    if (r.status !== "error" && r.trusted === false) {
      const n = el("span", "note bad", "Not trusted");
      n.title = r.trust_error || "The certificate failed verification";
      st.append(n);
    }
    tr.append(st);

    tr.append(el("td", "mono", day(r.expires_at) || "–"));

    const left = el("td");
    if (r.days_left === null) {
      left.append(el("span", "muted", "–"));
    } else {
      const wrap = el("div", "left");
      wrap.append(el("span", "txt", r.days_left < 0 ? `${-r.days_left} d ago` : `${r.days_left} days`));
      const run = el("div", `runway ${r.status}`);
      const fill = el("i");
      if (r.days_left >= 0) fill.style.width = Math.max(4, Math.min(100, (r.days_left / 90) * 100)) + "%";
      run.append(fill);
      wrap.append(run);
      left.append(wrap);
    }
    tr.append(left);

    const iss = el("td", "issuer", r.status === "error" ? "" : r.issuer || "–");
    if (r.status === "error") iss.append(el("span", "muted", r.error));
    tr.append(iss);

    tr.append(el("td", "mono", r.ip || "–"));
    return tr;
  }

  // ---------- sorting, search
  document.querySelectorAll("th[data-key]").forEach((th) => {
    th.querySelector("button").addEventListener("click", () => {
      const key = th.dataset.key;
      state.sortDir = state.sortKey === key ? -state.sortDir : 1;
      state.sortKey = key;
      document.querySelectorAll("th[data-key]").forEach((h) => h.setAttribute("aria-sort", "none"));
      th.setAttribute("aria-sort", state.sortDir === 1 ? "ascending" : "descending");
      renderRows();
    });
  });
  $("#search").addEventListener("input", (e) => { state.search = e.target.value.trim(); renderRows(); });
})();
