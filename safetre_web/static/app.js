// Minimal vanilla JS keeps CSP at script-src 'self'. No inline styles are ever
// written into the DOM as attributes: visual state is class toggling plus CSSOM
// custom properties (element.style.setProperty), which style-src permits.
document.addEventListener("DOMContentLoaded", () => {
  const form = document.getElementById("qform");
  const input = document.getElementById("q");
  const result = document.getElementById("result");
  const button = document.getElementById("runbtn");
  const counter = document.getElementById("charcount");
  const pipeline = document.getElementById("pipeline");
  const nodes = pipeline ? [...pipeline.querySelectorAll(".pipe-node")] : [];
  let scanTimer = null;

  const updateCount = () => {
    counter.textContent = `${input.value.length} / ${input.maxLength}`;
  };

  const emptyState = (title, msg) => `
    <div class="empty-state">
      <span class="beacon"></span>
      <div><strong>${title}</strong><p>${msg}</p></div>
    </div>`;

  /* --- pipeline ----------------------------------------------------------- */

  const resetPipeline = () => {
    clearInterval(scanTimer);
    pipeline.classList.remove("running");
    nodes.forEach((n) => n.classList.remove("active", "ok", "warn", "fail"));
  };

  const startScan = () => {
    resetPipeline();
    pipeline.classList.add("running");
    let i = 0;
    nodes[0].classList.add("active");
    scanTimer = setInterval(() => {
      i = (i + 1) % nodes.length;
      nodes.forEach((n) => n.classList.remove("active"));
      nodes[i].classList.add("active");
    }, 260);
  };

  // Final stage states come from the server's own trace: the card carries the
  // ordered stage names that actually ran (data-stages) and the outcome
  // (data-status). Stages that never ran stay dark.
  const finishPipeline = (card) => {
    resetPipeline();
    const status = card.dataset.status;
    const stages = (card.dataset.stages || "").split(",").filter(Boolean);
    const ran = new Set(stages);
    const last = stages[stages.length - 1];
    nodes.forEach((n) => {
      const s = n.dataset.stage;
      if (!ran.has(s)) return;
      if (s === last && status === "denied") n.classList.add("fail");
      else if (s === last && status === "review") n.classList.add("warn");
      else if (s === "gateway" && status === "redacted") n.classList.add("warn");
      else n.classList.add("ok");
    });
  };

  /* --- table decoration ----------------------------------------------------
     Redaction drops whole rows, so a NaN in a released table means "not
     computable"; those cells get a labelled hatch. Numeric columns
     right-align; the released `value` column gets a single-hue magnitude bar
     (skipped when any value is negative, e.g. correlations). */

  const NUMERIC = /^-?\d[\d,]*(\.\d+)?$/;

  const decorateTables = (scope) => {
    scope.querySelectorAll("table.agg").forEach((table) => {
      const heads = [...table.querySelectorAll("thead th")];
      const rows = [...table.querySelectorAll("tbody tr")];
      if (!heads.length || !rows.length) return;

      const cell = (row, c) => row.children[c];
      heads.forEach((th, c) => {
        const texts = rows.map((r) => cell(r, c)?.textContent.trim() ?? "");
        texts.forEach((t, i) => {
          if (t === "NaN") {
            const td = cell(rows[i], c);
            td.classList.add("suppressed");
            td.textContent = "n/a";
          }
        });
        const live = texts.filter((t) => t !== "NaN" && t !== "");
        if (live.length && live.every((t) => NUMERIC.test(t))) {
          th.classList.add("num");
          rows.forEach((r) => cell(r, c)?.classList.add("num"));
          if (th.textContent.trim() === "value") {
            const vals = live.map((t) => parseFloat(t.replace(/,/g, "")));
            const max = Math.max(...vals);
            if (max > 0 && vals.every((v) => v >= 0)) {
              rows.forEach((r) => {
                const td = cell(r, c);
                const v = parseFloat(td.textContent.replace(/,/g, ""));
                if (!Number.isNaN(v)) {
                  td.classList.add("bar");
                  td.style.setProperty("--w", `${((v / max) * 100).toFixed(1)}%`);
                }
              });
            }
          }
        }
      });
    });
  };

  /* --- submit --------------------------------------------------------------- */

  const run = async () => {
    const q = input.value.trim();
    if (!q) return;

    button.disabled = true;
    button.classList.add("loading");
    button.textContent = "Checking";
    result.innerHTML = emptyState("Running", "Checking the request inside the safepod.");
    startScan();
    const t0 = performance.now();

    try {
      const resp = await fetch("/api/query", {
        method: "POST",
        headers: { "Content-Type": "application/json", "Accept": "text/html" },
        body: JSON.stringify({ q }),
      });
      result.innerHTML = await resp.text();
      const card = result.querySelector(".result-card");
      if (card) {
        finishPipeline(card);
        const latency = card.querySelector(".latency");
        if (latency) latency.textContent = `${Math.round(performance.now() - t0)} ms`;
        decorateTables(card);
      } else {
        resetPipeline();
      }
    } catch (err) {
      resetPipeline();
      result.innerHTML = emptyState("Request failed",
        "Try again or contact the TRE operator.");
    } finally {
      button.disabled = false;
      button.classList.remove("loading");
      button.textContent = "Run query";
    }
  };

  form.addEventListener("submit", (e) => {
    e.preventDefault();
    run();
  });

  input.addEventListener("keydown", (e) => {
    if ((e.ctrlKey || e.metaKey) && e.key === "Enter") {
      e.preventDefault();
      run();
    }
  });

  document.querySelectorAll("[data-query]").forEach((example) => {
    example.addEventListener("click", () => {
      input.value = example.dataset.query;
      updateCount();
      run();
    });
  });

  input.addEventListener("input", updateCount);
  updateCount();

  // Shareable prefill: /#q=mean%20spend%20by%20age%20band runs on load.
  const hash = new URLSearchParams(location.hash.slice(1));
  const preset = hash.get("q");
  if (preset) {
    input.value = preset.slice(0, input.maxLength);
    updateCount();
    run();
  }
});
