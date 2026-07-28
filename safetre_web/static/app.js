// Minimal vanilla JS keeps CSP at script-src 'self'. No decorative animation
// (GOV.UK design language); state changes are class/text swaps only, and the
// result region is an aria-live landmark so outcomes are announced.
document.addEventListener("DOMContentLoaded", () => {
  const form = document.getElementById("qform");
  const input = document.getElementById("q");
  const result = document.getElementById("result");
  const button = document.getElementById("runbtn");
  const countMsg = document.getElementById("q-info");
  const steps = [...document.querySelectorAll("#pipeline .step")];

  /* --- character count (GOV.UK character-count behaviour) ------------------- */

  const updateCount = () => {
    const remaining = input.maxLength - input.value.length;
    countMsg.textContent = remaining === 1
      ? "You have 1 character remaining"
      : `You have ${remaining} characters remaining`;
  };

  /* --- gateway checks step list ---------------------------------------------
     Step state is text in a tag, never colour alone. Final states come from
     the server's own trace: the result card carries the ordered stage names
     that ran (data-stages) and the outcome (data-status). */

  const STATES = {
    notrun:   { label: "Not run",   cls: "tag--grey" },
    checking: { label: "Checking",  cls: "tag--blue" },
    done:     { label: "Completed", cls: "tag--green" },
    stopped:  { label: "Stopped",   cls: "tag--red" },
    redacted: { label: "Redacted",  cls: "tag--yellow" },
    review:   { label: "Review",    cls: "tag--yellow" },
  };

  const setStep = (step, state) => {
    const tag = step.querySelector(".step-status");
    tag.textContent = STATES[state].label;
    tag.className = `tag step-status ${STATES[state].cls}`;
  };

  const resetSteps = () => steps.forEach((s) => setStep(s, "notrun"));

  const finishSteps = (card) => {
    resetSteps();
    const status = card.dataset.status;
    const stages = (card.dataset.stages || "").split(",").filter(Boolean);
    const ran = new Set(stages);
    const last = stages[stages.length - 1];
    steps.forEach((step) => {
      const s = step.dataset.stage;
      if (!ran.has(s)) return;
      if (s === last && status === "denied") setStep(step, "stopped");
      else if (s === last && status === "review") setStep(step, "review");
      else if (s === "gateway" && status === "redacted") setStep(step, "redacted");
      else setStep(step, "done");
    });
  };

  /* --- table decoration ------------------------------------------------------
     Numeric columns right-align; a NaN in a released table means the value was
     suppressed or not computable, shown as "[c]" (the ONS convention) with a
     footnote. */

  const NUMERIC = /^-?\d[\d,]*(\.\d+)?$/;

  const decorateTables = (card) => {
    let anySuppressed = false;
    card.querySelectorAll("table.agg").forEach((table) => {
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
            td.textContent = "[c]";
            anySuppressed = true;
          }
        });
        const live = texts.filter((t) => t !== "NaN" && t !== "");
        if (live.length && live.every((t) => NUMERIC.test(t))) {
          th.classList.add("num");
          rows.forEach((r) => cell(r, c)?.classList.add("num"));
        }
      });
    });
    if (anySuppressed) {
      const wrap = card.querySelector(".table-wrap");
      if (wrap) {
        const note = document.createElement("p");
        note.className = "table-footnote";
        note.textContent = "[c] — value suppressed or not computable";
        wrap.insertAdjacentElement("afterend", note);
      }
    }
  };

  /* --- submit ------------------------------------------------------------------ */

  const run = async () => {
    const q = input.value.trim();
    if (!q) return;

    button.disabled = true;
    steps.forEach((s) => setStep(s, "checking"));
    result.innerHTML = "<p class=\"hint\">Checking the request in the safepod.</p>";
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
        finishSteps(card);
        const latency = card.querySelector(".latency");
        if (latency) {
          latency.textContent =
            `Completed in ${Math.round(performance.now() - t0)}ms · `;
        }
        decorateTables(card);
      } else {
        resetSteps();
      }
    } catch (err) {
      resetSteps();
      result.innerHTML =
        "<p class=\"hint\">The request failed. Try again or contact the TRE operator.</p>";
    } finally {
      button.disabled = false;
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

  // Shareable prefill: /#q=mean%20spend%20by%20age%20band fills the box.
  //
  // It fills it and stops. Running on load meant a link could put an
  // attacker-chosen string into the HMAC-chained audit log under whoever
  // opened it — and because the request was answered, the planted row recorded
  // `status=released` with an output shape, so the log read as that person
  // asking for identifiable data and being granted it. The chain proves an
  // entry is authentic; it was never able to prove a human composed it. A
  // click is the consent that closes the gap (hardening #50).
  //
  // Auto-run survives only as an explicitly enabled capture affordance for the
  // screenshot and deck scripts, which drive a headless browser that cannot
  // click. It is off unless the server sets SAFETRE_ALLOW_PREFILL_AUTORUN, and
  // like SAFETRE_ALLOW_TEST_CLIENT it is a sentinel: never enable it on a real
  // deployment.
  const hash = new URLSearchParams(location.hash.slice(1));
  const preset = hash.get("q");
  if (preset) {
    input.value = preset.slice(0, input.maxLength);
    updateCount();
    input.focus();
    if (document.body.dataset.autorunPrefill === "1") {
      run();
    }
  }
});
