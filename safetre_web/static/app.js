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
  // The single-query stage strip (#pipeline) applies to parse-outside. In
  // parse-inside each analysis step is a WHOLE gateway pass, so we hide that
  // strip and show one box per step in #gateway-live instead.
  const pipeline = document.getElementById("pipeline");
  const gatewayLive = document.getElementById("gateway-live");
  const engineList = document.getElementById("engine-live");
  const gatewayMode = (inside) => {
    if (pipeline) pipeline.hidden = inside;
    if (gatewayLive) gatewayLive.hidden = !inside;
  };

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

  /* --- submit ------------------------------------------------------------------
     One box, one toggle. "Parse outside" plans a single aggregate query outside
     the wall and animates the gateway-check strip. "Parse inside" streams the
     inside analyst's steps, each a box that settles released/denied, so a long
     run reads as working rather than stalled (docs/progress-indicator.md). The
     toggle is present only when the operator enabled the inside path; with it
     absent, everything is outside. */

  const currentMode = () => {
    const picked = document.querySelector("input[name='mode']:checked");
    return picked ? picked.value : "outside";
  };

  const runOutside = async (q, t0) => {
    gatewayMode(false);                       // single-query mode: show the stage strip
    steps.forEach((s) => setStep(s, "checking"));
    result.innerHTML = "<p class=\"hint\">Checking the request in the safepod.</p>";
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
        latency.textContent = `Completed in ${Math.round(performance.now() - t0)}ms · `;
      }
      decorateTables(card);
    } else {
      resetSteps();
    }
  };

  /* --- parse inside: one box per step, streamed as each settles -------------- */

  const ENGINE_TAG = {
    running:  { label: "running",  cls: "tag--blue" },
    released: { label: "released", cls: "tag--green" },
    redacted: { label: "redacted", cls: "tag--yellow" },
    denied:   { label: "denied",   cls: "tag--red" },
    skipped:  { label: "skipped",  cls: "tag--grey" },
    review:   { label: "review",   cls: "tag--yellow" },
  };

  const liveBox = (list, id, subq) => {
    const li = document.createElement("li");
    li.className = "step";
    li.innerHTML =
      "<span class=\"step-circle\" aria-hidden=\"true\"></span>" +
      "<span class=\"step-name\"></span>" +
      "<strong class=\"tag step-status\"></strong>";
    li.querySelector(".step-circle").textContent = id;
    li.querySelector(".step-name").textContent = subq;      // textContent: never HTML
    list.appendChild(li);
    return li;
  };

  const settleBox = (li, status) => {
    const s = ENGINE_TAG[status] || ENGINE_TAG.skipped;
    const tag = li.querySelector(".step-status");
    tag.textContent = s.label;
    tag.className = `tag step-status ${s.cls}`;
  };

  const runInsideBlocking = async (q) => {
    const resp = await fetch("/api/chimp", {
      method: "POST",
      headers: { "Content-Type": "application/json", "Accept": "text/html" },
      body: JSON.stringify({ q }),
    });
    result.innerHTML = await resp.text();
    decorateTables(result);
  };

  const runInside = async (q) => {
    resetSteps();
    gatewayMode(true);                        // internal mode: per-step boxes ARE the gateway view
    engineList.innerHTML = "";
    result.innerHTML =
      "<p class=\"hint\">The safe analysis engine is working inside the environment&hellip;</p>";
    let resp = null;
    try {
      resp = await fetch("/api/chimp/stream", {
        method: "POST",
        headers: { "Content-Type": "application/json", "Accept": "text/event-stream" },
        body: JSON.stringify({ q }),
      });
    } catch (e) { resp = null; }
    if (!resp || !resp.ok || !resp.body || !window.ReadableStream) {
      gatewayMode(false);                     // no live view; the dossier still lists the steps
      return runInsideBlocking(q);
    }
    const list = engineList;
    const boxes = {};
    const reader = resp.body.getReader();
    const decoder = new TextDecoder();
    let buf = "";
    for (;;) {
      const { value, done } = await reader.read();
      if (done) break;
      buf += decoder.decode(value, { stream: true });
      let sep;
      while ((sep = buf.indexOf("\n\n")) >= 0) {
        const chunk = buf.slice(0, sep);
        buf = buf.slice(sep + 2);
        let event = "message", data = "";
        chunk.split("\n").forEach((line) => {
          if (line.startsWith("event:")) event = line.slice(6).trim();
          else if (line.startsWith("data:")) data += line.slice(5).trim();
        });
        if (!data) continue;
        const payload = JSON.parse(data);
        if (event === "step_start") {
          boxes[payload.id] = liveBox(list, payload.id, payload.sub_question);
          settleBox(boxes[payload.id], "running");
        } else if (event === "step") {
          const li = boxes[payload.id] || liveBox(list, payload.id, payload.sub_question);
          settleBox(li, payload.status);
        } else if (event === "done") {
          result.innerHTML = payload.html;
          decorateTables(result);
        }
      }
    }
  };

  const run = async () => {
    const q = input.value.trim();
    if (!q) return;

    const mode = currentMode();
    button.disabled = true;
    const t0 = performance.now();

    try {
      if (mode === "inside") await runInside(q);
      else await runOutside(q, t0);
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
