// Minimal vanilla fetch keeps CSP at script-src 'self'.
document.addEventListener("DOMContentLoaded", () => {
  const form = document.getElementById("qform");
  const input = document.getElementById("q");
  const result = document.getElementById("result");
  const button = document.getElementById("runbtn");
  const counter = document.getElementById("charcount");

  const updateCount = () => {
    counter.textContent = `${input.value.length} / ${input.maxLength}`;
  };

  document.querySelectorAll("[data-query]").forEach((example) => {
    example.addEventListener("click", () => {
      input.value = example.dataset.query;
      updateCount();
      input.focus();
    });
  });

  input.addEventListener("input", updateCount);
  updateCount();

  form.addEventListener("submit", async (e) => {
    e.preventDefault();
    const q = input.value.trim();
    if (!q) return;

    button.disabled = true;
    button.textContent = "Running";
    result.innerHTML = `
      <div class="empty-state">
        <span class="dot"></span>
        <div><strong>Running</strong><p>Checking the request inside the safepod.</p></div>
      </div>`;
    try {
      const resp = await fetch("/api/query", {
        method: "POST",
        headers: { "Content-Type": "application/json", "Accept": "text/html" },
        body: JSON.stringify({ q }),
      });
      result.innerHTML = await resp.text();
    } catch (err) {
      result.innerHTML = `
        <div class="empty-state">
          <span class="dot"></span>
          <div><strong>Request failed</strong><p>Try again or contact the TRE operator.</p></div>
        </div>`;
    } finally {
      button.disabled = false;
      button.textContent = "Run query";
    }
  });
});
