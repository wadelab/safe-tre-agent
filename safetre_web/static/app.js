// Minimal vanilla fetch — keeps CSP at script-src 'self' (no external JS).
document.addEventListener("DOMContentLoaded", () => {
  const form = document.getElementById("qform");
  const input = document.getElementById("q");
  const result = document.getElementById("result");

  form.addEventListener("submit", async (e) => {
    e.preventDefault();
    const q = input.value.trim();
    if (!q) return;
    result.innerHTML = '<p class="muted">running…</p>';
    try {
      const resp = await fetch("/api/query", {
        method: "POST",
        headers: { "Content-Type": "application/json", "Accept": "text/html" },
        body: JSON.stringify({ q }),
      });
      // server returns an escaped HTML partial (Jinja autoescape; pandas escape=True)
      result.innerHTML = await resp.text();
    } catch (err) {
      result.innerHTML = '<p class="muted">request failed</p>';
    }
  });
});
