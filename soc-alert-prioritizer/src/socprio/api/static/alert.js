(() => {
  "use strict";

  const form = document.getElementById("triage");
  const toast = document.getElementById("toast");

  function notify(message) {
    toast.textContent = message;
    toast.classList.add("show");
    setTimeout(() => toast.classList.remove("show"), 2500);
  }

  form.addEventListener("submit", async (event) => {
    event.preventDefault();
    const data = new FormData(form);
    const body = { status: data.get("status"), notes: data.get("notes") };
    if (data.get("verdict")) body.verdict = data.get("verdict");

    const headers = { "Content-Type": "application/json" };
    if (data.get("api_key")) headers["X-API-Key"] = data.get("api_key");

    const response = await fetch(`/api/alerts/${encodeURIComponent(form.dataset.id)}`, {
      method: "PATCH", headers, body: JSON.stringify(body),
    });
    if (response.ok) {
      notify("Saved");
      setTimeout(() => window.location.reload(), 600);
    } else {
      const detail = await response.json().catch(() => ({}));
      notify(`Save failed: ${detail.detail ?? response.status}`);
    }
  });
})();
