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
    const body = { notes: data.get("notes") };
    // Only send the status when the analyst changed it, so that recording a
    // verdict alone lets the server close the alert.
    if (data.get("status") !== form.dataset.status) body.status = data.get("status");
    if (data.get("verdict")) body.verdict = data.get("verdict");

    const response = await fetch(`/api/alerts/${encodeURIComponent(form.dataset.id)}`, {
      method: "PATCH",
      headers: { "Content-Type": "application/json" },
      credentials: "same-origin",
      body: JSON.stringify(body),
    });
    if (response.status === 401) {
      window.location = "/login";
      return;
    }
    if (response.ok) {
      notify("Saved");
      setTimeout(() => window.location.reload(), 600);
    } else {
      const detail = await response.json().catch(() => ({}));
      notify(`Save failed: ${detail.detail ?? response.status}`);
    }
  });

  document.querySelectorAll("tr[data-href]").forEach((row) => {
    row.addEventListener("click", () => { window.location = row.dataset.href; });
  });
})();
