(() => {
  const status = document.getElementById("scan-status");
  if (!status) return;
  const id = window.location.pathname.split("/")[2];
  const endpoint = `/api/scan/${encodeURIComponent(id)}`;
  const poll = async () => {
    try {
      const response = await fetch(endpoint, { credentials: "same-origin" });
      if (!response.ok) throw new Error(`Status request failed (${response.status})`);
      const state = await response.json();
      status.textContent = state.status;
      document.getElementById("scan-phase").textContent = state.phase;
      document.getElementById("scan-error").textContent = state.error || "";
      if (state.status !== "running" && state.status !== "idle") return;
    } catch (error) {
      document.getElementById("scan-error").textContent = error.message;
    }
    window.setTimeout(poll, 1200);
  };
  poll();
})();
