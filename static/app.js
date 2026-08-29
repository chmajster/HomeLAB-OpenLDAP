(() => {
  const root = document.documentElement;
  const preference = root.dataset.themePreference;
  if (preference === "system") {
    const media = window.matchMedia("(prefers-color-scheme: dark)");
    const apply = () => root.setAttribute("data-bs-theme", media.matches ? "dark" : "light");
    apply();
    media.addEventListener("change", apply);
  }

  const form = document.getElementById("ldap-server-switcher");
  const select = document.getElementById("ldap-server-select");
  if (form && select) {
    const selectedId = String(select.dataset.selectedServer || "");
    fetch("/api/v1/ldap-servers/available", {headers: {Accept: "application/json"}})
      .then((response) => {
        if (!response.ok) throw new Error(`HTTP ${response.status}`);
        return response.json();
      })
      .then((servers) => {
        select.replaceChildren();
        if (!Array.isArray(servers) || servers.length === 0) {
          const option = document.createElement("option");
          option.textContent = "No enabled LDAP servers";
          select.appendChild(option);
          return;
        }
        for (const server of servers) {
          const option = document.createElement("option");
          option.value = String(server.id);
          option.textContent = `${server.name} · ${server.url}`;
          option.selected = selectedId ? String(server.id) === selectedId : false;
          select.appendChild(option);
        }
        select.disabled = false;
        select.addEventListener("change", () => form.submit());
      })
      .catch(() => {
        select.replaceChildren();
        const option = document.createElement("option");
        option.textContent = "LDAP server list unavailable";
        select.appendChild(option);
      });
  }

  const replicationRoot = document.querySelector("[data-replication-status]");
  if (!replicationRoot) return;
  const tbody = replicationRoot.querySelector("tbody");
  const summary = document.getElementById("replication-summary");
  const escapeText = (value) => String(value ?? "");
  const badgeClass = (status) => {
    if (status === "healthy") return "text-bg-success";
    if (status === "lagging") return "text-bg-warning";
    if (status === "critical" || status === "disconnected") return "text-bg-danger";
    return "text-bg-secondary";
  };

  fetch("/api/v1/replication/status", {headers: {Accept: "application/json"}})
    .then((response) => {
      if (!response.ok) throw new Error(`HTTP ${response.status}`);
      return response.json();
    })
    .then((payload) => {
      const items = Array.isArray(payload.items) ? payload.items : [];
      if (summary && payload.summary) {
        summary.textContent = `${payload.summary.healthy}/${payload.summary.total} healthy · ${payload.summary.lagging} lagging · ${payload.summary.disconnected} disconnected`;
      }
      if (!tbody) return;
      tbody.replaceChildren();
      if (items.length === 0) {
        const row = document.createElement("tr");
        const cell = document.createElement("td");
        cell.colSpan = 7;
        cell.className = "text-secondary";
        cell.textContent = "No syncrepl consumers configured.";
        row.appendChild(cell);
        tbody.appendChild(row);
        return;
      }
      for (const item of items) {
        const row = document.createElement("tr");
        const values = [item.rid || "—", item.provider || "—", item.searchbase || "—"];
        for (const value of values) {
          const cell = document.createElement("td");
          cell.textContent = escapeText(value);
          row.appendChild(cell);
        }
        const statusCell = document.createElement("td");
        const badge = document.createElement("span");
        badge.className = `badge ${badgeClass(item.status)}`;
        badge.textContent = escapeText(item.status);
        statusCell.appendChild(badge);
        row.appendChild(statusCell);

        const lagCell = document.createElement("td");
        lagCell.textContent = item.lag_seconds == null ? "—" : `${Number(item.lag_seconds).toFixed(0)} s`;
        row.appendChild(lagCell);
        const latencyCell = document.createElement("td");
        latencyCell.textContent = item.provider_latency_ms == null ? "—" : `${Number(item.provider_latency_ms).toFixed(1)} ms`;
        row.appendChild(latencyCell);
        const errorCell = document.createElement("td");
        errorCell.textContent = escapeText(item.error || "");
        row.appendChild(errorCell);
        tbody.appendChild(row);
      }
    })
    .catch((error) => {
      if (summary) summary.textContent = `Monitoring unavailable: ${error.message}`;
      if (tbody) {
        tbody.replaceChildren();
        const row = document.createElement("tr");
        const cell = document.createElement("td");
        cell.colSpan = 7;
        cell.className = "text-danger";
        cell.textContent = "Unable to load replication health.";
        row.appendChild(cell);
        tbody.appendChild(row);
      }
    });
})();
