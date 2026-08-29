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
  if (!form || !select) return;

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
})();
