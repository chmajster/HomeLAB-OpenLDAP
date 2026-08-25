(() => {
  const root = document.documentElement;
  const preference = root.dataset.themePreference;
  if (preference !== "system") return;

  const media = window.matchMedia("(prefers-color-scheme: dark)");
  const apply = () => root.setAttribute("data-bs-theme", media.matches ? "dark" : "light");
  apply();
  media.addEventListener("change", apply);
})();
