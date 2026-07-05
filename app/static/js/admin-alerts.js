(() => {
  function showDetail(ref, link, links, panels) {
    const panel = document.getElementById(`alert-detail-${ref}`);
    if (!panel) return;

    panels.forEach((item) => {
      item.hidden = item.dataset.alertRef !== ref;
    });
    links.forEach((item) => {
      item.setAttribute("aria-expanded", item.dataset.alertRef === ref ? "true" : "false");
    });

    if (window.history && typeof window.history.replaceState === "function") {
      window.history.replaceState(null, "", link.href);
    }
    panel.focus({ preventScroll: true });
    if (typeof panel.scrollIntoView === "function") {
      panel.scrollIntoView({ block: "nearest" });
    }
  }

  function initAlertDetails() {
    const links = Array.from(document.querySelectorAll("[data-alert-detail-link]"));
    const panels = Array.from(document.querySelectorAll("[data-alert-detail-panel]"));
    if (!links.length || !panels.length) return;

    links.forEach((link) => {
      link.addEventListener("click", (event) => {
        const ref = link.dataset.alertRef || "";
        if (!ref || !document.getElementById(`alert-detail-${ref}`)) return;
        event.preventDefault();
        showDetail(ref, link, links, panels);
      });
    });
  }

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", initAlertDetails);
  } else {
    initAlertDetails();
  }
})();
