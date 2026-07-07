(() => {
  function text(value, fallback) {
    const clean = value === null || value === undefined ? "" : String(value);
    return clean || fallback || "";
  }

  function appendTextCell(row, value, fallback) {
    const cell = document.createElement("td");
    cell.textContent = text(value, fallback);
    row.appendChild(cell);
    return cell;
  }

  function eventRow(item) {
    const row = document.createElement("tr");

    const timeCell = document.createElement("td");
    const time = document.createElement("time");
    time.dateTime = text(item.created_at_utc);
    time.textContent = text(item.created_at_display);
    timeCell.appendChild(time);
    row.appendChild(timeCell);

    const activityCell = document.createElement("td");
    const strong = document.createElement("strong");
    strong.textContent = text(item.activity);
    const type = document.createElement("span");
    type.className = "muted";
    type.textContent = text(item.event_type);
    activityCell.append(strong, document.createElement("br"), type);
    row.appendChild(activityCell);

    appendTextCell(row, item.severity, "none");
    appendTextCell(row, item.outcome);
    appendTextCell(row, item.actor_role);
    appendTextCell(row, `${text(item.source_kind, "unknown")}: ${text(item.source_display, "unknown")}`);
    appendTextCell(row, item.request_id);
    appendTextCell(row, item.target_ref, "none");

    const detailCell = document.createElement("td");
    const detailLink = document.createElement("a");
    detailLink.href = text(item.detail_url, "#");
    detailLink.textContent = "Open";
    detailCell.appendChild(detailLink);
    row.appendChild(detailCell);

    return row;
  }

  function emptyRow() {
    const row = document.createElement("tr");
    const cell = document.createElement("td");
    cell.colSpan = 9;
    cell.textContent = "No audit events match the current filters.";
    row.appendChild(cell);
    return row;
  }

  function setPageLink(link, url) {
    if (!link) return;
    const disabled = !url;
    if (disabled) {
      link.removeAttribute("href");
      link.setAttribute("aria-disabled", "true");
      link.setAttribute("tabindex", "-1");
      link.classList.add("is-disabled");
      return;
    }
    link.href = url;
    link.removeAttribute("aria-disabled");
    link.removeAttribute("tabindex");
    link.classList.remove("is-disabled");
  }

  function updateAuditLogs(root, payload) {
    const tbody = root.querySelector("[data-audit-table-body]");
    const resultCount = root.querySelector("[data-audit-result-count]");
    const pageIndicator = root.querySelector("[data-audit-page-indicator]");
    if (!tbody || !resultCount || !pageIndicator) return;

    const events = Array.isArray(payload.events) ? payload.events : [];
    tbody.replaceChildren(...(events.length ? events.map(eventRow) : [emptyRow()]));

    const total = Number(payload.total || 0);
    const page = Number(payload.page || 1);
    const totalPages = Number(payload.total_pages || 1);
    const summary = `${total} result(s), page ${page} of ${totalPages}`;
    resultCount.textContent = summary;
    pageIndicator.textContent = `Page ${page} of ${totalPages}`;

    setPageLink(root.querySelector("[data-audit-prev]"), payload.previous_page_url || "");
    setPageLink(root.querySelector("[data-audit-next]"), payload.next_page_url || "");
  }

  function fetchAuditPage(root, url, pushHistory) {
    root.setAttribute("aria-busy", "true");
    return fetch(url, {
      headers: { Accept: "application/json" },
      credentials: "same-origin",
    })
      .then((response) => {
        if (!response.ok) throw new Error("audit pagination failed");
        return response.json();
      })
      .then((payload) => {
        updateAuditLogs(root, payload);
        const browserHistory = globalThis.history;
        if (pushHistory && browserHistory && typeof browserHistory.pushState === "function") {
          browserHistory.pushState({ auditLogs: true }, "", url);
        }
      })
      .finally(() => {
        root.removeAttribute("aria-busy");
      });
  }

  function initAuditLogs() {
    const root = document.querySelector("[data-audit-log-browser]");
    if (!root) return;

    root.addEventListener("click", (event) => {
      const target = event.target instanceof Element ? event.target : null;
      const link = target ? target.closest("[data-audit-page-link]") : null;
      if (!link?.href || link.getAttribute("aria-disabled") === "true") return;
      event.preventDefault();
      fetchAuditPage(root, link.href, true).catch(() => {
        globalThis.location.assign(link.href);
      });
    });

    globalThis.addEventListener("popstate", () => {
      fetchAuditPage(root, globalThis.location.href, false).catch(() => {
        globalThis.location.reload();
      });
    });
  }

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", initAuditLogs);
  } else {
    initAuditLogs();
  }
})();
