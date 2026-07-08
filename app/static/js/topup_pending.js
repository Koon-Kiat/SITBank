(function () {
  "use strict";

  globalThis.addEventListener("DOMContentLoaded", function () {
    const root = document.querySelector("[data-topup-pending]");
    if (!root) {
      return;
    }

    const statusUrl = root.dataset.statusUrl;
    const dashboardUrl = root.dataset.dashboardUrl;
    const restartUrl = root.dataset.restartUrl;
    const statusMessage = document.querySelector("[data-topup-status-message]");

    function showRestartLink() {
      const link = document.createElement("a");
      link.className = "button secondary";
      link.href = restartUrl;
      link.textContent = "Start over";
      statusMessage.after(link);
    }

    function poll() {
      fetch(statusUrl, { credentials: "same-origin" })
        .then(function (response) {
          if (!response.ok) {
            throw new Error("status_unavailable");
          }
          return response.json();
        })
        .then(function (data) {
          if (data.status === "completed") {
            statusMessage.textContent = "Approved. Redirecting…";
            globalThis.location.href = dashboardUrl;
            return;
          }
          if (data.status === "expired" || data.status === "failed") {
            statusMessage.textContent = "This top-up request is no longer active.";
            showRestartLink();
            return;
          }
          globalThis.setTimeout(poll, 2000);
        })
        .catch(function () {
          globalThis.setTimeout(poll, 2000);
        });
    }

    globalThis.setTimeout(poll, 2000);
  });
})();
