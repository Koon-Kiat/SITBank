(function () {
  "use strict";

  function strengthLabel(value) {
    let score = 0;
    if (value.length >= 15) {
      score += 1;
    }
    if (value.length >= 20) {
      score += 1;
    }
    if (/[a-z]/.test(value) && /[A-Z]/.test(value)) {
      score += 1;
    }
    if (/\d/.test(value)) {
      score += 1;
    }
    if (/[^A-Za-z0-9]/.test(value)) {
      score += 1;
    }
    if (!value) {
      return "Password strength: not entered";
    }
    if (score <= 2) {
      return "Password strength: weak";
    }
    if (score <= 4) {
      return "Password strength: fair";
    }
    return "Password strength: strong";
  }

  function recoveryCodesText(list) {
    return Array.prototype.slice.call(list.querySelectorAll("[data-recovery-code]"))
      .map(function (item) {
        return item.textContent.trim();
      })
      .filter(Boolean)
      .join("\n");
  }

  function setRecoveryStatus(status, message) {
    if (status) {
      status.textContent = message;
    }
  }

  function copyRecoveryCodes(list, status) {
    const text = recoveryCodesText(list);
    if (!text) {
      return;
    }
    if (navigator.clipboard?.writeText) {
      navigator.clipboard.writeText(text).then(function () {
        setRecoveryStatus(status, "Recovery codes copied.");
      }).catch(function () {
        setRecoveryStatus(status, "Copy was not available. Download the codes instead.");
      });
      return;
    }
    setRecoveryStatus(status, "Copy was not available. Download the codes instead.");
  }

  function downloadRecoveryCodes(list, status) {
    const text = recoveryCodesText(list);
    if (!text) {
      return;
    }
    const blob = new Blob([
      "SITBank recovery codes\n",
      "Store these codes somewhere private. Each code can be used once.\n\n",
      text,
      "\n"
    ], { type: "text/plain" });
    const url = URL.createObjectURL(blob);
    const link = document.createElement("a");
    link.href = url;
    link.download = "sitbank-recovery-codes.txt";
    document.body.appendChild(link);
    link.click();
    link.remove();
    URL.revokeObjectURL(url);
    setRecoveryStatus(status, "Recovery codes download started.");
  }

  function setupRecoveryCodeList(list) {
    const status = document.querySelector("[data-recovery-code-status]");
    const copyButton = document.querySelector("[data-copy-recovery-codes]");
    const downloadButton = document.querySelector("[data-download-recovery-codes]");

    copyButton?.addEventListener("click", function () {
      copyRecoveryCodes(list, status);
    });
    downloadButton?.addEventListener("click", function () {
      downloadRecoveryCodes(list, status);
    });
  }

  globalThis.addEventListener("DOMContentLoaded", function () {
    document.querySelectorAll("[data-alert-dismiss]").forEach(function (button) {
      button.addEventListener("click", function () {
        const alert = button.closest(".alert");
        if (alert) {
          alert.remove();
        }
      });
      const alert = button.closest(".alert");
      if (alert) {
        if (alert.classList.contains("alert-success") || alert.classList.contains("alert-info")) {
          setTimeout(function () { alert.remove(); }, 3000);
        }
      }
    });

    document.querySelectorAll("[data-password-toggle]").forEach(function (button) {
      button.addEventListener("click", function () {
        const input = document.getElementById(button.dataset.passwordToggle);
        if (!input) {
          return;
        }
        const isHidden = input.type === "password";
        input.type = isHidden ? "text" : "password";
        button.textContent = isHidden ? "Hide" : "Show";
        button.setAttribute("aria-label", isHidden ? "Hide password" : "Show password");
      });
    });

    document.querySelectorAll("[data-password-strength-input]").forEach(function (input) {
      const key = input.dataset.passwordStrengthInput;
      const meter = document.querySelector('[data-password-strength="' + key + '"]');
      if (!meter) {
        return;
      }
      input.addEventListener("input", function () {
        meter.textContent = strengthLabel(input.value || "");
      });
    });

    document.querySelectorAll("[data-recovery-code-list]").forEach(setupRecoveryCodeList);
  });
})();
