(function () {
  "use strict";

  function strengthLabel(value) {
    var score = 0;
    if (value.length >= 15) {
      score += 1;
    }
    if (value.length >= 20) {
      score += 1;
    }
    if (/[a-z]/.test(value) && /[A-Z]/.test(value)) {
      score += 1;
    }
    if (/[0-9]/.test(value)) {
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

  window.addEventListener("DOMContentLoaded", function () {
    document.querySelectorAll("[data-alert-dismiss]").forEach(function (button) {
      button.addEventListener("click", function () {
        var alert = button.closest(".alert");
        if (alert) {
          alert.remove();
        }
      });
      var alert = button.closest(".alert");
      if (alert) {
        setTimeout(function () { alert.remove(); }, 3000);
      }
    });

    document.querySelectorAll("[data-password-toggle]").forEach(function (button) {
      button.addEventListener("click", function () {
        var input = document.getElementById(button.getAttribute("data-password-toggle"));
        if (!input) {
          return;
        }
        var isHidden = input.type === "password";
        input.type = isHidden ? "text" : "password";
        button.textContent = isHidden ? "Hide" : "Show";
        button.setAttribute("aria-label", isHidden ? "Hide password" : "Show password");
      });
    });

    document.querySelectorAll("[data-password-strength-input]").forEach(function (input) {
      var key = input.getAttribute("data-password-strength-input");
      var meter = document.querySelector('[data-password-strength="' + key + '"]');
      if (!meter) {
        return;
      }
      input.addEventListener("input", function () {
        meter.textContent = strengthLabel(input.value || "");
      });
    });

    document.querySelectorAll("[data-recovery-code-list]").forEach(function (list) {
      var status = document.querySelector("[data-recovery-code-status]");
      var copyButton = document.querySelector("[data-copy-recovery-codes]");
      var downloadButton = document.querySelector("[data-download-recovery-codes]");

      function recoveryCodesText() {
        return Array.prototype.slice.call(list.querySelectorAll("[data-recovery-code]"))
          .map(function (item) {
            return item.textContent.trim();
          })
          .filter(Boolean)
          .join("\n");
      }

      function setStatus(message) {
        if (status) {
          status.textContent = message;
        }
      }

      function fallbackCopy(text) {
        var textarea = document.createElement("textarea");
        textarea.value = text;
        textarea.setAttribute("readonly", "readonly");
        textarea.style.position = "fixed";
        textarea.style.left = "-9999px";
        document.body.appendChild(textarea);
        textarea.select();
        try {
          if (document.execCommand("copy")) {
            setStatus("Recovery codes copied.");
          } else {
            setStatus("Copy was not available. Download the codes instead.");
          }
        } catch (error) {
          setStatus("Copy was not available. Download the codes instead.");
        } finally {
          document.body.removeChild(textarea);
        }
      }

      if (copyButton) {
        copyButton.addEventListener("click", function () {
          var text = recoveryCodesText();
          if (!text) {
            return;
          }
          if (navigator.clipboard && navigator.clipboard.writeText) {
            navigator.clipboard.writeText(text).then(function () {
              setStatus("Recovery codes copied.");
            }).catch(function () {
              fallbackCopy(text);
            });
            return;
          }
          fallbackCopy(text);
        });
      }

      if (downloadButton) {
        downloadButton.addEventListener("click", function () {
          var text = recoveryCodesText();
          var blob;
          var url;
          var link;
          if (!text) {
            return;
          }
          blob = new Blob([
            "SITBank recovery codes\n",
            "Store these codes somewhere private. Each code can be used once.\n\n",
            text,
            "\n"
          ], { type: "text/plain" });
          url = URL.createObjectURL(blob);
          link = document.createElement("a");
          link.href = url;
          link.download = "sitbank-recovery-codes.txt";
          document.body.appendChild(link);
          link.click();
          document.body.removeChild(link);
          URL.revokeObjectURL(url);
          setStatus("Recovery codes download started.");
        });
      }
    });
  });
})();
