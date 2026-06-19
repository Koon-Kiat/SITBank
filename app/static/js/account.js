(function () {
  "use strict";

  function getStrengthLevel(value) {
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
      return "none";
    }
    if (score <= 2) {
      return "weak";
    }
    if (score <= 4) {
      return "fair";
    }
    return "strong";
  }

  function strengthLabel(value) {
    var level = getStrengthLevel(value);
    if (level === "none") {
      return "Password strength: not entered";
    }
    return "Password strength: " + level;
  }

  window.addEventListener("DOMContentLoaded", function () {
    document.querySelectorAll("[data-alert-dismiss]").forEach(function (button) {
      button.addEventListener("click", function () {
        var alert = button.closest(".alert");
        if (alert) {
          alert.remove();
        }
      });
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
      var bar = meter ? meter.querySelector(".strength-bar-fill") : null;
      if (!meter) {
        return;
      }
      input.addEventListener("input", function () {
        var level = getStrengthLevel(input.value || "");
        meter.textContent = strengthLabel(input.value || "");
        meter.classList.remove("weak", "fair", "strong");
        if (bar) {
          bar.style.width = "0%";
          bar.classList.remove("weak", "fair", "strong");
        }
        if (level !== "none") {
          meter.classList.add(level);
          if (bar) {
            bar.classList.add(level);
            if (level === "weak") {
              bar.style.width = "33%";
            } else if (level === "fair") {
              bar.style.width = "66%";
            } else if (level === "strong") {
              bar.style.width = "100%";
            }
          }
        }
      });
    });
  });
})();
