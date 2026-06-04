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
  });
})();
