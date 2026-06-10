(function () {
  "use strict";

  var storageKey = "sitbank-theme";
  var root = document.documentElement;

  function preferredTheme() {
    var stored = window.localStorage.getItem(storageKey);
    if (stored === "dark" || stored === "light") {
      return stored;
    }
    if (window.matchMedia && window.matchMedia("(prefers-color-scheme: dark)").matches) {
      return "dark";
    }
    return "light";
  }

  function applyTheme(theme) {
    root.setAttribute("data-theme", theme);
    var toggle = document.querySelector("[data-theme-toggle]");
    var label = document.querySelector("[data-theme-toggle-label]");
    var icon = document.querySelector("[data-theme-toggle-icon]");
    var isDark = theme === "dark";
    var actionLabel = isDark ? "Switch to light mode" : "Switch to dark mode";
    if (toggle) {
      toggle.setAttribute("aria-pressed", isDark ? "true" : "false");
      toggle.setAttribute("aria-label", actionLabel);
      toggle.setAttribute("title", actionLabel);
    }
    if (label) {
      label.textContent = actionLabel;
    }
    if (icon) {
      icon.setAttribute("data-icon", isDark ? "sun" : "moon");
      var iconUse = icon.querySelector("use");
      if (iconUse) {
        iconUse.setAttribute("href", isDark ? "#icon-theme-sun" : "#icon-theme-moon");
      }
    }
  }

  function closestElement(target, selector) {
    if (!target || !target.closest) {
      return null;
    }
    return target.closest(selector);
  }

  applyTheme(preferredTheme());

  window.addEventListener("DOMContentLoaded", function () {
    var toggle = document.querySelector("[data-theme-toggle]");
    var navToggle = document.querySelector("[data-nav-toggle]");
    var navMenu = document.querySelector("[data-nav-menu]");
    var accountMenu = document.querySelector("[data-account-menu]");
    var accountTrigger = document.querySelector("[data-account-trigger]");
    var accountPanel = document.querySelector("[data-account-panel]");

    function accountItems() {
      if (!accountPanel) {
        return [];
      }
      return Array.prototype.slice.call(accountPanel.querySelectorAll("a, button"));
    }

    function setAccountOpen(isOpen) {
      if (!accountMenu || !accountTrigger || !accountPanel) {
        return;
      }
      accountMenu.classList.toggle("is-open", isOpen);
      accountTrigger.setAttribute("aria-expanded", isOpen ? "true" : "false");
      accountPanel.hidden = !isOpen;
    }

    function focusAccountItem(index) {
      var items = accountItems();
      if (!items.length) {
        return;
      }
      items[(index + items.length) % items.length].focus();
    }

    if (!toggle) {
      return;
    }
    toggle.addEventListener("click", function () {
      var nextTheme = root.getAttribute("data-theme") === "dark" ? "light" : "dark";
      window.localStorage.setItem(storageKey, nextTheme);
      applyTheme(nextTheme);
    });

    if (navToggle && navMenu) {
      navToggle.addEventListener("click", function () {
        var isOpen = navMenu.classList.toggle("is-open");
        navToggle.setAttribute("aria-expanded", isOpen ? "true" : "false");
      });

      navMenu.addEventListener("click", function (event) {
        if (event.target.tagName === "A") {
          navMenu.classList.remove("is-open");
          navToggle.setAttribute("aria-expanded", "false");
        }
      });
    }

    if (accountTrigger && accountPanel) {
      accountTrigger.addEventListener("click", function () {
        setAccountOpen(!accountMenu.classList.contains("is-open"));
      });

      accountTrigger.addEventListener("keydown", function (event) {
        if (event.key === "Enter" || event.key === " " || event.key === "ArrowDown") {
          event.preventDefault();
          setAccountOpen(true);
          focusAccountItem(0);
        }
      });

      accountPanel.addEventListener("keydown", function (event) {
        var items = accountItems();
        var currentIndex = items.indexOf(document.activeElement);
        if (event.key === "Escape") {
          event.preventDefault();
          setAccountOpen(false);
          accountTrigger.focus();
        } else if (event.key === "ArrowDown") {
          event.preventDefault();
          focusAccountItem(currentIndex + 1);
        } else if (event.key === "ArrowUp") {
          event.preventDefault();
          focusAccountItem(currentIndex - 1);
        } else if (event.key === "Home") {
          event.preventDefault();
          focusAccountItem(0);
        } else if (event.key === "End") {
          event.preventDefault();
          focusAccountItem(items.length - 1);
        }
      });

      accountPanel.addEventListener("click", function (event) {
        if (closestElement(event.target, "a")) {
          setAccountOpen(false);
        }
      });

      document.addEventListener("click", function (event) {
        if (!closestElement(event.target, "[data-account-menu]")) {
          setAccountOpen(false);
        }
      });

      document.addEventListener("keydown", function (event) {
        if (event.key === "Escape") {
          setAccountOpen(false);
        }
      });
    }
  });
})();
