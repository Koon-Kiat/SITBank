(function () {
  "use strict";

  const storageKey = "sitbank-theme";
  const root = document.documentElement;

  function preferredTheme() {
    const stored = globalThis.localStorage.getItem(storageKey);
    if (stored === "dark" || stored === "light") {
      return stored;
    }
    if (globalThis.matchMedia?.("(prefers-color-scheme: dark)")?.matches) {
      return "dark";
    }
    return "light";
  }

  function applyTheme(theme) {
    root.dataset.theme = theme;
    const toggle = document.querySelector("[data-theme-toggle]");
    const label = document.querySelector("[data-theme-toggle-label]");
    const icon = document.querySelector("[data-theme-toggle-icon]");
    const isDark = theme === "dark";
    const actionLabel = isDark ? "Switch to light mode" : "Switch to dark mode";
    if (toggle) {
      toggle.setAttribute("aria-pressed", isDark ? "true" : "false");
      toggle.setAttribute("aria-label", actionLabel);
      toggle.setAttribute("title", actionLabel);
    }
    if (label) {
      label.textContent = actionLabel;
    }
    if (icon) {
      icon.dataset.icon = isDark ? "sun" : "moon";
      const iconUse = icon.querySelector("use");
      if (iconUse) {
        iconUse.setAttribute("href", isDark ? "#icon-theme-sun" : "#icon-theme-moon");
      }
    }
  }

  function closestElement(target, selector) {
    if (!target?.closest) {
      return null;
    }
    return target.closest(selector);
  }

  applyTheme(preferredTheme());

  globalThis.addEventListener("DOMContentLoaded", function () {
    const toggle = document.querySelector("[data-theme-toggle]");
    const navToggle = document.querySelector("[data-nav-toggle]");
    const navMenu = document.querySelector("[data-nav-menu]");
    const accountMenu = document.querySelector("[data-account-menu]");
    const accountTrigger = document.querySelector("[data-account-trigger]");
    const accountPanel = document.querySelector("[data-account-panel]");

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
      const items = accountItems();
      if (!items.length) {
        return;
      }
      items[(index + items.length) % items.length].focus();
    }

    if (!toggle) {
      return;
    }
    toggle.addEventListener("click", function () {
      const nextTheme = root.dataset.theme === "dark" ? "light" : "dark";
      globalThis.localStorage.setItem(storageKey, nextTheme);
      applyTheme(nextTheme);
    });

    if (navToggle && navMenu) {
      navToggle.addEventListener("click", function () {
        const isOpen = navMenu.classList.toggle("is-open");
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
        const items = accountItems();
        const currentIndex = items.indexOf(document.activeElement);
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
