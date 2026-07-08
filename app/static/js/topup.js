(function () {
  "use strict";

  globalThis.addEventListener("DOMContentLoaded", function () {
    const presetGroup = document.querySelector("[data-topup-presets]");
    if (!presetGroup) {
      return;
    }

    const amountInput = document.getElementById("topup-amount-input");
    const customGroup = document.querySelector("[data-topup-custom-group]");
    const submitButton = document.querySelector("[data-topup-submit]");
    const form = presetGroup.closest("section")?.querySelector("form");

    function revealCustom() {
      if (customGroup) {
        customGroup.hidden = false;
      }
      if (submitButton) {
        submitButton.hidden = false;
      }
      amountInput?.focus();
    }

    presetGroup.addEventListener("click", function (event) {
      const presetButton = event.target.closest("[data-topup-preset]");
      if (presetButton && amountInput) {
        amountInput.value = presetButton.dataset.topupPreset;
        form?.requestSubmit();
        return;
      }

      if (event.target.closest("[data-topup-custom-toggle]")) {
        revealCustom();
      }
    });
  });
})();
