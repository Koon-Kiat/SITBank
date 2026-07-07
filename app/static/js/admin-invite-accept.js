(function () {
  const managedForms = [];
  const messages = {
    pending: "Security challenge is verifying. Submit will unlock when it completes.",
    ready: "Security challenge complete. You can start setup.",
    required: "Complete the security challenge to enable setup.",
    expired: "Security challenge expired. Complete it again before starting setup.",
    failed: "Security challenge could not be completed. Try again or refresh the page.",
    timeout: "Security challenge timed out. Complete it again before starting setup.",
    submitting: "Starting setup..."
  };

  function updateForm(form, state, token) {
    const required = form.dataset.turnstileRequired === "true";
    const responseInput = form.querySelector("[data-turnstile-response]");
    const submitButton = form.querySelector("[data-invite-start-submit]");
    const status = form.querySelector("[data-turnstile-status]");
    const hasFreshToken = state === "valid" && Boolean(token);

    form.dataset.turnstileState = state;
    if (responseInput) {
      responseInput.value = hasFreshToken ? token : "";
    }
    if (status) {
      if (hasFreshToken) status.textContent = messages.ready;
      else if (state === "expired") status.textContent = messages.expired;
      else if (state === "failed") status.textContent = messages.failed;
      else if (state === "timeout") status.textContent = messages.timeout;
      else status.textContent = required ? messages.pending : "";
    }
    if (submitButton) {
      submitButton.disabled = required && !hasFreshToken;
    }
  }

  function setTurnstileState(state, token) {
    for (const form of managedForms) {
      updateForm(form, state, token || "");
    }
  }

  function prepareSubmit(event, form) {
    const required = form.dataset.turnstileRequired === "true";
    const responseInput = form.querySelector("[data-turnstile-response]");
    const submitButton = form.querySelector("[data-invite-start-submit]");
    const status = form.querySelector("[data-turnstile-status]");
    const hasFreshToken = !required || Boolean(responseInput && responseInput.value);

    if (form.dataset.submitting === "true" || !hasFreshToken) {
      event.preventDefault();
      if (status && !hasFreshToken) status.textContent = messages.required;
      return;
    }

    form.dataset.submitting = "true";
    if (submitButton) {
      submitButton.disabled = true;
      submitButton.textContent = messages.submitting;
    }
  }

  function init() {
    const forms = document.querySelectorAll("[data-invite-accept-start]");
    for (const form of forms) {
      managedForms.push(form);
      form.addEventListener("submit", function (event) {
        prepareSubmit(event, form);
      });
      if (form.dataset.turnstileRequired === "true") {
        updateForm(form, "pending", "");
      }
    }
  }

  window.sitbankInviteTurnstileSuccess = function (token) {
    setTurnstileState("valid", token);
  };
  window.sitbankInviteTurnstileExpired = function () {
    setTurnstileState("expired", "");
  };
  window.sitbankInviteTurnstileError = function () {
    setTurnstileState("failed", "");
    return true;
  };
  window.sitbankInviteTurnstileTimeout = function () {
    setTurnstileState("timeout", "");
  };
  window.sitbankInviteTurnstilePending = function () {
    setTurnstileState("pending", "");
  };

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", init);
  } else {
    init();
  }
})();
