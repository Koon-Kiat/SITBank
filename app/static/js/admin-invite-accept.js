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

  function updateForm(form, state, token, options) {
    const required = form.dataset.turnstileRequired === "true";
    const responseInput = form.querySelector("[data-turnstile-response]");
    const submitButton = form.querySelector("[data-invite-start-submit]");
    const status = form.querySelector("[data-turnstile-status]");
    const shouldClearToken = Boolean(options && options.clearToken);
    const storedToken = responseInput ? responseInput.value : "";
    const keepValidResponse =
      state === "pending" &&
      !shouldClearToken &&
      form.dataset.turnstileState === "valid" &&
      Boolean(storedToken);
    const effectiveState = keepValidResponse ? "valid" : state;
    const effectiveToken =
      effectiveState === "valid" ? token || storedToken : "";
    const hasFreshToken = effectiveState === "valid" && Boolean(effectiveToken);

    form.dataset.turnstileState = effectiveState;
    if (responseInput) {
      responseInput.value = hasFreshToken ? effectiveToken : "";
    }
    if (status) {
      if (hasFreshToken) status.textContent = messages.ready;
      else if (effectiveState === "expired") status.textContent = messages.expired;
      else if (effectiveState === "failed") status.textContent = messages.failed;
      else if (effectiveState === "timeout") status.textContent = messages.timeout;
      else status.textContent = required ? messages.pending : "";
    }
    if (submitButton) {
      submitButton.disabled =
        form.dataset.submitting === "true" || (required && !hasFreshToken);
    }
  }

  function setTurnstileState(state, token, options) {
    for (const form of managedForms) {
      updateForm(form, state, token || "", options || {});
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
    if (token) {
      setTurnstileState("valid", token, { clearToken: false });
    } else {
      setTurnstileState("pending", "", { clearToken: true });
    }
  };
  window.sitbankInviteTurnstileExpired = function () {
    setTurnstileState("expired", "", { clearToken: true });
  };
  window.sitbankInviteTurnstileError = function () {
    setTurnstileState("failed", "", { clearToken: true });
    return true;
  };
  window.sitbankInviteTurnstileTimeout = function () {
    setTurnstileState("timeout", "", { clearToken: true });
  };
  window.sitbankInviteTurnstileInteractiveStart = function () {
    setTurnstileState("pending", "", { clearToken: true });
  };
  window.sitbankInviteTurnstileInteractiveEnd = function () {
    setTurnstileState("pending", "", { clearToken: false });
  };
  window.sitbankInviteTurnstilePending = function () {
    setTurnstileState("pending", "", { clearToken: false });
  };

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", init);
  } else {
    init();
  }
})();
