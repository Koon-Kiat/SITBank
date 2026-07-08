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

  function turnstileMessage(required, hasFreshToken, state) {
    if (hasFreshToken) {
      return messages.ready;
    }
    const stateMessages = {
      expired: messages.expired,
      failed: messages.failed,
      timeout: messages.timeout
    };
    return stateMessages[state] || (required ? messages.pending : "");
  }

  function setText(element, value) {
    if (element) {
      element.textContent = value;
    }
  }

  function updateSubmitButton(button, form, required, hasFreshToken) {
    if (button) {
      button.disabled =
        form.dataset.submitting === "true" || (required && !hasFreshToken);
    }
  }

  function updateForm(form, state, token, options) {
    const required = form.dataset.turnstileRequired === "true";
    const responseInput = form.querySelector("[data-turnstile-response]");
    const submitButton = form.querySelector("[data-invite-start-submit]");
    const status = form.querySelector("[data-turnstile-status]");
    const shouldClearToken = Boolean(options?.clearToken);
    const storedToken = responseInput?.value || "";
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
    setText(status, turnstileMessage(required, hasFreshToken, effectiveState));
    updateSubmitButton(submitButton, form, required, hasFreshToken);
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
    const hasFreshToken = !required || Boolean(responseInput?.value);

    if (form.dataset.submitting === "true" || !hasFreshToken) {
      event.preventDefault();
      if (!hasFreshToken) {
        setText(status, messages.required);
      }
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
