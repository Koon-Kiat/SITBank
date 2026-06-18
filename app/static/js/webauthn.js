/*
(function () {
  "use strict";

  var SECURITY_KEY_INCOMPLETE_MESSAGE = "Security key verification was not completed. Try again.";
  var WEBAUTHN_BROWSER_ERROR_NAMES = [
    "AbortError",
    "ConstraintError",
    "InvalidStateError",
    "NotAllowedError",
    "NotSupportedError",
    "SecurityError",
    "UnknownError"
  ];

  function webAuthnErrorMessage(error) {
    var name = error && error.name ? String(error.name) : "";
    var message = error && error.message ? String(error.message) : "";
    var normalized = message.toLowerCase();
    if (
      WEBAUTHN_BROWSER_ERROR_NAMES.indexOf(name) !== -1 ||
      normalized.indexOf("operation either timed out") !== -1 ||
      normalized.indexOf("not allowed") !== -1
    ) {
      return SECURITY_KEY_INCOMPLETE_MESSAGE;
    }
    return message || "Security key request failed. Please try again.";
  }

  function base64urlToBuffer(value) {
    var base64 = value.replace(/-/g, "+").replace(/_/g, "/");
    while (base64.length % 4) {
      base64 += "=";
    }
    var binary = window.atob(base64);
    var bytes = new Uint8Array(binary.length);
    for (var index = 0; index < binary.length; index += 1) {
      bytes[index] = binary.charCodeAt(index);
    }
    return bytes.buffer;
  }

  function bufferToBase64url(buffer) {
    var bytes = new Uint8Array(buffer || new ArrayBuffer(0));
    var binary = "";
    for (var index = 0; index < bytes.byteLength; index += 1) {
      binary += String.fromCharCode(bytes[index]);
    }
    return window.btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
  }

  function csrfToken(form) {
    var input = form.querySelector('input[name="csrf_token"]');
    return input ? input.value : "";
  }

  function showError(node, message) {
    if (!node) {
      return;
    }
    node.textContent = message;
    node.hidden = false;
  }

  function clearError(node) {
    if (!node) {
      return;
    }
    node.textContent = "";
    node.hidden = true;
  }

  function postJson(url, payload, csrf) {
    return window.fetch(url, {
      method: "POST",
      credentials: "same-origin",
      headers: {
        "Accept": "application/json",
        "Content-Type": "application/json",
        "X-CSRFToken": csrf
      },
      body: JSON.stringify(payload)
    }).then(function (response) {
      var contentType = response.headers.get("Content-Type") || "";
      if (contentType.indexOf("application/json") === -1) {
        return response.text().then(function () {
          if (response.status === 401) {
            throw new Error("Your session expired. Please sign in again.");
          }
          if (response.status === 413) {
            throw new Error("Security key response was too large for the server.");
          }
          throw new Error("Security key request failed with HTTP " + response.status + ".");
        });
      }
      return response.json().then(function (body) {
        if (!response.ok) {
          throw new Error(body.error || "Security key request failed");
        }
        return body;
      });
    });
  }

  function prepareRegistrationOptions(options) {
    options.challenge = base64urlToBuffer(options.challenge);
    options.user.id = base64urlToBuffer(options.user.id);
    options.excludeCredentials = (options.excludeCredentials || []).map(function (credential) {
      credential.id = base64urlToBuffer(credential.id);
      return credential;
    });
    return options;
  }

  function prepareAuthenticationOptions(options) {
    options.challenge = base64urlToBuffer(options.challenge);
    options.allowCredentials = (options.allowCredentials || []).map(function (credential) {
      credential.id = base64urlToBuffer(credential.id);
      return credential;
    });
    return options;
  }

  function registrationResponse(credential) {
    var response = credential.response;
    var transports = [];
    if (response.getTransports) {
      transports = response.getTransports();
    }
    return {
      id: credential.id,
      rawId: bufferToBase64url(credential.rawId),
      type: credential.type,
      authenticatorAttachment: credential.authenticatorAttachment,
      clientExtensionResults: credential.getClientExtensionResults(),
      response: {
        attestationObject: bufferToBase64url(response.attestationObject),
        clientDataJSON: bufferToBase64url(response.clientDataJSON),
        transports: transports
      }
    };
  }

  function authenticationResponse(credential) {
    var response = credential.response;
    return {
      id: credential.id,
      rawId: bufferToBase64url(credential.rawId),
      type: credential.type,
      authenticatorAttachment: credential.authenticatorAttachment,
      clientExtensionResults: credential.getClientExtensionResults(),
      response: {
        authenticatorData: bufferToBase64url(response.authenticatorData),
        clientDataJSON: bufferToBase64url(response.clientDataJSON),
        signature: bufferToBase64url(response.signature),
        userHandle: response.userHandle ? bufferToBase64url(response.userHandle) : null
      }
    };
  }

  window.addEventListener("DOMContentLoaded", function () {
    var registerForm = document.querySelector("[data-webauthn-register-form]");
    var loginForm = document.querySelector("[data-webauthn-login-form]");
    var stepUpForms = document.querySelectorAll("[data-webauthn-step-up-form]");

    if (registerForm) {
      registerForm.addEventListener("submit", function (event) {
        event.preventDefault();
        var errorNode = document.querySelector("[data-webauthn-register-error]");
        var label = registerForm.querySelector('input[name="label"]').value;
        clearError(errorNode);
        postJson("/auth/webauthn/register/options", { label: label }, csrfToken(registerForm))
          .then(function (options) {
            return navigator.credentials.create({ publicKey: prepareRegistrationOptions(options) });
          })
          .then(function (credential) {
            return postJson(
              "/auth/webauthn/register/verify",
              { credential: registrationResponse(credential) },
              csrfToken(registerForm)
            );
          })
          .then(function () {
            window.location.assign("/security-keys");
          })
          .catch(function (error) {
            showError(errorNode, webAuthnErrorMessage(error));
          });
      });
    }

    if (loginForm) {
      loginForm.addEventListener("submit", function (event) {
        event.preventDefault();
        var errorNode = document.querySelector("[data-webauthn-login-error]");
        var identifier = loginForm.querySelector('input[name="identifier"]').value;
        clearError(errorNode);
        postJson("/auth/webauthn/authenticate/options", { identifier: identifier }, csrfToken(loginForm))
          .then(function (options) {
            return navigator.credentials.get({ publicKey: prepareAuthenticationOptions(options) });
          })
          .then(function (credential) {
            return postJson(
              "/auth/webauthn/authenticate/verify",
              { credential: authenticationResponse(credential) },
              csrfToken(loginForm)
            );
          })
          .then(function () {
            window.location.assign("/dashboard");
          })
          .catch(function (error) {
            showError(errorNode, webAuthnErrorMessage(error));
          });
      });
    }

    stepUpForms.forEach(function (form) {
      form.addEventListener("submit", function (event) {
        if (form.getAttribute("data-webauthn-step-up-complete") === "true") {
          return;
        }
        event.preventDefault();
        var errorNode = form.querySelector("[data-webauthn-step-up-error]");
        var action = form.getAttribute("data-step-up-action");
        var tokenInput = form.querySelector('input[name="stepup_token"]');
        clearError(errorNode);
        if (!window.PublicKeyCredential || !navigator.credentials) {
          showError(errorNode, "Security key verification is not available in this browser.");
          return;
        }
        postJson("/auth/webauthn/step-up/options", { action: action }, csrfToken(form))
          .then(function (options) {
            return navigator.credentials.get({ publicKey: prepareAuthenticationOptions(options) });
          })
          .then(function (credential) {
            return postJson(
              "/auth/webauthn/step-up/verify",
              { action: action, credential: authenticationResponse(credential) },
              csrfToken(form)
            );
          })
          .then(function (result) {
            if (!tokenInput) {
              tokenInput = document.createElement("input");
              tokenInput.type = "hidden";
              tokenInput.name = "stepup_token";
              form.appendChild(tokenInput);
            }
            tokenInput.value = result.stepup_token;
            form.setAttribute("data-webauthn-step-up-complete", "true");
            form.submit();
          })
          .catch(function (error) {
            showError(errorNode, webAuthnErrorMessage(error));
          });
      });
    });
  });
})();
*/
