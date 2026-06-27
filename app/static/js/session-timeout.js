(function () {
  var meta = document.querySelector('meta[name="session-timeout"]');
  if (!meta) return;

  var timeoutSeconds = parseInt(meta.getAttribute('content'), 10);
  if (!timeoutSeconds || timeoutSeconds <= 0) return;

  var warningSeconds = 60;
  var timeoutMs = timeoutSeconds * 1000;
  var warningMs = Math.max(0, (timeoutSeconds - warningSeconds) * 1000);

  var expireTimer = null;
  var warningTimer = null;
  var countdownInterval = null;
  var displayInterval = null;
  var lastResetTime = Date.now();

  var overlayEl = document.getElementById('session-timeout-overlay');
  var countdownEl = document.getElementById('session-timeout-countdown');
  var continueBtn = document.getElementById('session-continue-btn');
  var timerEl = document.getElementById('session-timer');
  var timerValueEl = document.getElementById('session-timer-value');
  var csrfMeta = document.querySelector('meta[name="csrf-token"]');

  function formatTime(ms) {
    var totalSeconds = Math.max(0, Math.ceil(ms / 1000));
    var m = Math.floor(totalSeconds / 60);
    var s = totalSeconds % 60;
    return m + ':' + (s < 10 ? '0' + s : s);
  }

  function updateTimerDisplay() {
    var remaining = timeoutMs - (Date.now() - lastResetTime);
    if (timerValueEl) timerValueEl.textContent = formatTime(remaining);
    if (timerEl) {
      if (remaining <= warningMs) {
        timerEl.classList.add('is-warning');
      } else {
        timerEl.classList.remove('is-warning');
      }
    }
  }

  function hideOverlay() {
    if (overlayEl) overlayEl.hidden = true;
    clearInterval(countdownInterval);
    countdownInterval = null;
  }

  function showOverlay() {
    if (!overlayEl) return;
    var remaining = warningSeconds;
    if (countdownEl) countdownEl.textContent = remaining;
    overlayEl.hidden = false;
    clearInterval(countdownInterval);
    countdownInterval = setInterval(function () {
      remaining -= 1;
      if (countdownEl) countdownEl.textContent = remaining;
      if (remaining <= 0) {
        clearInterval(countdownInterval);
        countdownInterval = null;
      }
    }, 1000);
  }

  function expire() {
    window.location.href = '/login?session_expired=1';
  }

  function resetTimers() {
    clearTimeout(expireTimer);
    clearTimeout(warningTimer);
    hideOverlay();
    lastResetTime = Date.now();
    updateTimerDisplay();
    warningTimer = setTimeout(showOverlay, warningMs);
    expireTimer = setTimeout(expire, timeoutMs);
  }

  if (continueBtn) {
    continueBtn.addEventListener('click', function () {
      var headers = {
        'Accept': 'application/json'
      };
      if (csrfMeta && csrfMeta.getAttribute('content')) {
        headers['X-CSRFToken'] = csrfMeta.getAttribute('content');
      }
      continueBtn.disabled = true;
      fetch('/auth/session/extend', {
        method: 'POST',
        credentials: 'same-origin',
        headers: headers
      }).then(function (response) {
        if (!response.ok) {
          throw new Error('session extension failed');
        }
        return response.json().catch(function () { return {}; });
      }).then(function (payload) {
        if (payload.timeout_seconds && payload.timeout_seconds > 0) {
          timeoutSeconds = parseInt(payload.timeout_seconds, 10);
          timeoutMs = timeoutSeconds * 1000;
          warningMs = Math.max(0, (timeoutSeconds - warningSeconds) * 1000);
        }
        resetTimers();
      }).catch(function () {
        expire();
      }).finally(function () {
        continueBtn.disabled = false;
      });
    });
  }

  displayInterval = setInterval(updateTimerDisplay, 1000);
  resetTimers();
})();
