(function () {
  const meta = document.querySelector('meta[name="session-timeout"]');
  if (!meta) return;

  let timeoutSeconds = Number.parseInt(meta.getAttribute('content'), 10);
  if (!timeoutSeconds || timeoutSeconds <= 0) return;

  const warningSeconds = 60;
  let timeoutMs = timeoutSeconds * 1000;
  let warningMs = Math.max(0, (timeoutSeconds - warningSeconds) * 1000);

  let expireTimer = null;
  let warningTimer = null;
  let countdownInterval = null;
  let lastResetTime = Date.now();

  const overlayEl = document.getElementById('session-timeout-overlay');
  const countdownEl = document.getElementById('session-timeout-countdown');
  const continueBtn = document.getElementById('session-continue-btn');
  const timerEl = document.getElementById('session-timer');
  const timerValueEl = document.getElementById('session-timer-value');
  const csrfMeta = document.querySelector('meta[name="csrf-token"]');

  function formatTime(ms) {
    const totalSeconds = Math.max(0, Math.ceil(ms / 1000));
    const m = Math.floor(totalSeconds / 60);
    const s = totalSeconds % 60;
    return m + ':' + (s < 10 ? '0' + s : s);
  }

  function updateTimerDisplay() {
    const remaining = timeoutMs - (Date.now() - lastResetTime);
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
    if (overlayEl?.open) overlayEl.close();
    clearInterval(countdownInterval);
    countdownInterval = null;
  }

  function showOverlay() {
    if (!overlayEl) return;
    let remaining = warningSeconds;
    if (countdownEl) countdownEl.textContent = remaining;
    if (!overlayEl.open) overlayEl.showModal();
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
    globalThis.location.href = '/login?session_expired=1';
  }

  function resetTimers() {
    clearTimeout(expireTimer);
    clearTimeout(warningTimer);
    hideOverlay();
    lastResetTime = Date.now();
    updateTimerDisplay();
    if (warningMs > 0) {
      warningTimer = setTimeout(showOverlay, warningMs);
    }
    expireTimer = setTimeout(expire, timeoutMs);
  }

  if (continueBtn) {
    continueBtn.addEventListener('click', function () {
      const headers = {
        'Accept': 'application/json'
      };
      if (csrfMeta?.getAttribute('content')) {
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
          timeoutSeconds = Number.parseInt(payload.timeout_seconds, 10);
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

  setInterval(updateTimerDisplay, 1000);
  resetTimers();
})();
