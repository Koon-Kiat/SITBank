(function () {
  var meta = document.querySelector('meta[name="session-timeout"]');
  if (!meta) return;

  var timeoutSeconds = parseInt(meta.getAttribute('content'), 10);
  if (!timeoutSeconds || timeoutSeconds <= 0) return;

  var warningSeconds = 60;
  var timeoutMs = timeoutSeconds * 1000;
  var warningMs = (timeoutSeconds - warningSeconds) * 1000;
  var keepaliveThrottleMs = 30000;

  var expireTimer = null;
  var warningTimer = null;
  var countdownInterval = null;
  var displayInterval = null;
  var lastResetTime = Date.now();
  var lastKeepalive = 0;

  var overlayEl = document.getElementById('session-timeout-overlay');
  var countdownEl = document.getElementById('session-timeout-countdown');
  var continueBtn = document.getElementById('session-continue-btn');
  var timerEl = document.getElementById('session-timer');
  var timerValueEl = document.getElementById('session-timer-value');

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
    if (overlayEl) overlayEl.style.display = 'none';
    clearInterval(countdownInterval);
    countdownInterval = null;
  }

  function showOverlay() {
    if (!overlayEl) return;
    var remaining = warningSeconds;
    if (countdownEl) countdownEl.textContent = remaining;
    overlayEl.style.display = 'flex';
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

  function sendKeepalive() {
    var now = Date.now();
    if (now - lastKeepalive < keepaliveThrottleMs) return;
    lastKeepalive = now;
    fetch('/auth/csrf-token', { credentials: 'same-origin' }).catch(function () {});
  }

  function onActivity() {
    if (overlayEl && overlayEl.style.display === 'flex') return;
    sendKeepalive();
    resetTimers();
  }

  if (continueBtn) {
    continueBtn.addEventListener('click', function () {
      lastKeepalive = 0;
      sendKeepalive();
      resetTimers();
    });
  }

  ['mousemove', 'keydown', 'click', 'scroll', 'touchstart'].forEach(function (type) {
    document.addEventListener(type, onActivity, { passive: true });
  });

  displayInterval = setInterval(updateTimerDisplay, 1000);
  resetTimers();
})();
