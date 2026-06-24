(function () {
  function formatRemaining(ms) {
    if (ms <= 0) return null;
    var totalSecs = Math.ceil(ms / 1000);
    var mins = Math.floor(totalSecs / 60);
    var secs = totalSecs % 60;
    return mins > 0 ? mins + 'm ' + secs + 's' : secs + 's';
  }

  function tick() {
    var badges = document.querySelectorAll('[data-cooldown-expires]');
    if (!badges.length) {
      clearInterval(timer);
      return;
    }
    var allDone = true;
    badges.forEach(function (badge) {
      var remaining = new Date(badge.dataset.cooldownExpires) - Date.now();
      var label = formatRemaining(remaining);
      if (label) {
        badge.textContent = 'Cooldown: ' + label;
        allDone = false;
      } else {
        // Cooldown just expired — reload so server re-renders "Ready" status
        window.location.reload();
      }
    });
    if (allDone) clearInterval(timer);
  }

  var timer = setInterval(tick, 1000);
  tick();
}());
