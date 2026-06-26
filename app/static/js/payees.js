(function () {
  function formatRemaining(ms) {
    if (ms <= 0) return null;
    var totalSecs = Math.ceil(ms / 1000);
    var days = Math.floor(totalSecs / 86400);
    var remainder = totalSecs % 86400;
    var hours = Math.floor(remainder / 3600);
    remainder = remainder % 3600;
    var mins = Math.floor(remainder / 60);
    var secs = remainder % 60;
    if (days > 0) return days + 'd ' + hours + 'h';
    if (hours > 0) return hours + 'h ' + mins + 'm';
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
        badge.textContent = 'Available in ' + label;
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
