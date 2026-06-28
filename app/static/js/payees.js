(function () {
  function formatRemaining(ms) {
    if (ms <= 0) return null;
    const totalSecs = Math.ceil(ms / 1000);
    const days = Math.floor(totalSecs / 86400);
    let remainder = totalSecs % 86400;
    const hours = Math.floor(remainder / 3600);
    remainder = remainder % 3600;
    const mins = Math.floor(remainder / 60);
    const secs = remainder % 60;
    if (days > 0) return days + 'd ' + hours + 'h';
    if (hours > 0) return hours + 'h ' + mins + 'm';
    return mins > 0 ? mins + 'm ' + secs + 's' : secs + 's';
  }

  function tick() {
    const badges = document.querySelectorAll('[data-cooldown-expires]');
    if (!badges.length) {
      clearInterval(timer);
      return;
    }
    let allDone = true;
    badges.forEach(function (badge) {
      const remaining = new Date(badge.dataset.cooldownExpires) - Date.now();
      const label = formatRemaining(remaining);
      if (label) {
        badge.textContent = 'Available in ' + label;
        allDone = false;
      } else {
        // Cooldown just expired — reload so server re-renders "Ready" status
        globalThis.location.reload();
      }
    });
    if (allDone) clearInterval(timer);
  }

  const timer = setInterval(tick, 1000);
  tick();
}());
