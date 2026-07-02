(function () {
  function makeToggle(btnId, maskedId, fullId, iconId, labelShow, labelHide) {
    const btn = document.getElementById(btnId);
    const masked = document.getElementById(maskedId);
    const full = document.getElementById(fullId);
    const icon = document.getElementById(iconId);
    if (!btn || !masked || !full || !icon) return;
    btn.addEventListener('click', function () {
      const revealing = full.hidden;
      masked.hidden = revealing;
      full.hidden   = !revealing;
      icon.setAttribute('href', revealing ? '#icon-eye' : '#icon-eye-off');
      btn.setAttribute('aria-label', revealing ? labelHide : labelShow);
      btn.setAttribute('aria-pressed', String(revealing));
    });
  }

  makeToggle('payup-bal-eye-btn',  'payup-balance-masked', 'payup-balance-full', 'payup-bal-eye-icon',  'Show balance',        'Hide balance');
  makeToggle('payup-acct-eye-btn', 'payup-acct-masked',   'payup-acct-full',   'payup-acct-eye-icon', 'Show account number', 'Hide account number');
}());
