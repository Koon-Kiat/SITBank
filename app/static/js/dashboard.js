(function () {
  function makeToggle(btnId, maskedId, fullId, iconId, labelShow, labelHide) {
    var btn    = document.getElementById(btnId);
    var masked = document.getElementById(maskedId);
    var full   = document.getElementById(fullId);
    var icon   = document.getElementById(iconId);
    if (!btn || !masked || !full || !icon) return;
    btn.addEventListener('click', function () {
      var revealing = full.hidden;
      masked.hidden = revealing;
      full.hidden   = !revealing;
      icon.setAttribute('href', revealing ? '#icon-eye' : '#icon-eye-off');
      btn.setAttribute('aria-label', revealing ? labelHide : labelShow);
      btn.setAttribute('aria-pressed', String(revealing));
    });
  }

  makeToggle('bal-eye-btn',  'card-balance-masked', 'card-balance-full', 'bal-eye-icon',  'Show balance',        'Hide balance');
  makeToggle('acct-eye-btn', 'card-acct-masked',   'card-acct-full',   'acct-eye-icon', 'Show account number', 'Hide account number');
}());
