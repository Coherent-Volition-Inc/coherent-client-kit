// Default MFA prompt belongs to CVKit, so existing login callers need no changes.
export function requestMfaCode({ error = '', document: doc = globalThis.document } = {}) {
  if (!doc?.body) return Promise.reject(new Error('MFA requires a browser or Auth.configure({ requestMfaCode })'));
  return new Promise((resolve, reject) => {
    const previous = doc.activeElement;
    const dialog = doc.createElement('dialog');
    dialog.setAttribute('aria-label', 'Two-factor authentication');
    const form = doc.createElement('form');
    const heading = doc.createElement('h2'); heading.textContent = 'Two-factor authentication';
    const label = doc.createElement('label'); label.textContent = 'Enter the six-digit code from your authenticator';
    const input = doc.createElement('input'); input.type = 'text'; input.inputMode = 'numeric'; input.autocomplete = 'one-time-code'; input.pattern = '[0-9]{6}'; input.maxLength = 6; input.required = true;
    label.append(input);
    const message = doc.createElement('p'); message.setAttribute('role', 'alert'); message.textContent = error;
    const submit = doc.createElement('button'); submit.type = 'submit'; submit.textContent = 'Verify';
    const cancel = doc.createElement('button'); cancel.type = 'button'; cancel.textContent = 'Cancel';
    form.append(heading, label, message, submit, cancel); dialog.append(form); doc.body.append(dialog);
    let done = false;
    const finish = (code) => {
      if (done) return; done = true;
      dialog.remove(); previous?.focus?.();
      if (code) resolve(code);
      else { const err = new Error('Two-factor authentication cancelled'); err.code = 'MFA_CANCELLED'; reject(err); }
    };
    form.addEventListener('submit', event => { event.preventDefault(); if (/^[0-9]{6}$/.test(input.value)) finish(input.value); });
    cancel.addEventListener('click', () => finish(null));
    dialog.addEventListener('cancel', event => { event.preventDefault(); finish(null); });
    if (typeof dialog.showModal !== 'function') { dialog.remove(); reject(new Error('MFA dialog unavailable; configure requestMfaCode')); return; }
    dialog.showModal(); input.focus();
  });
}
