// Keep admin-issued reset credentials compatible with existing login callers.
export function requestNewPassword({ error = '', document: doc = globalThis.document } = {}) {
  if (!doc?.body) return Promise.reject(new Error('Password reset requires a browser or Auth.configure({ requestNewPassword })'));
  return new Promise((resolve, reject) => {
    const previous = doc.activeElement;
    const dialog = doc.createElement('dialog'); dialog.setAttribute('aria-label', 'Set a new password');
    const form = doc.createElement('form');
    const heading = doc.createElement('h2'); heading.textContent = 'Set a new password';
    const hint = doc.createElement('p'); hint.textContent = 'Your recovery credential allows only a password reset. Set your password to finish signing in.';
    const input = doc.createElement('input'); input.type = 'password'; input.autocomplete = 'new-password'; input.required = true; input.minLength = 8;
    const confirm = doc.createElement('input'); confirm.type = 'password'; confirm.autocomplete = 'new-password'; confirm.required = true;
    const label = doc.createElement('label'); label.textContent = 'New password'; label.append(input);
    const confirmation = doc.createElement('label'); confirmation.textContent = 'Confirm password'; confirmation.append(confirm);
    label.style.display = confirmation.style.display = 'block';
    const message = doc.createElement('p'); message.setAttribute('role', 'alert'); message.textContent = error;
    const submit = doc.createElement('button'); submit.type = 'submit'; submit.textContent = 'Set password and sign in';
    const cancel = doc.createElement('button'); cancel.type = 'button'; cancel.textContent = 'Cancel';
    form.append(heading, hint, label, confirmation, message, submit, cancel); dialog.append(form); doc.body.append(dialog);
    let done = false;
    const finish = value => {
      if (done) return; done = true;
      input.value = confirm.value = ''; dialog.remove(); previous?.focus?.(); resolve(value);
    };
    form.addEventListener('submit', event => {
      event.preventDefault();
      if (input.value !== confirm.value) { message.textContent = 'Passwords must match.'; confirm.focus(); return; }
      const length = new TextEncoder().encode(input.value).length;
      if (length < 8 || length > 4096) { message.textContent = 'Use a password of 8–4096 UTF-8 bytes.'; return; }
      finish(input.value);
    });
    cancel.addEventListener('click', () => finish(null));
    dialog.addEventListener('cancel', event => { event.preventDefault(); finish(null); });
    if (typeof dialog.showModal !== 'function') { dialog.remove(); reject(new Error('Password dialog unavailable; configure requestNewPassword')); return; }
    dialog.showModal(); input.focus();
  });
}
