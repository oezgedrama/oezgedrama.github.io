/* Unlocks password-protected content (see _plugins/site_lock.rb). Every lock (kanji, cv …) has its
   own password. Keys live only in this page's memory: a reload or another page asks again. Only a
   "this lock was opened" flag is kept for the browser session, to show the lock's nav item. */
(function () {
  var cfg = window.SITE_LOCK;
  var SEEN = 'site-lock-seen-';
  var root = document.documentElement;
  if (!cfg || !window.crypto || !crypto.subtle) return;
  var LOCKS = Object.keys(cfg.checks);

  function bytes(b64) {
    var s = atob(b64), out = new Uint8Array(s.length);
    for (var i = 0; i < s.length; i++) out[i] = s.charCodeAt(i);
    return out;
  }
  function decrypt(key, data) {
    return crypto.subtle.decrypt({ name: 'AES-GCM', iv: data.slice(0, 12) }, key, data.slice(12));
  }
  /* resolves to the key if it opens the lock's check blob, else rejects */
  function verify(lock, raw) {
    return crypto.subtle.importKey('raw', raw, 'AES-GCM', false, ['decrypt']).then(function (key) {
      return decrypt(key, bytes(cfg.checks[lock])).then(function () { return key; });
    });
  }
  function derive(lock, password) {
    var enc = new TextEncoder();
    return crypto.subtle.importKey('raw', enc.encode(password), 'PBKDF2', false, ['deriveBits']).then(function (base) {
      return crypto.subtle.deriveBits({ name: 'PBKDF2', salt: enc.encode(cfg.salt + ':' + lock), iterations: cfg.iterations,
        hash: 'SHA-256' }, base, 256);
    });
  }

  function seen(lock) {
    try { return !!sessionStorage.getItem(SEEN + lock); } catch (e) { return false; }
  }
  var keys = {};  // lock -> Promise<CryptoKey|null>, for this page view only
  var open = {};  // lock -> true once unlocked on this page
  function storedKey(lock) {
    return keys[lock] || Promise.resolve(null);
  }
  function refresh() {
    root.classList.toggle('site-unlocked', LOCKS.some(function (lock) { return open[lock] || seen(lock); }));
    Array.prototype.forEach.call(document.querySelectorAll('.masthead__menu-item--locked'), function (li) {
      li.classList.toggle('is-unlocked', seen(li.getAttribute('data-lock')));
    });
  }
  function forget(lock) {
    try { sessionStorage.removeItem(SEEN + lock); } catch (e) {}
    delete keys[lock];
    delete open[lock];
    refresh();
  }
  /* try the password on each of the locks; resolves to {lock: key} for the ones it opens, rejects if none */
  function unlockWith(password, locks) {
    var opened = {};
    return Promise.all(locks.map(function (lock) {
      return derive(lock, password).then(function (raw) {
        return verify(lock, raw).then(function (key) {
          try { sessionStorage.setItem(SEEN + lock, '1'); } catch (e) {}
          keys[lock] = Promise.resolve(key);
          open[lock] = true;
          opened[lock] = key;
          unlockPage(lock, key);
        }, function () {});
      });
    })).then(function () {
      if (!Object.keys(opened).length) throw new Error('wrong password');
      refresh();
      return opened;
    });
  }

  /* ---- password form and dialog ---- */
  var EYE = '<svg viewBox="0 0 24 24" width="18" height="18" aria-hidden="true"><path d="M2 12s3.6-7 10-7 10 7 10 7-3.6 7-10 7S2 12 2 12z" ' +
    'fill="none" stroke="currentColor" stroke-width="1.8"/><circle cx="12" cy="12" r="3" fill="none" stroke="currentColor" stroke-width="1.8"/></svg>';
  var EYE_OFF = '<svg viewBox="0 0 24 24" width="18" height="18" aria-hidden="true"><path d="M2 12s3.6-7 10-7 10 7 10 7-3.6 7-10 7S2 12 2 12z" ' +
    'fill="none" stroke="currentColor" stroke-width="1.8"/><circle cx="12" cy="12" r="3" fill="none" stroke="currentColor" stroke-width="1.8"/>' +
    '<path d="M4 20L20 4" stroke="currentColor" stroke-width="1.8" stroke-linecap="round"/></svg>';
  function form(message, locks, onDone) {
    var f = document.createElement('form');
    f.className = 'site-lock__form';
    f.innerHTML = '<p class="site-lock__msg"></p><div class="site-lock__row">' +
      '<span class="site-lock__field"><input type="password" autocomplete="current-password" placeholder="Password" aria-label="Password" required>' +
      '<button type="button" class="site-lock__eye" aria-label="Show password" aria-pressed="false" title="Show password">' + EYE + '</button></span>' +
      '<button type="submit" class="btn btn--inverse">Unlock</button></div><p class="site-lock__error" aria-live="polite"></p>';
    f.querySelector('.site-lock__msg').textContent = message;
    var eye = f.querySelector('.site-lock__eye');
    eye.addEventListener('click', function () {
      var input = f.querySelector('input'), show = input.type === 'password';
      input.type = show ? 'text' : 'password';
      eye.innerHTML = show ? EYE_OFF : EYE;
      eye.setAttribute('aria-pressed', show ? 'true' : 'false');
      eye.setAttribute('aria-label', show ? 'Hide password' : 'Show password');
      eye.title = eye.getAttribute('aria-label');
      input.focus();
    });
    f.addEventListener('submit', function (e) {
      e.preventDefault();
      var input = f.querySelector('input'), err = f.querySelector('.site-lock__error'), btn = f.querySelector('button');
      btn.disabled = true;
      err.textContent = '';
      unlockWith(input.value, locks).then(onDone, function () {
        err.textContent = 'Wrong password.';
        input.select();
      }).then(function () { btn.disabled = false; });
    });
    return f;
  }

  function dialog(message, locks) {
    return new Promise(function (resolve) {
      var back = document.createElement('div');
      back.className = 'site-lock__backdrop';
      var box = document.createElement('div');
      box.className = 'site-lock__dialog';
      box.setAttribute('role', 'dialog');
      box.setAttribute('aria-modal', 'true');
      box.setAttribute('aria-label', 'Password required');
      function close(opened) { back.remove(); document.removeEventListener('keydown', onKey); resolve(opened || null); }
      function onKey(e) { if (e.key === 'Escape') close(); }
      box.appendChild(form(message, locks, close));
      var cancel = document.createElement('button');
      cancel.type = 'button';
      cancel.className = 'site-lock__cancel';
      cancel.textContent = 'Cancel';
      cancel.addEventListener('click', function () { close(); });
      box.querySelector('.site-lock__row').appendChild(cancel);
      back.appendChild(box);
      back.addEventListener('click', function (e) { if (e.target === back) close(); });
      document.addEventListener('keydown', onKey);
      document.body.appendChild(back);
      box.querySelector('input').focus();
    });
  }

  /* the lock's key from storage, or ask for its password (null if cancelled) */
  function getKey(lock, message) {
    return storedKey(lock).then(function (key) {
      if (key) return key;
      return dialog(message || 'This content is password protected.', [lock]).then(function (opened) {
        return opened ? opened[lock] : null;
      });
    });
  }

  /* ---- protected page content: <div class="site-lock" data-lock="…" data-site-lock="…"> ---- */
  function blocks(lock) {
    return Array.prototype.filter.call(document.querySelectorAll('.site-lock[data-site-lock]'), function (el) {
      return !lock || el.getAttribute('data-lock') === lock;
    });
  }
  function unlockPage(lock, key) {
    blocks(lock).forEach(function (el) {
      decrypt(key, bytes(el.getAttribute('data-site-lock'))).then(function (buf) {
        var holder = document.createElement('div');
        holder.innerHTML = new TextDecoder().decode(buf);
        Array.prototype.forEach.call(holder.querySelectorAll('script'), function (old) {
          var s = document.createElement('script');  // scripts from innerHTML do not run; recreate them
          Array.prototype.forEach.call(old.attributes, function (a) { s.setAttribute(a.name, a.value); });
          s.textContent = old.textContent;
          old.replaceWith(s);
        });
        el.replaceWith.apply(el, Array.prototype.slice.call(holder.childNodes));
      });
    });
  }
  function lockedPage() {
    blocks().forEach(function (el) {
      var lock = el.getAttribute('data-lock');
      storedKey(lock).then(function (key) {
        if (key) { unlockPage(lock, key); return; }
        if (!el.firstChild) el.appendChild(form('This page is password protected.', [lock], function () {}));
        el.querySelector('input').focus();
      });
    });
  }

  /* ---- protected downloads: <a data-locked-file="/path.pdf" data-lock="cv" data-filename="name.pdf"> ---- */
  document.addEventListener('click', function (e) {
    var a = e.target.closest && e.target.closest('[data-locked-file]');
    if (!a) return;
    e.preventDefault();
    getKey(a.getAttribute('data-lock'), 'The download is password protected.').then(function (key) {
      if (!key) return;
      return fetch(a.getAttribute('data-locked-file') + '.enc').then(function (r) {
        if (!r.ok) throw new Error(r.status);
        return r.arrayBuffer();
      }).then(function (buf) { return decrypt(key, new Uint8Array(buf)); }).then(function (plain) {
        var url = URL.createObjectURL(new Blob([plain], { type: a.getAttribute('data-type') || 'application/pdf' }));
        var link = document.createElement('a');
        link.href = url;
        link.download = a.getAttribute('data-filename') || 'download';
        document.body.appendChild(link);
        link.click();
        link.remove();
        setTimeout(function () { URL.revokeObjectURL(url); }, 10000);
      });
    }).catch(function () { alert('The file could not be downloaded.'); });
  });

  /* ---- lock button in the masthead: any password opens the lock(s) it belongs to; when open, locks all ---- */
  var toggle = document.getElementById('site-lock-toggle');
  if (toggle) {
    toggle.addEventListener('click', function (e) {
      e.preventDefault();
      if (root.classList.contains('site-unlocked')) {
        LOCKS.forEach(forget);
        if (document.querySelector('[data-protected-page]')) location.reload();
      } else {
        dialog('Enter a password to unlock private pages.', LOCKS);
      }
    });
  }

  /* keys saved by the earlier version of this script: no longer kept */
  try { LOCKS.forEach(function (lock) { localStorage.removeItem('site-lock-key-' + lock); }); } catch (e) {}
  refresh();
  lockedPage();
  window.SiteLock = { getKey: getKey, forget: forget };
})();
