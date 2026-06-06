// Grafted Secrets - minimal vanilla interactions. No inline scripts (strict CSP),
// no framework. All behavior is wired via event delegation and htmx events.
(function () {
  'use strict';

  const $ = (sel, root) => (root || document).querySelector(sel);
  const status = () => $('#sr-status');

  function announce(msg) {
    const el = status();
    if (el) { el.textContent = ''; el.textContent = msg; }
  }

  // --- CSRF: attach the token only to state-changing htmx requests ---
  document.addEventListener('htmx:configRequest', function (e) {
    if (/^(get|head|options)$/i.test(e.detail.verb)) return;
    const m = $('meta[name=csrf-token]');
    if (m) e.detail.headers['X-CSRF-Token'] = m.content;
  });

  // --- clipboard (with plain-HTTP execCommand fallback) ---
  async function copyText(text) {
    if (navigator.clipboard) {
      try { await navigator.clipboard.writeText(text); return true; } catch (_) {}
    }
    // Fallback: offscreen (not opacity:0) + setSelectionRange works on iOS Safari.
    const ta = document.createElement('textarea');
    ta.value = text;
    ta.style.position = 'fixed';
    ta.style.left = '-9999px';
    ta.style.top = '0';
    document.body.appendChild(ta);
    ta.focus();
    ta.setSelectionRange(0, ta.value.length);
    let ok = false;
    try { ok = document.execCommand('copy'); } catch (_) {}
    document.body.removeChild(ta);
    return ok;
  }

  async function copyFrom(url) {
    try {
      const res = await fetch(url, { credentials: 'same-origin' });
      if (!res.ok) throw new Error('fetch');
      const text = await res.text();
      announce((await copyText(text)) ? 'Value copied' : 'Copy failed');
    } catch (_) { announce('Copy failed'); }
  }

  // --- code block copy buttons ---
  function initCodeCopy(root) {
    (root || document).querySelectorAll('.markdown pre').forEach(function (pre) {
      if (pre.querySelector('.code-copy-btn')) return;
      const btn = document.createElement('button');
      btn.type = 'button';
      btn.className = 'icon-btn code-copy-btn';
      btn.setAttribute('aria-label', 'Copy code');
      btn.setAttribute('data-copy-code', '');
      btn.innerHTML = '<svg class="icon" aria-hidden="true"><use href="#i-copy"></use></svg>';
      pre.appendChild(btn);
    });
  }

  // --- theme: cycle system -> light -> dark, persisted in a cookie ---
  function setTheme(v) {
    document.documentElement.dataset.theme = v;
    document.cookie = 'gs_theme=' + v + '; path=/; max-age=31536000; samesite=lax';
    announce(v ? v + ' theme' : 'system theme');
  }
  function effectiveTheme() {
    const t = document.documentElement.dataset.theme;
    if (t === 'light' || t === 'dark') return t;
    return window.matchMedia && window.matchMedia('(prefers-color-scheme: dark)').matches ? 'dark' : 'light';
  }
  // Two-state toggle so every tap visibly flips (no invisible "system" step).
  function toggleTheme() {
    setTheme(effectiveTheme() === 'dark' ? 'light' : 'dark');
  }

  // --- secret-name input: force UPPER_SNAKE_CASE as you type ---
  document.addEventListener('input', function (e) {
    const el = e.target;
    if (!el.matches || !el.matches('[data-keyname]')) return;
    const v = el.value.toUpperCase().replace(/\s/g, '_'); // 1:1 so the cursor stays put
    if (v !== el.value) {
      const s = el.selectionStart, end = el.selectionEnd;
      el.value = v;
      try { el.setSelectionRange(s, end); } catch (_) {}
    }
  });

  // --- tree expand/collapse ---
  function openNode(node) {
    if (!node) return;
    node.classList.add('open');
    const tw = node.querySelector(':scope > .node-row > [data-twisty]');
    if (tw) tw.setAttribute('aria-expanded', 'true');
  }
  // Tapping anywhere on a node row toggles it (the chevron is a tiny target on a
  // phone). Action buttons and links are excluded.
  document.addEventListener('click', function (e) {
    if (e.target.closest('.node-actions') || e.target.closest('a')) return;
    const row = e.target.closest('.node-row');
    if (!row) return;
    const tw = row.querySelector('[data-twisty]');
    if (!tw) return;
    if (e.target.closest('[data-twisty]')) {
      const node = tw.closest('.node');
      tw.setAttribute('aria-expanded', String(node.classList.toggle('open')));
    } else {
      tw.click(); // delegate so the chevron's lazy-load (secrets) still fires
    }
  });

  // --- per-row action menu (small screens collapse the icon cluster into a popover) ---
  function closeMenus(except) {
    document.querySelectorAll('.node-actions.menu-open').forEach(function (a) {
      if (a === except) return;
      a.classList.remove('menu-open');
      const b = a.querySelector('[data-menu]');
      if (b) b.setAttribute('aria-expanded', 'false');
    });
  }
  document.addEventListener('click', function (e) {
    const toggle = e.target.closest('[data-menu]');
    if (toggle) {
      const actions = toggle.closest('.node-actions');
      closeMenus(actions);
      const open = actions.classList.toggle('menu-open');
      toggle.setAttribute('aria-expanded', String(open));
      return;
    }
    // A click on an action inside the menu still runs (htmx/copy handle it); we
    // just dismiss the popover. Any click outside dismisses too.
    closeMenus(null);
  });
  document.addEventListener('keydown', function (e) {
    if (e.key === 'Escape') closeMenus(null);
  });

  // --- search dropdown ---
  function clearSearch() { const r = $('#search-results'); if (r) r.innerHTML = ''; }
  document.addEventListener('click', function (e) {
    if (e.target.closest('.search-hit')) { clearSearch(); return; } // let htmx navigate
    if (!e.target.closest('.search')) clearSearch();
  });
  function unflash() {
    document.querySelectorAll('.node.flash').forEach(function (n) { n.classList.remove('flash'); });
  }
  function focusSecret(id) {
    const node = document.getElementById('secret-' + id);
    if (!node) return;
    let p = node.parentElement ? node.parentElement.closest('.node') : null;
    while (p) { openNode(p); p = p.parentElement ? p.parentElement.closest('.node') : null; }
    node.scrollIntoView({ block: 'center' });
    unflash();
    node.classList.add('flash'); // stays until the next interaction (see pointerdown)
  }
  // The target key travels in the URL (?key=...) so focus survives any nav path.
  function focusFromURL() {
    const key = new URLSearchParams(location.search).get('key');
    if (!key) return false;
    focusSecret(key);
    try { history.replaceState(history.state, '', location.pathname); } catch (_) {}
    return true;
  }

  // --- click delegation ---
  document.addEventListener('click', function (e) {
    const t = e.target.closest('[data-open],[data-close],[data-copy],[data-copy-code],[data-toggle-input],[data-theme-toggle],[data-focus-search],[data-notes-mode]');
    if (!t) return;

    if (t.hasAttribute('data-theme-toggle')) { toggleTheme(); return; }

    if (t.dataset.notesMode) {
      const form = t.closest('form');
      const ta = form && form.querySelector('[data-notes]');
      const pv = form && form.querySelector('.notes-preview');
      const seg = t.closest('.seg');
      if (seg) seg.querySelectorAll('[data-notes-mode]').forEach((b) => b.classList.toggle('active', b === t));
      const preview = t.dataset.notesMode === 'preview';
      if (ta) ta.hidden = preview;
      if (pv) pv.hidden = !preview;
      if (preview && pv && ta) {
        const csrf = $('meta[name=csrf-token]');
        fetch('/notes/preview', {
          method: 'POST',
          credentials: 'same-origin',
          headers: {
            'Content-Type': 'application/x-www-form-urlencoded',
            'X-CSRF-Token': csrf ? csrf.content : '',
          },
          body: 'notes=' + encodeURIComponent(ta.value),
        }).then(function (r) { return r.text(); }).then(function (html) { pv.innerHTML = html; });
      }
      return;
    }

    if (t.hasAttribute('data-focus-search')) {
      const s = $('[data-search]'); if (s) s.focus();
      return;
    }
    if (t.dataset.open) {
      const d = $(t.dataset.open); if (d && d.showModal && !d.open) d.showModal();
      return;
    }
    if (t.hasAttribute('data-close')) {
      const d = t.closest('dialog'); if (d) d.close();
      return;
    }
    if (t.dataset.copy) { copyFrom(t.dataset.copy); return; }
    if (t.hasAttribute('data-copy-code')) {
      const pre = t.closest('pre');
      const code = pre && pre.querySelector('code');
      const text = (code || pre) ? (code || pre).textContent : '';
      copyText(text.replace(/\n$/, '')).then(function (ok) { announce(ok ? 'Copied' : 'Copy failed'); });
      return;
    }

    if (t.hasAttribute('data-toggle-input')) {
      const input = t.parentElement.querySelector('[data-secret-input]');
      if (input) {
        const show = input.type === 'password';
        input.type = show ? 'text' : 'password';
        t.setAttribute('aria-pressed', String(show));
        t.setAttribute('aria-label', show ? 'Hide value' : 'Show value');
      }
      return;
    }
  });

  // Track where a press started so a drag that ends on the backdrop (e.g. a text
  // selection dragged out of a field) does not dismiss the dialog.
  let downTarget = null;
  document.addEventListener('pointerdown', function (e) { downTarget = e.target; unflash(); }, true);

  // close a dialog only when both press and release land on its backdrop
  document.addEventListener('click', function (e) {
    if (e.target.tagName === 'DIALOG' && e.target.open && downTarget === e.target) {
      const r = e.target.getBoundingClientRect();
      const inside = e.clientX >= r.left && e.clientX <= r.right && e.clientY >= r.top && e.clientY <= r.bottom;
      if (!inside) e.target.close();
    }
  });

  // Clear the shared dialog on close so secret-bearing markup never lingers in
  // the DOM and a no-swap response can't re-show a stale body.
  const sharedDialog = document.getElementById('dialog');
  if (sharedDialog) sharedDialog.addEventListener('close', function () { this.innerHTML = ''; });

  // --- htmx swap lifecycle ---
  document.addEventListener('htmx:afterSwap', function (e) {
    const target = e.detail.target;
    if (!target) return;
    initCodeCopy(target);

    // A form/detail fragment was loaded into the shared dialog: open it.
    if (target.id === 'dialog') {
      if (target.children.length && target.showModal && !target.open) target.showModal();
      const f = target.querySelector('input,textarea,button');
      if (f) f.focus();
      return;
    }

    // A navigation/mutation result lands OUTSIDE the dialog → close it. A swap
    // into the dialog (e.g. the notes preview) must leave it open.
    const dlg = document.getElementById('dialog');
    if (dlg && dlg.open && !dlg.contains(target)) dlg.close();

    // A node was appended into a (possibly collapsed) branch: reveal it.
    if (target.classList && target.classList.contains('node-children')) {
      openNode(target.closest('.node'));
    }

    // Main view changed: jump to a searched key, else move focus to the heading.
    if (target.id === 'main') {
      clearSearch();
      if (focusFromURL()) return;
      const h = target.querySelector('h1');
      if (h) { h.setAttribute('tabindex', '-1'); h.focus(); }
    }
  });

  // Initial full-page load straight to /projects/{id}?key={id} (e.g. a bookmarked
  // or non-htmx search result).
  focusFromURL();
  initCodeCopy(document);

  document.addEventListener('htmx:responseError', function () {
    announce('Something went wrong. Please try again.');
  });

  // --- restore interstitial: wait for the server to bounce, then go to unlock ---
  // The restore stages a new database and restarts the process. Once graceful
  // shutdown begins the old server refuses new connections, so the first healthz
  // that succeeds is the restarted server -> go straight to unlock. Each probe is
  // abort-timed because a restarting Docker proxy can accept then hang the socket.
  (function restoreWait() {
    if (!document.querySelector('[data-restore-wait]')) return;
    var done = false;
    function go() { if (!done) { done = true; location.href = '/unlock'; } }
    function poll() {
      if (done) return;
      var ctrl = new AbortController();
      var to = setTimeout(function () { ctrl.abort(); }, 1500);
      fetch('/healthz', { cache: 'no-store', signal: ctrl.signal })
        .then(function (r) { clearTimeout(to); if (r.ok) { go(); } else { setTimeout(poll, 1200); } })
        .catch(function () { clearTimeout(to); setTimeout(poll, 1200); });
    }
    // Brief head start so the restart is underway before the first probe; then a
    // hard fallback so the page can never get stuck if probing somehow stalls.
    setTimeout(poll, 2500);
    setTimeout(go, 25000);
  })();
})();
