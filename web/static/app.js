// Grafted Secrets — minimal vanilla interactions. No inline scripts (strict CSP),
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

  // --- theme: cycle system -> light -> dark, persisted in a cookie ---
  function setTheme(v) {
    document.documentElement.dataset.theme = v;
    document.cookie = 'gs_theme=' + v + '; path=/; max-age=31536000; samesite=lax';
    announce(v ? v + ' theme' : 'system theme');
  }
  function cycleTheme() {
    const cur = document.documentElement.dataset.theme || '';
    setTheme(cur === '' ? 'light' : cur === 'light' ? 'dark' : '');
  }

  // --- tree expand/collapse ---
  function openNode(node) {
    if (!node) return;
    node.classList.add('open');
    const tw = node.querySelector(':scope > .node-row > [data-twisty]');
    if (tw) tw.setAttribute('aria-expanded', 'true');
  }
  document.addEventListener('click', function (e) {
    const tw = e.target.closest('[data-twisty]');
    if (!tw) return; // htmx (if any) still handles its own lazy-load on this click
    const node = tw.closest('.node');
    const open = node.classList.toggle('open');
    tw.setAttribute('aria-expanded', String(open));
  });

  // --- click delegation ---
  document.addEventListener('click', function (e) {
    const t = e.target.closest('[data-open],[data-close],[data-copy],[data-toggle-input],[data-theme-toggle],[data-focus-search]');
    if (!t) return;

    if (t.hasAttribute('data-theme-toggle')) { cycleTheme(); return; }

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
  document.addEventListener('pointerdown', function (e) { downTarget = e.target; }, true);

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

    // A form/detail fragment was loaded into the shared dialog: open it.
    if (target.id === 'dialog') {
      if (target.children.length && target.showModal && !target.open) target.showModal();
      const f = target.querySelector('input,textarea,button');
      if (f) f.focus();
      return;
    }

    // Any other swap is a navigation or a mutation result → close the dialog.
    const dlg = document.getElementById('dialog');
    if (dlg && dlg.open) dlg.close();

    // A node was appended into a (possibly collapsed) branch: reveal it.
    if (target.classList && target.classList.contains('node-children')) {
      openNode(target.closest('.node'));
    }

    // Main view changed: move focus to the heading for a11y.
    if (target.id === 'main') {
      const h = target.querySelector('h1');
      if (h) { h.setAttribute('tabindex', '-1'); h.focus(); }
    }
  });

  document.addEventListener('htmx:responseError', function () {
    announce('Something went wrong. Please try again.');
  });
})();
