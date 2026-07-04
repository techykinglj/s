/* Privacy Sentinel — UI flow: Connect → Run Full Audit → report. */
'use strict';

(function () {

  const $ = (id) => document.getElementById(id);
  const btnConnect = $('btn-connect');
  const btnRun = $('btn-run');
  const statusLine = $('connect-status');
  const progressBox = $('progress');
  const progressList = $('progress-list');
  const resultsBox = $('results');
  const cardsMount = $('cards');
  const summaryLine = $('results-summary');

  /* Service worker: offline shell. Degrades silently on old Safari. */
  if ('serviceWorker' in navigator) {
    window.addEventListener('load', () => {
      navigator.serviceWorker.register('sw.js').catch(() => { /* e.g. file:// or old browser */ });
    });
  }

  /* iOS "Add to Home Screen" guidance (no install prompt exists on iOS). */
  (function iosHint() {
    const isIOS = /iPad|iPhone|iPod/.test(navigator.userAgent) ||
      (navigator.platform === 'MacIntel' && navigator.maxTouchPoints > 1);
    const standalone = window.matchMedia && window.matchMedia('(display-mode: standalone)').matches ||
      window.navigator.standalone === true;
    if (isIOS && !standalone) $('ios-install').hidden = false;
  })();

  /* Connect: real readiness checks, then enable Run. */
  let connected = false;
  btnConnect.addEventListener('click', async () => {
    if (connected) return;
    btnConnect.disabled = true;
    statusLine.textContent = 'Checking this browser\'s capabilities…';
    const caps = [];
    caps.push('fetch' in window ? 'network requests ✓' : 'network requests ✗');
    caps.push((navigator.permissions && navigator.permissions.query) ? 'permissions API ✓' : 'permissions API unavailable (checks adapt)');
    caps.push((window.crypto && crypto.subtle) ? 'secure hashing ✓' : 'secure hashing via fallback');
    caps.push(navigator.onLine ? 'online ✓' : 'offline — network checks will say so honestly');
    // Real reachability probe (does not block readiness if it fails; checks handle offline).
    let reach = 'not tested';
    if (navigator.onLine && 'fetch' in window) {
      try {
        await fetch('https://api.pwnedpasswords.com/range/00000', { method: 'GET', cache: 'no-store' });
        reach = 'external lookups reachable ✓';
      } catch (e) {
        reach = 'external lookups blocked — affected checks will report that';
      }
    }
    caps.push(reach);
    connected = true;
    btnConnect.textContent = '✓ Connected';
    btnConnect.classList.add('connected');
    btnConnect.disabled = true;
    btnRun.disabled = false;
    statusLine.textContent = caps.join(' · ');
  });

  /* Run Full Audit: sequential checks with a live progress list. */
  let running = false;
  btnRun.addEventListener('click', async () => {
    if (running) return;
    running = true;
    btnRun.disabled = true;
    resultsBox.hidden = true;
    progressList.textContent = '';
    progressBox.hidden = false;

    const inputs = {
      email: ($('inp-email').value || '').trim(),
      password: $('inp-password').value || '',
      domain: ($('inp-domain').value || '').trim()
    };
    const checks = Checks.all(inputs);

    const items = checks.map((c) => {
      const li = document.createElement('li');
      li.textContent = c.name;
      progressList.appendChild(li);
      return li;
    });

    const results = [];
    for (let i = 0; i < checks.length; i++) {
      items[i].classList.add('running');
      let r;
      try {
        r = await checks[i].run();
      } catch (e) {
        // Belt-and-braces: a check that somehow throws becomes an honest N/A, never a crash.
        r = { id: 'check-' + i, label: checks[i].name, status: 'NA',
              headline: 'This check failed to run on this platform.',
              details: { Error: String(e && e.message || e) } };
      }
      results.push(r);
      items[i].classList.remove('running');
      items[i].classList.add('done');
      items[i].textContent = checks[i].name + ' — done';
    }

    Report.render(results, cardsMount, summaryLine);
    progressBox.hidden = true;
    resultsBox.hidden = false;
    btnRun.disabled = false;
    btnRun.textContent = 'Run Again';
    running = false;
    resultsBox.scrollIntoView({ behavior: 'smooth', block: 'start' });
  });

})();
