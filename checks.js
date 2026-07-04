/* Privacy Sentinel — web checks.
 * Every check returns { id, label, status, headline, details }.
 * status ∈ CLEAR | ATTENTION | RISK | NA
 * Rule: real live measurement or an explicit "Not available on this platform."
 * Never fabricate. Never throw — every check catches its own failures.
 */
'use strict';

const Checks = (() => {

  const NA = 'NA', CLEAR = 'CLEAR', ATTENTION = 'ATTENTION', RISK = 'RISK';

  // Shared state populated by earlier checks for later heuristics.
  const shared = { ipInfo: null, ipInfoSource: null, secondIp: null };

  function result(id, label, status, headline, details) {
    return { id, label, status, headline, details: details || {} };
  }

  async function fetchJson(url, timeoutMs) {
    const ctl = ('AbortController' in self) ? new AbortController() : null;
    const t = ctl ? setTimeout(() => ctl.abort(), timeoutMs || 8000) : null;
    try {
      const r = await fetch(url, { signal: ctl ? ctl.signal : undefined });
      if (!r.ok) throw new Error('HTTP ' + r.status);
      return await r.json();
    } finally {
      if (t) clearTimeout(t);
    }
  }

  /* 1. Public network identity */
  async function publicNetwork() {
    const id = 'public-network', label = 'Public network identity';
    if (!navigator.onLine) {
      return result(id, label, NA, 'You appear to be offline — no lookup performed.',
        { Note: 'Reconnect and re-run to see what sites learn about your network.' });
    }
    // Primary: ipwho.is (keyless, CORS-enabled). Fallback: ipapi.co.
    let info = null, source = null;
    try {
      const j = await fetchJson('https://ipwho.is/');
      if (j && j.ip) {
        info = { ip: j.ip, city: j.city, region: j.region, country: j.country,
                 isp: j.connection && j.connection.isp, org: j.connection && j.connection.org,
                 asn: j.connection && j.connection.asn, timezone: j.timezone && j.timezone.id };
        source = 'ipwho.is';
      }
    } catch (e) { /* fall through */ }
    if (!info) {
      try {
        const j = await fetchJson('https://ipapi.co/json/');
        if (j && j.ip) {
          info = { ip: j.ip, city: j.city, region: j.region, country: j.country_name,
                   isp: j.org, org: j.org, asn: j.asn, timezone: j.timezone };
          source = 'ipapi.co';
        }
      } catch (e) { /* fall through */ }
    }
    if (!info) {
      return result(id, label, NA, 'Public IP lookup services were unreachable from this network.',
        { Note: 'This can happen behind strict firewalls or content blockers. Nothing was measured — no value is shown rather than a guess.' });
    }
    shared.ipInfo = info; shared.ipInfoSource = source;
    const place = [info.city, info.region, info.country].filter(Boolean).join(', ');
    return result(id, label, ATTENTION,
      'Every site you visit sees this: ' + info.ip + (place ? ' near ' + place : ''),
      { 'Public IP': info.ip, 'Approximate location (from IP)': place || 'unresolved',
        'Internet provider / organisation': info.isp || info.org || 'unresolved',
        'Network (ASN)': info.asn || 'unresolved',
        'Looked up via': source,
        'What this means': 'This is broadcast by design with every connection. A VPN replaces it with the VPN\'s address.' });
  }

  /* 2. WebRTC local-IP leak */
  async function webrtcLeak() {
    const id = 'webrtc', label = 'WebRTC IP leak';
    const RTC = window.RTCPeerConnection || window.webkitRTCPeerConnection;
    if (!RTC) {
      return result(id, label, CLEAR, 'WebRTC is not exposed by this browser — this leak vector is closed.',
        { Note: 'RTCPeerConnection is absent, so the classic VPN-defeating IP leak cannot occur here.' });
    }
    try {
      const ips = await new Promise((resolve) => {
        const found = new Set();
        let pc;
        try { pc = new RTC({ iceServers: [] }); } catch (e) { resolve(null); return; }
        const finish = () => { try { pc.close(); } catch (e) {} resolve([...found]); };
        const timer = setTimeout(finish, 3000);
        pc.onicecandidate = (ev) => {
          if (!ev.candidate) { clearTimeout(timer); finish(); return; }
          const m = /([0-9]{1,3}(?:\.[0-9]{1,3}){3}|[0-9a-f]{1,4}(?::[0-9a-f]{1,4}){7})/i.exec(ev.candidate.candidate);
          if (m) found.add(m[1]);
          if (/\.local/.test(ev.candidate.candidate)) found.add('(mDNS-obfuscated)');
        };
        try {
          pc.createDataChannel('probe');
          pc.createOffer().then(o => pc.setLocalDescription(o)).catch(() => { clearTimeout(timer); finish(); });
        } catch (e) { clearTimeout(timer); finish(); }
      });
      if (ips === null) {
        return result(id, label, CLEAR, 'WebRTC connections are blocked — this leak vector is closed.', {});
      }
      const isPrivate = (ip) => /^(10\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.|169\.254\.|fe80:|fd|fc)/i.test(ip);
      const privates = ips.filter(isPrivate);
      const publics = ips.filter(ip => !isPrivate(ip) && ip !== '(mDNS-obfuscated)');
      const details = {
        'Addresses surfaced by WebRTC': ips.length ? ips.join(', ') : 'none',
        'What this means': 'WebRTC can reveal your device\'s local network address (and sometimes your real public IP) even behind a VPN. Modern browsers hide it behind a random ".local" name.'
      };
      if (privates.length || publics.length) {
        return result(id, label, RISK,
          'WebRTC exposes ' + (privates.length ? 'your local network address' : 'an IP address') + ' to any site that asks.',
          details);
      }
      return result(id, label, CLEAR,
        ips.includes('(mDNS-obfuscated)')
          ? 'Your browser masks WebRTC addresses (mDNS obfuscation) — protected.'
          : 'No IP addresses leaked via WebRTC.',
        details);
    } catch (e) {
      return result(id, label, CLEAR, 'WebRTC probing failed safely — treated as blocked/protected.',
        { Error: String(e && e.message || e) });
    }
  }

  /* 3. DNS leak indicator (honest heuristic) */
  async function dnsIndicator() {
    const id = 'dns', label = 'DNS leak indicator';
    const details = {
      'Honest limitation': 'A web page cannot see which DNS servers your device uses — a true DNS-leak test needs special server infrastructure. What follows is indicative only.'
    };
    if (!navigator.onLine || !shared.ipInfo) {
      return result(id, label, NA, 'Indicative test unavailable (offline or IP lookup failed).', details);
    }
    // Cross-check: a second, independent IP endpoint. Disagreement suggests split/proxied routing.
    let second = null;
    try {
      const j = await fetchJson('https://api.ipify.org?format=json', 6000);
      second = j && j.ip;
    } catch (e) { /* endpoint unreachable — fine */ }
    shared.secondIp = second;
    if (second && second !== shared.ipInfo.ip) {
      details['Endpoint A (' + shared.ipInfoSource + ')'] = shared.ipInfo.ip;
      details['Endpoint B (ipify.org)'] = second;
      return result(id, label, ATTENTION,
        'Two lookup services saw different public IPs — traffic may be split across routes (indicative, not proof).', details);
    }
    details['Consistency'] = second
      ? 'Two independent services saw the same public IP (' + second + ').'
      : 'Second service unreachable; only one measurement available.';
    details['To go further'] = 'Use your VPN provider\'s own leak-test page, which controls the resolver side and can name your actual DNS servers.';
    return result(id, label, CLEAR, 'No routing inconsistency observed (indicative check only).', details);
  }

  /* 4. VPN / proxy heuristic */
  async function vpnHeuristic() {
    const id = 'vpn', label = 'VPN / proxy heuristic';
    if (!shared.ipInfo) {
      return result(id, label, NA, 'Cannot assess — public IP lookup was unavailable.', {});
    }
    const info = shared.ipInfo;
    let browserTz = null;
    try { browserTz = Intl.DateTimeFormat().resolvedOptions().timeZone || null; } catch (e) {}
    const tzMismatch = !!(browserTz && info.timezone && browserTz !== info.timezone);
    const orgText = ((info.isp || '') + ' ' + (info.org || '') + ' ' + (info.asn || '')).toLowerCase();
    const dcHints = ['hosting', 'datacenter', 'data center', 'cloud', 'vpn', 'proxy', 'server', 'digitalocean', 'linode', 'ovh', 'hetzner', 'amazon', 'aws', 'google cloud', 'azure', 'm247', 'leaseweb', 'vultr', 'choopa', 'colocation'];
    const dcHit = dcHints.filter(h => orgText.includes(h));
    const details = {
      'Browser timezone': browserTz || 'unavailable',
      'Timezone of your public IP': info.timezone || 'unresolved',
      'Network organisation': (info.isp || info.org || 'unresolved'),
      'Datacenter/VPN keywords in network name': dcHit.length ? dcHit.join(', ') : 'none',
      'Honest limitation': 'This is a heuristic, not a certainty. Residential VPNs and corporate proxies can evade it; travel can trigger it falsely.'
    };
    if (tzMismatch && dcHit.length) {
      return result(id, label, CLEAR, 'Strong signs you are behind a VPN/proxy (timezone mismatch + datacenter network). Good for privacy.', details);
    }
    if (tzMismatch || dcHit.length) {
      return result(id, label, ATTENTION,
        (tzMismatch ? 'Your clock timezone differs from your IP\'s timezone' : 'Your IP belongs to a datacenter-type network') + ' — possibly a VPN/proxy, possibly travel.', details);
    }
    return result(id, label, ATTENTION, 'No VPN/proxy indicators — you appear to browse from your real connection.', details);
  }

  /* 5. Device fingerprint */
  async function deviceFingerprint() {
    const id = 'device-fp', label = 'Device fingerprint';
    const d = {};
    const add = (k, v) => { d[k] = (v === undefined || v === null || v === '') ? 'not exposed by this browser' : String(v); };
    try { add('User agent', navigator.userAgent); } catch (e) { add('User agent', null); }
    try { add('Platform', navigator.platform); } catch (e) { add('Platform', null); }
    try { add('Languages', (navigator.languages || [navigator.language]).join(', ')); } catch (e) { add('Languages', null); }
    try { add('Timezone', Intl.DateTimeFormat().resolvedOptions().timeZone); } catch (e) { add('Timezone', null); }
    try { add('Screen', screen.width + '×' + screen.height + ' @ ' + screen.colorDepth + '-bit'); } catch (e) { add('Screen', null); }
    add('Device memory (GB)', ('deviceMemory' in navigator) ? navigator.deviceMemory : null);
    add('CPU cores', ('hardwareConcurrency' in navigator) ? navigator.hardwareConcurrency : null);
    add('Touch support', ('maxTouchPoints' in navigator) ? (navigator.maxTouchPoints > 0 ? 'yes (' + navigator.maxTouchPoints + ' points)' : 'no') : null);
    // Rough distinctiveness impression: count how many attributes carry entropy.
    const distinct = Object.values(d).filter(v => v !== 'not exposed by this browser').length;
    d['Uniqueness impression'] = distinct + ' of ' + Object.keys(d).length +
      ' attributes exposed. Combined, attributes like these routinely single out one browser among millions — no cookies needed.';
    return result(id, label, ATTENTION,
      'Your browser volunteers ' + distinct + ' identifying attributes to every site.', d);
  }

  /* 6. Canvas + WebGL fingerprint */
  async function canvasWebgl() {
    const id = 'canvas-webgl', label = 'Canvas & GPU fingerprint';
    const details = {};
    let canvasHash = null, webglVendor = null, webglRenderer = null;
    try {
      const c = document.createElement('canvas');
      c.width = 240; c.height = 60;
      const ctx = c.getContext('2d');
      if (ctx) {
        ctx.textBaseline = 'top';
        ctx.font = '14px Arial';
        ctx.fillStyle = '#f60'; ctx.fillRect(120, 1, 62, 20);
        ctx.fillStyle = '#069'; ctx.fillText('Sentinel, 🛡 fingerprint', 2, 15);
        ctx.fillStyle = 'rgba(102,204,0,.7)'; ctx.fillText('Sentinel, 🛡 fingerprint', 4, 17);
        const data = c.toDataURL();
        canvasHash = await hashString(data);
      }
    } catch (e) { /* blocked */ }
    try {
      const c2 = document.createElement('canvas');
      const gl = c2.getContext('webgl') || c2.getContext('experimental-webgl');
      if (gl) {
        const ext = gl.getExtension('WEBGL_debug_renderer_info');
        if (ext) {
          webglVendor = gl.getParameter(ext.UNMASKED_VENDOR_WEBGL);
          webglRenderer = gl.getParameter(ext.UNMASKED_RENDERER_WEBGL);
        } else {
          webglVendor = gl.getParameter(gl.VENDOR);
          webglRenderer = gl.getParameter(gl.RENDERER) + ' (unmasked value withheld by browser)';
        }
      }
    } catch (e) { /* blocked */ }
    details['Canvas hash'] = canvasHash ? canvasHash.slice(0, 24) + '… (stable per device+browser)' : 'blocked or unavailable';
    details['GPU vendor'] = webglVendor || 'blocked or unavailable';
    details['GPU renderer'] = webglRenderer || 'blocked or unavailable';
    details['What this means'] = 'Tiny rendering differences make this hash a durable tracker; the GPU string often names your exact device model.';
    if (!canvasHash && !webglRenderer) {
      return result(id, label, CLEAR, 'Canvas and WebGL fingerprinting are blocked — anti-fingerprinting protection is active.', details);
    }
    return result(id, label, ATTENTION,
      'Sites can compute a stable graphics fingerprint of this device' + (webglRenderer ? ' (GPU: ' + String(webglRenderer).slice(0, 60) + ')' : '') + '.', details);
  }

  /* 7. Audio fingerprint */
  async function audioFingerprint() {
    const id = 'audio-fp', label = 'Audio fingerprint';
    const AC = window.OfflineAudioContext || window.webkitOfflineAudioContext;
    if (!AC) {
      return result(id, label, NA, 'Not available on this platform (no OfflineAudioContext).', {});
    }
    try {
      const ctx = new AC(1, 44100, 44100);
      const osc = ctx.createOscillator();
      osc.type = 'triangle'; osc.frequency.value = 10000;
      const comp = ctx.createDynamicsCompressor();
      osc.connect(comp); comp.connect(ctx.destination);
      osc.start(0);
      const buf = await ctx.startRendering();
      const data = buf.getChannelData(0);
      let sum = 0;
      for (let i = 4500; i < 5000; i++) sum += Math.abs(data[i]);
      const sig = sum.toFixed(8);
      const hash = await hashString(sig);
      return result(id, label, ATTENTION,
        'Your audio stack produces a measurable signature sites can use to track you.',
        { 'Audio signature hash': hash.slice(0, 24) + '…',
          'Raw signal sum': sig,
          'What this means': 'Audio processing differs subtly per device/OS/browser — another cookie-less tracking handle.' });
    } catch (e) {
      return result(id, label, CLEAR, 'Audio fingerprinting appears blocked — protection active.',
        { Error: String(e && e.message || e) });
    }
  }

  /* 8. Font enumeration */
  async function fontEnumeration() {
    const id = 'fonts', label = 'Installed-font surface';
    try {
      const probe = ['Arial', 'Arial Black', 'Verdana', 'Helvetica', 'Helvetica Neue', 'Times New Roman', 'Georgia',
        'Courier New', 'Menlo', 'Monaco', 'Consolas', 'Tahoma', 'Trebuchet MS', 'Impact', 'Comic Sans MS',
        'Palatino', 'Garamond', 'Futura', 'Gill Sans', 'Optima', 'Baskerville', 'American Typewriter',
        'Avenir', 'Avenir Next', 'San Francisco', 'Segoe UI', 'Calibri', 'Cambria', 'Roboto', 'Noto Sans',
        'Ubuntu', 'Droid Sans', 'Lucida Grande', 'Lucida Console', 'Copperplate', 'Didot', 'Rockwell', 'Hoefler Text'];
      const bases = ['monospace', 'sans-serif', 'serif'];
      const span = document.createElement('span');
      span.style.cssText = 'position:absolute;left:-9999px;top:-9999px;font-size:72px;visibility:hidden';
      span.textContent = 'mmmMMMwwwlli10O°—悟';
      document.body.appendChild(span);
      const baseline = {};
      for (const b of bases) {
        span.style.fontFamily = b;
        baseline[b] = span.offsetWidth + 'x' + span.offsetHeight;
      }
      const present = [];
      for (const f of probe) {
        for (const b of bases) {
          span.style.fontFamily = '"' + f + '",' + b;
          if ((span.offsetWidth + 'x' + span.offsetHeight) !== baseline[b]) { present.push(f); break; }
        }
      }
      document.body.removeChild(span);
      return result(id, label, ATTENTION,
        present.length + ' of ' + probe.length + ' probed fonts are detectable — part of your fingerprint.',
        { 'Detected fonts': present.join(', ') || 'none beyond defaults',
          'What this means': 'Which fonts your system has is measurable without permission and adds bits to your fingerprint.' });
    } catch (e) {
      return result(id, label, NA, 'Font probing not available on this platform.', { Error: String(e && e.message || e) });
    }
  }

  /* 9. Permission states */
  async function permissionStates() {
    const id = 'permissions', label = 'Site permissions';
    if (!navigator.permissions || !navigator.permissions.query) {
      return result(id, label, NA, 'Not available on this platform (Permissions API absent — common on iOS Safari).',
        { Note: 'Check Settings → Safari (or your browser\'s site settings) manually for camera/mic/location grants.' });
    }
    const wanted = [
      ['camera', 'Camera'], ['microphone', 'Microphone'], ['geolocation', 'Location'],
      ['notifications', 'Notifications'], ['clipboard-read', 'Clipboard (read)']
    ];
    const states = {}; const granted = [];
    for (const [name, pretty] of wanted) {
      try {
        const st = await navigator.permissions.query({ name });
        states[pretty] = st.state;
        if (st.state === 'granted') granted.push(pretty);
      } catch (e) {
        states[pretty] = 'not queryable in this browser';
      }
    }
    states['What this means'] = 'Anything "granted" here works for this site without asking again. Review grants you don\'t remember making.';
    if (granted.length) {
      return result(id, label, ATTENTION,
        'Already granted to this site: ' + granted.join(', ') + '.', states);
    }
    return result(id, label, CLEAR, 'No sensitive permission is pre-granted to this site.', states);
  }

  /* 10. Privacy signals */
  async function privacySignals() {
    const id = 'privacy-signals', label = 'Privacy signals';
    const d = {};
    let dnt = null;
    try { dnt = navigator.doNotTrack || window.doNotTrack || navigator.msDoNotTrack || null; } catch (e) {}
    d['Do Not Track'] = dnt === '1' ? 'enabled' : (dnt === '0' ? 'explicitly disabled' : 'not set (most browsers dropped it)');
    const gpc = ('globalPrivacyControl' in navigator) ? navigator.globalPrivacyControl : null;
    d['Global Privacy Control'] = gpc === true ? 'enabled — sites you visit receive a legal do-not-sell signal'
      : (gpc === false ? 'available but off' : 'not supported by this browser');
    try { d['First-party cookies'] = navigator.cookieEnabled ? 'enabled' : 'disabled'; } catch (e) { d['First-party cookies'] = 'unknown'; }
    d['Storage Access API'] = (document.hasStorageAccess ? 'present (browser partitions third-party storage)' : 'absent');
    d['Third-party cookies'] = 'not directly testable from a single page (needs a second domain) — modern Safari/Firefox block them by default; Chrome is phasing them out.';
    const good = (gpc === true) || (dnt === '1');
    return result(id, label, good ? CLEAR : ATTENTION,
      good ? 'You broadcast an opt-out privacy signal — good.'
           : 'No opt-out signal (GPC/DNT) is being sent; consider a browser or extension that sends Global Privacy Control.',
      d);
  }

  /* 11. Account breach check (email, HIBP — key required) */
  async function emailBreach(email) {
    const id = 'email-breach', label = 'Email breach lookup';
    if (!email) {
      return result(id, label, NA, 'Skipped — no email entered.',
        { Note: 'Enter an email in the optional box above and re-run to check it against known breaches.' });
    }
    const key = (typeof window !== 'undefined' && window.HIBP_KEY) ? window.HIBP_KEY : null;
    const useProxy = (typeof window !== 'undefined' && window.BREACH_PROXY === true);
    // Preferred: same-origin serverless proxy (keeps the key server-side).
    // Only attempted when explicitly enabled in config.js — never a speculative 404.
    if (useProxy) {
      try {
        const r = await fetch('/api/breach?email=' + encodeURIComponent(email), { headers: { 'Accept': 'application/json' } });
        if (r.ok) return breachVerdict(id, label, email, await r.json());
        // A JSON 404 is HIBP's "no breaches"; an HTML 404 is a missing proxy — never confuse the two.
        const ct = r.headers.get('content-type') || '';
        if (r.status === 404 && ct.includes('json')) return breachVerdict(id, label, email, []);
        throw new Error('proxy HTTP ' + r.status);
      } catch (e) {
        return result(id, label, NA, 'The breach proxy at /api/breach did not respond as expected.',
          { Error: String(e && e.message || e),
            Note: 'BREACH_PROXY is enabled in config.js but the endpoint is missing or broken — see README.' });
      }
    }
    if (!key) {
      return result(id, label, NA, 'Add a HIBP API key to enable breach-by-email lookup.',
        { 'How to enable': 'Get a key at haveibeenpwned.com/API/Key, copy web/config.example.js to web/config.js and set window.HIBP_KEY. The key is never committed (config.js is gitignored).',
          'Why': 'Have I Been Pwned requires a paid API key for by-email lookups. Without one this check stays off rather than showing invented results.' });
    }
    try {
      const r = await fetch('https://haveibeenpwned.com/api/v3/breachedaccount/' + encodeURIComponent(email) + '?truncateResponse=false',
        { headers: { 'hibp-api-key': key } });
      if (r.status === 404) return breachVerdict(id, label, email, []);
      if (!r.ok) throw new Error('HTTP ' + r.status);
      return breachVerdict(id, label, email, await r.json());
    } catch (e) {
      return result(id, label, NA, 'Breach lookup could not run from this page (the HIBP API blocks direct browser calls).',
        { Error: String(e && e.message || e),
          'How to enable': 'Deploy the app with a serverless proxy at /api/breach that adds the hibp-api-key header server-side (see README).' });
    }
  }
  function breachVerdict(id, label, email, breaches) {
    if (!breaches || !breaches.length) {
      return result(id, label, CLEAR, email + ' does not appear in known breaches indexed by Have I Been Pwned.', {});
    }
    const names = breaches.map(b => (b.Title || b.Name || 'unknown') + (b.BreachDate ? ' (' + b.BreachDate + ')' : ''));
    return result(id, label, RISK,
      email + ' appears in ' + breaches.length + ' known breach' + (breaches.length > 1 ? 'es' : '') + '.',
      { 'Breaches': names.join('; '),
        'Do this now': 'Change the password anywhere you reused it, and turn on two-factor authentication.' });
  }

  /* 12. Password exposure (HIBP k-anonymity range API — keyless) */
  async function passwordExposure(password) {
    const id = 'password', label = 'Password exposure';
    if (!password) {
      return result(id, label, NA, 'Skipped — no password entered.',
        { Note: 'Enter a password in the optional box and re-run. Only 5 anonymised characters ever leave this device.' });
    }
    try {
      const hex = (await sha1Hex(password)).toUpperCase();
      const prefix = hex.slice(0, 5), suffix = hex.slice(5);
      const r = await fetch('https://api.pwnedpasswords.com/range/' + prefix);
      if (!r.ok) throw new Error('HTTP ' + r.status);
      const text = await r.text();
      let count = 0;
      for (const line of text.split(/\r?\n/)) {
        const [suf, c] = line.split(':');
        if (suf && suf.trim() === suffix) { count = parseInt(c, 10) || 0; break; }
      }
      if (count > 0) {
        return result(id, label, RISK,
          'This password appears ' + count.toLocaleString() + ' times in known breach data — never use it anywhere.',
          { 'Times seen in breaches': String(count),
            'Privacy note': 'The password never left this page. Only the first 5 characters of its SHA-1 hash were sent (k-anonymity); matching happened locally.' });
      }
      return result(id, label, CLEAR, 'This password does not appear in known breach data.',
        { 'Privacy note': 'Only the first 5 characters of an anonymised hash were sent; the password itself never left this page.' });
    } catch (e) {
      return result(id, label, NA, 'The breach-password service was unreachable — check not performed.',
        { Error: String(e && e.message || e) });
    }
  }

  /* 13. Connection security */
  async function connectionSecurity(domain) {
    const id = 'connection', label = 'Connection security';
    const d = {};
    const https = location.protocol === 'https:';
    const local = /^(localhost|127\.|0\.0\.0\.0|\[::1\])/.test(location.hostname) || location.protocol === 'file:';
    d['This page'] = https ? 'served over HTTPS — encrypted in transit'
      : (local ? 'local/dev context (' + location.protocol + '//' + location.hostname + ') — HTTPS applies once deployed' : 'NOT served over HTTPS — anything you type here could be read in transit');
    let status = https || local ? CLEAR : RISK;
    if (domain) {
      const host = domain.trim().replace(/^https?:\/\//i, '').replace(/\/.*$/, '');
      if (host) {
        try {
          await fetch('https://' + host + '/', { mode: 'no-cors', cache: 'no-store' });
          d['Your site (' + host + ')'] = 'reachable over HTTPS ✓';
          d['Security headers'] = 'not readable from a browser page (cross-origin responses are opaque). Use securityheaders.com for a full header grade — honest limitation, not an omission.';
        } catch (e) {
          d['Your site (' + host + ')'] = 'could not be reached over HTTPS from this browser (site down, blocked, or HTTPS not configured).';
          if (status === CLEAR) status = ATTENTION;
        }
      }
    } else {
      d['Your site'] = 'skipped — no domain entered (optional).';
    }
    return result(id, label, status,
      https ? 'Your connection to this page is encrypted.' :
      (local ? 'Running locally — deploy behind HTTPS (any static host does this automatically).' :
       'This page is not encrypted — do not enter secrets on non-HTTPS pages.'),
      d);
  }

  /* ---- hashing helpers ---- */
  async function hashString(s) {
    if (window.crypto && crypto.subtle && window.isSecureContext) {
      const buf = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(s));
      return [...new Uint8Array(buf)].map(b => b.toString(16).padStart(2, '0')).join('');
    }
    return sha1Fallback(s); // non-secure context fallback; still a real digest
  }
  async function sha1Hex(s) {
    if (window.crypto && crypto.subtle && window.isSecureContext) {
      const buf = await crypto.subtle.digest('SHA-1', new TextEncoder().encode(s));
      return [...new Uint8Array(buf)].map(b => b.toString(16).padStart(2, '0')).join('');
    }
    return sha1Fallback(s);
  }
  // Compact pure-JS SHA-1 (for http:// LAN testing where crypto.subtle is absent).
  function sha1Fallback(msg) {
    function rotl(n, s) { return (n << s) | (n >>> (32 - s)); }
    const utf8 = unescape(encodeURIComponent(msg));
    const ml = utf8.length;
    const words = [];
    for (let i = 0; i < ml; i++) words[i >> 2] = (words[i >> 2] || 0) | (utf8.charCodeAt(i) << (24 - (i % 4) * 8));
    words[ml >> 2] = (words[ml >> 2] || 0) | (0x80 << (24 - (ml % 4) * 8));
    words[(((ml + 8) >> 6) + 1) * 16 - 1] = ml * 8;
    let h0 = 0x67452301, h1 = 0xEFCDAB89, h2 = 0x98BADCFE, h3 = 0x10325476, h4 = 0xC3D2E1F0;
    const w = new Array(80);
    for (let b = 0; b < words.length; b += 16) {
      for (let t = 0; t < 16; t++) w[t] = words[b + t] | 0;
      for (let t = 16; t < 80; t++) w[t] = rotl(w[t - 3] ^ w[t - 8] ^ w[t - 14] ^ w[t - 16], 1);
      let a = h0, b2 = h1, c = h2, d = h3, e = h4;
      for (let t = 0; t < 80; t++) {
        const f = t < 20 ? ((b2 & c) | (~b2 & d)) : t < 40 ? (b2 ^ c ^ d) : t < 60 ? ((b2 & c) | (b2 & d) | (c & d)) : (b2 ^ c ^ d);
        const k = t < 20 ? 0x5A827999 : t < 40 ? 0x6ED9EBA1 : t < 60 ? 0x8F1BBCDC : 0xCA62C1D6;
        const tmp = (rotl(a, 5) + f + e + k + w[t]) | 0;
        e = d; d = c; c = rotl(b2, 30); b2 = a; a = tmp;
      }
      h0 = (h0 + a) | 0; h1 = (h1 + b2) | 0; h2 = (h2 + c) | 0; h3 = (h3 + d) | 0; h4 = (h4 + e) | 0;
    }
    return [h0, h1, h2, h3, h4].map(x => (x >>> 0).toString(16).padStart(8, '0')).join('');
  }

  /* Ordered manifest of all checks; app.js runs these sequentially. */
  function all(inputs) {
    return [
      { name: 'Public network identity', run: () => publicNetwork() },
      { name: 'WebRTC IP leak', run: () => webrtcLeak() },
      { name: 'DNS leak indicator', run: () => dnsIndicator() },
      { name: 'VPN / proxy heuristic', run: () => vpnHeuristic() },
      { name: 'Device fingerprint', run: () => deviceFingerprint() },
      { name: 'Canvas & GPU fingerprint', run: () => canvasWebgl() },
      { name: 'Audio fingerprint', run: () => audioFingerprint() },
      { name: 'Installed-font surface', run: () => fontEnumeration() },
      { name: 'Site permissions', run: () => permissionStates() },
      { name: 'Privacy signals', run: () => privacySignals() },
      { name: 'Email breach lookup', run: () => emailBreach(inputs.email) },
      { name: 'Password exposure', run: () => passwordExposure(inputs.password) },
      { name: 'Connection security', run: () => connectionSecurity(inputs.domain) }
    ];
  }

  return { all };
})();
