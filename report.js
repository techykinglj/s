/* Privacy Sentinel — report rendering: summary cards + expandable details. */
'use strict';

const Report = (() => {

  const BADGE_TEXT = { CLEAR: 'CLEAR', ATTENTION: 'ATTENTION', RISK: 'RISK', NA: 'N/A' };

  /* Plain-English next step per check, shown when it needs acting on.
     Written for a non-technical reader: what to do, not how it works. */
  const ACTIONS = {
    'public-network': 'Sites can see where you are. A reputable VPN (or iCloud Private Relay on Apple devices) hides your location and network from every site you visit.',
    'webrtc': 'Your browser is leaking a network address even a VPN can\'t hide. Use your VPN\'s browser extension, or switch to a browser that masks WebRTC (Safari or Brave).',
    'dns': 'Your traffic may be taking two different routes. Run your VPN provider\'s own leak test to be sure.',
    'vpn': 'You\'re browsing without a VPN. Not an emergency — but on public Wi-Fi, or if you want sites not to know your location, turn one on.',
    'device-fp': 'Your browser hands over a lot of identifying details. Browsing in Safari or Brave (instead of Chrome) cuts down how trackable you are.',
    'canvas-webgl': 'Sites can recognise this exact device even without cookies. Safari and Brave blunt this automatically; Firefox can too (strict mode).',
    'audio-fp': 'Another cookie-less way sites can recognise you. The same fix as above applies — a privacy-focused browser blunts it.',
    'fonts': 'Nothing to do by itself — this simply adds to your fingerprint. A privacy browser reduces it.',
    'permissions': 'A permission is already switched on for this site. Check your browser\'s site settings and turn off anything you don\'t remember allowing.',
    'privacy-signals': 'Your browser isn\'t telling sites "don\'t sell my data." Brave and Firefox send this signal out of the box; extensions add it to Safari and Chrome.',
    'email-breach': 'Your email appeared in a data breach. Change that password everywhere you used it, and turn on two-step login for your important accounts.',
    'password': 'Stop using this password today — criminals literally have lists with it. Use your phone\'s built-in password manager to replace it, and turn on two-step login.',
    'connection': 'This page isn\'t encrypted. Never type passwords or card numbers on a page without the padlock.'
  };

  const VERDICT = {
    RISK: 'Your audit found something that needs fixing now.',
    ATTENTION: 'Nothing urgent — but a few easy changes would make you noticeably harder to track.',
    CLEAR: 'Looking good. Nothing urgent turned up in what this audit can see.'
  };

  function el(tag, cls, text) {
    const n = document.createElement(tag);
    if (cls) n.className = cls;
    if (text !== undefined) n.textContent = text;
    return n;
  }

  function renderCard(r) {
    const card = el('details', 'card');
    const sum = el('summary');
    const badge = el('span', 'badge ' + (BADGE_TEXT[r.status] ? r.status : 'NA'), BADGE_TEXT[r.status] || 'N/A');
    const title = el('span', 'card-title');
    title.appendChild(el('span', 'label', r.label));
    title.appendChild(el('span', 'headline', r.headline));
    const chev = el('span', 'chev', '›');
    sum.appendChild(badge); sum.appendChild(title); sum.appendChild(chev);
    card.appendChild(sum);

    const body = el('div', 'card-details');
    if ((r.status === 'RISK' || r.status === 'ATTENTION') && ACTIONS[r.id]) {
      body.appendChild(el('p', 'card-action', 'What to do: ' + ACTIONS[r.id]));
    }
    const keys = Object.keys(r.details || {});
    if (!keys.length) {
      body.appendChild(el('p', null, 'No further data for this check.'));
    } else {
      const dl = el('dl');
      for (const k of keys) {
        dl.appendChild(el('dt', null, k));
        dl.appendChild(el('dd', null, String(r.details[k])));
      }
      body.appendChild(dl);
    }
    card.appendChild(body);
    return card;
  }

  /* Overall verdict + top actions: the part a non-technical reader actually uses. */
  function renderVerdict(results) {
    const box = el('div', 'verdict');
    const worst = results.some(r => r.status === 'RISK') ? 'RISK'
                : results.some(r => r.status === 'ATTENTION') ? 'ATTENTION' : 'CLEAR';
    box.classList.add('verdict-' + worst);
    box.appendChild(el('p', 'verdict-line', VERDICT[worst]));
    // Top 3 actions, risks first, in check order within each severity.
    const actionable = results.filter(r => (r.status === 'RISK' || r.status === 'ATTENTION') && ACTIONS[r.id]);
    actionable.sort((a, b) => (a.status === b.status) ? 0 : (a.status === 'RISK' ? -1 : 1));
    const top = actionable.slice(0, 3);
    if (top.length) {
      box.appendChild(el('p', 'verdict-do', top.length > 1 ? 'Do these first:' : 'Do this first:'));
      const ul = el('ul', 'verdict-actions');
      for (const r of top) {
        const li = el('li');
        li.appendChild(el('strong', null, r.label + ' — '));
        li.appendChild(document.createTextNode(ACTIONS[r.id]));
        ul.appendChild(li);
      }
      box.appendChild(ul);
    }
    return box;
  }

  function render(results, mount, summaryMount) {
    mount.textContent = '';
    const counts = { CLEAR: 0, ATTENTION: 0, RISK: 0, NA: 0 };
    for (const r of results) counts[counts.hasOwnProperty(r.status) ? r.status : 'NA']++;
    mount.appendChild(renderVerdict(results));
    for (const r of results) mount.appendChild(renderCard(r));
    if (summaryMount) {
      const bits = [];
      if (counts.RISK) bits.push(counts.RISK + ' need fixing');
      if (counts.ATTENTION) bits.push(counts.ATTENTION + ' worth a look');
      if (counts.CLEAR) bits.push(counts.CLEAR + ' fine as-is');
      if (counts.NA) bits.push(counts.NA + ' couldn\'t run here');
      summaryMount.textContent = results.length + ' checks ran — ' + bits.join(', ') + '. Tap any card to see the evidence.';
    }
  }

  return { render };
})();
