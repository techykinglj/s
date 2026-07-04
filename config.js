/* Privacy Sentinel — optional configuration (safe to leave as-is).
 *
 * ── Email breach lookups (Have I Been Pwned) ──────────────────────────────
 * The password check works without any key. Breach-lookup BY EMAIL needs one:
 *   1) get a key at haveibeenpwned.com/API/Key
 *   2) uncomment ONE of the lines below
 *
 * ⚠ If you put a real key here, keep it out of git:
 *      git update-index --assume-unchanged web/config.js
 *   Better: deploy a serverless proxy at /api/breach (see README) and set
 *   BREACH_PROXY instead — the key then never touches the browser at all.
 */

// window.HIBP_KEY = 'your-key-here';   // direct mode (HIBP may block browser calls)
// window.BREACH_PROXY = true;          // use your deployed /api/breach proxy
