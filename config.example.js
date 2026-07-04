/* Optional configuration — copy to config.js (gitignored) to enable extras.
 * Without this file the app works fully; only the email-breach check stays off. */

/* Have I Been Pwned API key (haveibeenpwned.com/API/Key) enables breach-by-email lookup.
 * NOTE: HIBP does not allow direct browser calls for most origins; prefer a serverless
 * proxy at /api/breach (see README). Never commit a real key. */
// window.HIBP_KEY = 'your-key-here';
