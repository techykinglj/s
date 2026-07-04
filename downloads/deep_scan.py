#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Privacy Sentinel — Mac Deep Scan
=================================
A read-only audit of what is running, auto-starting, and phoning home on THIS Mac.
- Python 3 standard library only. No installs, no network calls, nothing sent anywhere.
- Writes a self-contained report.html next to this script and opens it.
- Honest by design: anything it cannot see is marked "limited", never invented.

Run:  python3 deep_scan.py        (or double-click Privacy-Deep-Scan.command)
"""

import datetime
import glob
import html
import json
import os
import plistlib
import platform
import re
import subprocess
import sys

IS_MAC = (platform.system() == "Darwin")
HOME = os.path.expanduser("~")
CMD_TIMEOUT = 25  # seconds per external command; never hang the scan

CLEAR, ATTENTION, RISK, NA = "CLEAR", "ATTENTION", "RISK", "NA"

# ---------------------------------------------------------------------------
# Known-good signers: Apple platform code + widely-used developers.
# Purpose: DON'T scare users about legitimate software (mission §7).
# Matching is against `codesign` Authority lines / TeamIdentifier.
# ---------------------------------------------------------------------------
APPLE_AUTHORITIES = (
    "Software Signing",                       # Apple OS binaries
    "Apple Mac OS Application Signing",       # Mac App Store
    "Apple Code Signing Certification Authority",
    "Apple Root CA",
)
KNOWN_DEVELOPERS = (
    # substring of "Developer ID Application: <name> (<team>)"
    "Google", "Microsoft", "Adobe", "Dropbox", "Zoom Video Communications",
    "Mozilla", "Spotify", "Docker Inc", "Slack Technologies", "AgileBits",
    "1Password", "Valve", "Logitech", "Cisco", "Brave Software", "DuckDuckGo",
    "Signal Messenger", "WhatsApp", "Telegram", "Notion Labs", "Figma",
    "GitHub", "JetBrains", "Oracle", "VMware", "Parallels", "Backblaze",
    "Canon", "Epson", "HP Inc", "Sonos", "Elgato", "Rogue Amoeba",
    "Objective-See",  # security tools
)


def run(cmd, timeout=CMD_TIMEOUT):
    """Run a command; return (rc, stdout, stderr). Never raises, never hangs."""
    try:
        p = subprocess.run(
            cmd, capture_output=True, timeout=timeout,
            text=True, errors="replace"  # unicode-safe (edge case 11)
        )
        return p.returncode, p.stdout, p.stderr
    except FileNotFoundError:
        return 127, "", "command not found: %s" % cmd[0]
    except subprocess.TimeoutExpired:
        return 124, "", "timed out after %ss" % timeout
    except Exception as e:  # permission errors etc. — degrade, never crash
        return 1, "", "error: %s" % e


def which(binname):
    for p in os.environ.get("PATH", "/usr/bin:/bin:/usr/sbin:/sbin").split(":"):
        if p and os.access(os.path.join(p, binname), os.X_OK):
            return os.path.join(p, binname)
    for p in ("/usr/bin", "/bin", "/usr/sbin", "/sbin", "/usr/local/bin"):
        if os.access(os.path.join(p, binname), os.X_OK):
            return os.path.join(p, binname)
    return None


HAVE_CODESIGN = bool(which("codesign"))

# Cache signature verdicts per binary path — codesign is slow on a 2019 Air.
_sig_cache = {}


def signature_info(path):
    """Classify a binary: ('apple'|'known-dev'|'dev-id'|'adhoc'|'unsigned'|'unknown', authority_text)."""
    if not path or not os.path.exists(path):
        return "unknown", "file not found"
    if path in _sig_cache:
        return _sig_cache[path]
    if not HAVE_CODESIGN:
        verdict = ("unknown", "codesign unavailable — install Command Line Tools: xcode-select --install")
        _sig_cache[path] = verdict
        return verdict
    rc, out, err = run(["codesign", "-dv", "--verbose=4", path])
    text = out + err  # codesign writes to stderr
    if rc != 0 and "code object is not signed" in text:
        verdict = ("unsigned", "not signed at all")
    elif "Signature=adhoc" in text:
        verdict = ("adhoc", "ad-hoc signature (no identity)")
    else:
        auths = re.findall(r"Authority=(.+)", text)
        team = ""
        m = re.search(r"TeamIdentifier=(\S+)", text)
        if m and m.group(1) != "not set":
            team = m.group(1)
        joined = "; ".join(auths) if auths else text.strip()[:200]
        if any(a.startswith(ap) or ap in a for a in auths for ap in APPLE_AUTHORITIES):
            verdict = ("apple", joined)
        elif any(any(k.lower() in a.lower() for k in KNOWN_DEVELOPERS) for a in auths):
            verdict = ("known-dev", joined)
        elif any(a.startswith("Developer ID Application") for a in auths):
            verdict = ("dev-id", joined + (" [team %s]" % team if team else ""))
        elif rc == 0 and auths:
            verdict = ("dev-id", joined)
        elif rc != 0:
            verdict = ("unsigned", text.strip()[:200] or "unsigned")
        else:
            verdict = ("unknown", joined or "no authority information")
    _sig_cache[path] = verdict
    return verdict


def classify_persistence(sig_kind):
    """Persistence items (launch agents etc.): stricter — unsigned persistence is the #1 malware vector."""
    return {
        "apple": CLEAR, "known-dev": CLEAR,
        "dev-id": ATTENTION,           # validly signed but not a household name — worth a look
        "adhoc": RISK, "unsigned": RISK,
        "unknown": ATTENTION,
    }.get(sig_kind, ATTENTION)


def classify_process(sig_kind):
    """Mere running processes: gentler than persistence."""
    return {
        "apple": CLEAR, "known-dev": CLEAR,
        "dev-id": CLEAR,               # signed & notarizable third-party app actually running is normal
        "adhoc": ATTENTION, "unsigned": ATTENTION,
        "unknown": ATTENTION,
    }.get(sig_kind, ATTENTION)


def section(sid, title, status, summary, items, note=None):
    return {"id": sid, "title": title, "status": status, "summary": summary,
            "items": items, "note": note}


def item(name, status, detail):
    return {"name": name, "status": status, "detail": detail}


def worst(statuses):
    for s in (RISK, ATTENTION, CLEAR):
        if s in statuses:
            return s
    return NA


def limited(sid, title, why):
    return section(sid, title, NA, "Limited — " + why, [],
                   note="Nothing is shown here rather than showing invented data.")


# ---------------------------------------------------------------------------
# §MAC CHECKS
# ---------------------------------------------------------------------------

def plist_program(plist_path):
    """Extract the executable a launchd plist runs."""
    try:
        with open(plist_path, "rb") as f:
            data = plistlib.load(f)
    except Exception as e:
        return None, "unreadable plist (%s)" % e, None
    prog = data.get("Program")
    args = data.get("ProgramArguments")
    label = data.get("Label", os.path.basename(plist_path))
    exe = prog or (args[0] if isinstance(args, list) and args else None)
    return exe, None, label


def check_launch_items():
    dirs = [
        (os.path.join(HOME, "Library/LaunchAgents"), "user launch agent"),
        ("/Library/LaunchAgents", "system-wide launch agent"),
        ("/Library/LaunchDaemons", "system-wide launch daemon"),
    ]
    if not IS_MAC:
        return limited("launch", "Launch Agents & Daemons", "requires macOS (launchd folders not present on this OS).")
    items, statuses = [], []
    denied = False
    for d, kind in dirs:
        if not os.path.isdir(d):
            continue
        try:
            plists = sorted(glob.glob(os.path.join(d, "*.plist")))
        except PermissionError:
            denied = True
            continue
        for p in plists:
            exe, perr, label = plist_program(p)
            if perr:
                items.append(item(os.path.basename(p), ATTENTION, "%s — %s. Path: %s" % (kind, perr, p)))
                statuses.append(ATTENTION)
                continue
            if exe:
                kind_sig, auth = signature_info(exe)
                st = classify_persistence(kind_sig)
                detail = "%s · runs: %s · signature: %s (%s) · plist: %s" % (kind, exe, kind_sig, auth, p)
            else:
                st = ATTENTION
                detail = "%s · plist declares no Program/ProgramArguments · plist: %s" % (kind, p)
            items.append(item(label or os.path.basename(p), st, detail))
            statuses.append(st)
    apple_note = ("Apple's own agents in /System/Library are managed by macOS and intentionally not listed as findings. "
                  + ("Some folders were not readable — grant Full Disk Access (System Settings → Privacy & Security) for complete results." if denied else ""))
    if not items:
        return section("launch", "Launch Agents & Daemons", CLEAR,
                       "No third-party auto-start items found in the standard launchd folders.",
                       [], note=apple_note)
    risky = sum(1 for s in statuses if s == RISK)
    summary = ("%d auto-start item(s) found; %d unsigned/ad-hoc (the classic malware persistence vector)." % (len(items), risky)
               if risky else "%d auto-start item(s) found; signatures look accounted for." % len(items))
    return section("launch", "Launch Agents & Daemons", worst(statuses), summary, items, note=apple_note)


def check_login_items():
    if not IS_MAC:
        return limited("login", "Login Items", "requires macOS.")
    rc, out, err = run(["osascript", "-e",
                        'tell application "System Events" to get the name of every login item'])
    if rc != 0:
        why = ("macOS blocked the query — approve the Automation prompt (System Settings → Privacy & Security → Automation) and re-run. "
               "Raw error: %s" % (err.strip()[:160] or "unknown"))
        return limited("login", "Login Items", why)
    names = [n.strip() for n in out.strip().split(",") if n.strip()]
    if not names:
        return section("login", "Login Items", CLEAR, "No login items open automatically at sign-in.", [])
    items = [item(n, ATTENTION, "Opens automatically every time you log in. Remove unknowns in System Settings → General → Login Items.") for n in names]
    return section("login", "Login Items", ATTENTION,
                   "%d item(s) open automatically at login — confirm you recognise each." % len(names), items,
                   note="Modern macOS also runs 'background items' — see the Launch Agents section above for those.")


def check_processes():
    rc, out, err = run(["ps", "-axo", "pid,ppid,%cpu,%mem,user,comm"], timeout=30)
    if rc != 0:
        return limited("procs", "Running processes", "process listing failed: %s" % (err.strip()[:160]))
    lines = out.strip().splitlines()[1:]
    items, statuses = [], []
    nonapple = 0
    for ln in lines:
        parts = ln.split(None, 5)
        if len(parts) < 6:
            continue
        pid, ppid, cpu, mem, user, comm = parts
        # Apple system paths are trusted wholesale — do not alarm on OS internals (mission §7).
        if comm.startswith(("/System/", "/usr/libexec/", "/usr/sbin/", "/sbin/", "/usr/bin/", "/bin/")):
            continue
        nonapple += 1
        if IS_MAC and comm.startswith("/") and HAVE_CODESIGN:
            kind_sig, auth = signature_info(comm)
            st = classify_process(kind_sig)
            detail = "pid %s · user %s · cpu %s%% · mem %s%% · signature: %s (%s)" % (pid, user, cpu, mem, kind_sig, auth[:160])
        else:
            st = ATTENTION if not IS_MAC else ATTENTION
            detail = "pid %s · user %s · cpu %s%% · mem %s%% · signature: not verifiable %s" % (
                pid, user, cpu, mem, "(non-macOS environment)" if not IS_MAC else "(codesign unavailable or non-path command)")
        items.append(item(comm, st, detail))
        statuses.append(st)
        if len(items) >= 120:  # cap for report speed on a 2019 Air (edge case 10)
            items.append(item("…list capped at 120 non-system processes", NA, "Full count: %d candidate processes." % nonapple))
            break
    total = len(lines)
    if not items:
        return section("procs", "Running processes", CLEAR,
                       "%d processes running; all are standard OS binaries." % total, [])
    st = worst(statuses)
    if not IS_MAC:
        st = NA
    return section("procs", "Running processes", st,
                   "%d processes running; %d outside standard system paths (shown below)." % (total, nonapple),
                   items,
                   note=None if IS_MAC else "Signature verification requires macOS — statuses here are informational only.")


def _lsof_connections():
    if not which("lsof"):
        return None, "lsof not available"
    rc, out, err = run(["lsof", "-i", "-n", "-P"], timeout=40)
    if rc not in (0, 1):  # lsof returns 1 when some info was unavailable — output is still usable
        return None, err.strip()[:160] or ("lsof exit %d" % rc)
    return out, None


def check_network(out_cache={}):
    """Outbound connections — what's phoning home."""
    if "raw" not in out_cache:
        raw, err = _lsof_connections()
        out_cache["raw"] = raw
        out_cache["err"] = err
    raw = out_cache["raw"]
    if raw is None:
        return limited("net-out", "Outbound connections (phoning home)", out_cache["err"])
    items, statuses = [], []
    seen = set()
    for ln in raw.splitlines()[1:]:
        if "ESTABLISHED" not in ln:
            continue
        parts = ln.split()
        if len(parts) < 9:
            continue
        proc, pid, user = parts[0], parts[1], parts[2]
        conn = parts[8] if len(parts) > 8 else ""
        m = re.search(r"->([\[\]0-9a-fA-F\.:]+):(\d+)", ln)
        remote = ("%s:%s" % (m.group(1), m.group(2))) if m else conn
        key = (proc, remote)
        if key in seen:
            continue
        seen.add(key)
        st = CLEAR
        wellknown = ("Safari", "firefox", "Google", "Chrome", "com.apple", "trustd", "nsurlsessi",
                     "apsd", "cloudd", "rapportd", "identitys", "Mail", "Slack", "zoom", "Spotify",
                     "Dropbox", "node", "python", "ssh", "mDNSRespo", "netbiosd", "sharingd")
        if not any(w.lower() in proc.lower() for w in wellknown):
            st = ATTENTION
        items.append(item("%s → %s" % (proc, remote), st,
                          "pid %s · user %s · An app talking to the internet. Recognise it? If not, look it up before worrying — many system helpers have odd names." % (pid, user)))
        statuses.append(st)
        if len(items) >= 100:
            items.append(item("…list capped at 100 connections", NA, ""))
            break
    if not items:
        return section("net-out", "Outbound connections (phoning home)", CLEAR,
                       "No established outbound connections at scan time.", [])
    flagged = sum(1 for s in statuses if s == ATTENTION)
    return section("net-out", "Outbound connections (phoning home)", worst(statuses),
                   "%d active connection(s); %d from processes that aren't household names (worth a glance, not panic)." % (len(seen), flagged),
                   items)


def check_listeners():
    raw, err = _lsof_connections()
    if raw is None:
        return limited("net-in", "Listening ports", err)
    items, statuses = [], []
    seen = set()
    for ln in raw.splitlines()[1:]:
        if "LISTEN" not in ln:
            continue
        parts = ln.split()
        if len(parts) < 9:
            continue
        proc, pid, user = parts[0], parts[1], parts[2]
        m = re.search(r"([\[\]0-9a-fA-F\.\*:]+):(\d+|\*)\s+\(LISTEN\)", ln)
        addr = ("%s:%s" % (m.group(1), m.group(2))) if m else parts[8]
        key = (proc, addr)
        if key in seen:
            continue
        seen.add(key)
        localonly = addr.startswith(("127.0.0.1", "[::1]", "localhost"))
        st = CLEAR if localonly else ATTENTION
        items.append(item("%s listening on %s" % (proc, addr), st,
                          "pid %s · user %s · %s" % (pid, user,
                          "Bound to localhost only — not reachable from the network." if localonly
                          else "Accepts connections from the network. Expected for file sharing/AirDrop-type services; investigate anything you don't recognise.")))
        statuses.append(st)
        if len(items) >= 60:
            items.append(item("…list capped at 60 listeners", NA, ""))
            break
    if not items:
        return section("net-in", "Listening ports", CLEAR, "Nothing is accepting inbound connections.", [])
    return section("net-in", "Listening ports", worst(statuses),
                   "%d listener(s) found — localhost-only ones are harmless." % len(seen), items)


def check_profiles():
    if not IS_MAC:
        return limited("profiles", "Configuration profiles (MDM)", "requires macOS.")
    rc, out, err = run(["profiles", "list"])
    if rc != 0:
        rc, out, err = run(["profiles", "-P"])  # older syntax
    if rc != 0:
        return limited("profiles", "Configuration profiles (MDM)",
                       "the profiles tool needs elevated rights here (%s). Check manually: System Settings → General → Device Management." % (err.strip()[:120] or "no output"))
    text = out.strip()
    if not text or "There are no configuration profiles" in text or "no profiles" in text.lower():
        return section("profiles", "Configuration profiles (MDM)", CLEAR,
                       "No configuration profiles installed — no one manages or monitors this Mac via MDM.", [])
    lines = [l.strip() for l in text.splitlines() if l.strip() and not l.startswith("_")]
    items = [item(l, RISK, "A configuration profile can silently control network settings, certificates, and monitoring. On a personal Mac, remove any profile you did not knowingly install (System Settings → General → Device Management).") for l in lines[:40]]
    return section("profiles", "Configuration profiles (MDM)", RISK,
                   "Configuration profile(s) are installed on this Mac — verify each one.", items)


def check_extensions():
    if not IS_MAC:
        return limited("kext", "Kernel & system extensions", "requires macOS.")
    items, statuses = [], []
    rc, out, err = run(["kextstat", "-l"])
    if rc == 0:
        for ln in out.splitlines():
            if "com.apple." in ln:
                continue
            m = re.search(r"(\S+\.\S+)\s+\(", ln)
            name = m.group(1) if m else ln.strip()[:80]
            if not name:
                continue
            items.append(item(name, ATTENTION, "Third-party KERNEL extension — runs with the deepest possible access. Legitimate for some security/audio/VM tools; investigate if unfamiliar."))
            statuses.append(ATTENTION)
    kext_note = None if rc == 0 else "kextstat unavailable (%s)." % (err.strip()[:100] or "no output")
    rc2, out2, err2 = run(["systemextensionsctl", "list"])
    if rc2 == 0:
        for ln in out2.splitlines():
            if "activated" not in ln and "enabled" not in ln:
                continue
            if "com.apple." in ln:
                continue
            items.append(item(ln.strip()[:110], ATTENTION, "Third-party SYSTEM extension (network filter, endpoint monitor, driver). VPNs and security tools live here — so does commercial spyware. Recognise it?"))
            statuses.append(ATTENTION)
    if not items:
        return section("kext", "Kernel & system extensions", CLEAR,
                       "No third-party kernel or system extensions detected.", [], note=kext_note)
    return section("kext", "Kernel & system extensions", worst(statuses),
                   "%d third-party extension(s) loaded — confirm each is something you installed." % len(items),
                   items, note=kext_note)


def check_cron():
    items, statuses = [], []
    rc, out, err = run(["crontab", "-l"])
    if rc == 0 and out.strip():
        for ln in out.splitlines():
            ln = ln.strip()
            if ln and not ln.startswith("#"):
                items.append(item("cron: " + ln[:100], ATTENTION,
                                  "A scheduled command for your user. Fine if you set it up; a red flag if you've never used cron."))
                statuses.append(ATTENTION)
    at_dirs = ["/etc/periodic/daily", "/etc/periodic/weekly", "/etc/periodic/monthly"]
    for d in at_dirs:
        if os.path.isdir(d):
            try:
                for f in sorted(os.listdir(d)):
                    p = os.path.join(d, f)
                    # stock macOS periodic scripts are Apple's; only note non-standard additions
                    if not f[0].isdigit():
                        items.append(item("periodic: " + p, ATTENTION, "Non-standard periodic script — stock entries are numbered (e.g. 110.clean-tmps)."))
                        statuses.append(ATTENTION)
            except PermissionError:
                pass
    if not items:
        return section("cron", "Cron & scheduled jobs", CLEAR,
                       "No user cron jobs or non-standard periodic scripts.", [],
                       note="launchd timers are covered in the Launch Agents section.")
    return section("cron", "Cron & scheduled jobs", worst(statuses),
                   "%d scheduled job(s) found outside the OS defaults." % len(items), items)


def check_browser_extensions():
    found, statuses = [], []
    profiles_globs = [
        ("Chrome", os.path.join(HOME, "Library/Application Support/Google/Chrome/*/Extensions/*/*/manifest.json")),
        ("Edge", os.path.join(HOME, "Library/Application Support/Microsoft Edge/*/Extensions/*/*/manifest.json")),
        ("Brave", os.path.join(HOME, "Library/Application Support/BraveSoftware/Brave-Browser/*/Extensions/*/*/manifest.json")),
        ("Firefox", os.path.join(HOME, "Library/Application Support/Firefox/Profiles/*/extensions/*.xpi")),
        ("Firefox", os.path.join(HOME, ".mozilla/firefox/*/extensions/*.xpi")),  # linux test path
        ("Chrome", os.path.join(HOME, ".config/google-chrome/*/Extensions/*/*/manifest.json")),  # linux test path
    ]
    denied = False
    for browser, pat in profiles_globs:
        try:
            for mf in glob.glob(pat):
                if mf.endswith(".xpi"):
                    name = os.path.basename(mf)
                    detail = "Firefox add-on file: %s" % mf
                else:
                    try:
                        with open(mf, "r", encoding="utf-8", errors="replace") as f:
                            data = json.load(f)
                        name = data.get("name", "?")
                        if name.startswith("__MSG_"):
                            name = os.path.basename(os.path.dirname(os.path.dirname(mf)))  # extension ID
                        detail = "version %s · id %s" % (data.get("version", "?"),
                                                          os.path.basename(os.path.dirname(os.path.dirname(mf))))
                    except Exception:
                        continue
                found.append(item("%s: %s" % (browser, name), ATTENTION,
                                  detail + " · Extensions can read every page you visit. Remove any you don't actively use."))
                statuses.append(ATTENTION)
        except PermissionError:
            denied = True
    # Safari extensions are app-bundled; listing needs Full Disk Access to Containers
    safari_note = "Safari extensions: check Safari → Settings → Extensions (their files live inside app sandboxes not readable here)."
    if denied:
        safari_note += " Some browser folders were unreadable — grant Full Disk Access for complete results."
    if not found:
        return section("browser-ext", "Browser extensions", CLEAR,
                       "No Chrome/Brave/Edge/Firefox extensions found in standard profile folders.", [],
                       note=safari_note)
    return section("browser-ext", "Browser extensions", ATTENTION,
                   "%d browser extension(s) installed — each can see what you browse; keep only what you use." % len(found),
                   found[:80], note=safari_note)


def check_dns_hosts():
    items, statuses = [], []
    # /etc/hosts tampering
    try:
        with open("/etc/hosts", "r", encoding="utf-8", errors="replace") as f:
            lines = f.readlines()
        std = {"localhost", "broadcasthost", "localhost.localdomain", "ip6-localhost", "ip6-loopback",
               "ip6-localnet", "ip6-mcastprefix", "ip6-allnodes", "ip6-allrouters", "ip6-allhosts"}
        extra = []
        for ln in lines:
            s = ln.strip()
            if not s or s.startswith("#"):
                continue
            parts = s.split()
            hosts = [h for h in parts[1:] if h not in std]
            if hosts:
                extra.append(s)
        if extra:
            for e in extra[:30]:
                items.append(item("hosts: " + e[:100], ATTENTION,
                                  "A manual redirect in /etc/hosts. Ad-blocking entries are fine; entries redirecting banks or login pages are a classic attack."))
                statuses.append(ATTENTION)
        else:
            items.append(item("/etc/hosts", CLEAR, "Only the standard localhost entries — no tampering."))
            statuses.append(CLEAR)
    except Exception as e:
        items.append(item("/etc/hosts", NA, "unreadable: %s" % e))
    # DNS servers
    if IS_MAC:
        rc, out, err = run(["scutil", "--dns"])
        if rc == 0:
            servers = sorted(set(re.findall(r"nameserver\[\d+\]\s*:\s*(\S+)", out)))
            wellknown_dns = {"1.1.1.1", "1.0.0.1", "8.8.8.8", "8.8.4.4", "9.9.9.9", "149.112.112.112",
                             "208.67.222.222", "208.67.220.220"}
            private = [s for s in servers if re.match(r"^(10\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.|fe80|fd)", s)]
            odd = [s for s in servers if s not in wellknown_dns and s not in private]
            det = "Servers in use: %s" % (", ".join(servers) or "none reported")
            if odd:
                items.append(item("DNS servers", ATTENTION, det + " · Unrecognised public resolver(s): %s — fine if you (or your VPN) chose them; suspicious if they appeared on their own." % ", ".join(odd)))
                statuses.append(ATTENTION)
            else:
                items.append(item("DNS servers", CLEAR, det + " · Router-provided or well-known resolvers."))
                statuses.append(CLEAR)
        else:
            items.append(item("DNS servers", NA, "scutil unavailable: %s" % (err.strip()[:100] or "no output")))
    else:
        items.append(item("DNS servers", NA, "scutil requires macOS — skipped on this OS."))
    st = worst([s for s in statuses]) if statuses else NA
    return section("dns", "DNS & hosts-file tampering", st,
                   "Checked /etc/hosts and the DNS resolvers your Mac actually uses." if IS_MAC
                   else "Checked /etc/hosts; resolver check requires macOS.",
                   items)


def check_gatekeeper():
    if not IS_MAC:
        return limited("gatekeeper", "Gatekeeper & signature summary", "requires macOS.")
    items = []
    rc, out, err = run(["spctl", "--status"])
    text = (out + err).strip()
    if "enabled" in text:
        items.append(item("Gatekeeper", CLEAR, "Assessments enabled — macOS blocks unidentified apps by default."))
        gk = CLEAR
    elif "disabled" in text:
        items.append(item("Gatekeeper", RISK, "Assessments DISABLED — any unsigned app can run silently. Re-enable: sudo spctl --master-enable"))
        gk = RISK
    else:
        items.append(item("Gatekeeper", NA, "spctl gave no verdict: %s" % (text[:100] or "no output")))
        gk = NA
    unsigned = sum(1 for v in _sig_cache.values() if v[0] in ("unsigned", "adhoc"))
    checked = len(_sig_cache)
    if checked:
        st = ATTENTION if unsigned else CLEAR
        items.append(item("Unsigned binaries encountered this scan", st,
                          "%d of %d binaries checked had no valid signature (details in their own sections)." % (unsigned, checked)))
    if not HAVE_CODESIGN:
        items.append(item("codesign tool", NA,
                          "Not installed — run: xcode-select --install  (enables signature verification for a complete scan)."))
    return section("gatekeeper", "Gatekeeper & signature summary",
                   worst([i["status"] for i in items if i["status"] != NA]) if any(i["status"] != NA for i in items) else NA,
                   "System-wide code-signing posture.", items)


# ---------------------------------------------------------------------------
# Report (self-contained HTML, inline CSS/JS, no external calls)
# ---------------------------------------------------------------------------

REPORT_CSS = """
:root{--accent:#0f4c5c;--ink:#1c2733;--soft:#5a6a7a;--bg:#fafbfc;--card:#fff;--line:#e3e8ee;
--clear:#1e8e5a;--clear-bg:#e7f6ee;--att:#b26a00;--att-bg:#fdf3e1;--risk:#c0392b;--risk-bg:#fdebe9;--na:#7a8794;--na-bg:#eef1f4}
*{box-sizing:border-box}body{margin:0;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,Helvetica,Arial,sans-serif;
font-size:16px;line-height:1.5;color:var(--ink);background:var(--bg)}
.wrap{max-width:860px;margin:0 auto;padding:32px 20px 60px}
h1{font-size:1.7rem;margin:0 0 4px;letter-spacing:-.02em}.sub{color:var(--soft);margin:0 0 24px}
details.sec{background:var(--card);border:1px solid var(--line);border-radius:14px;margin:10px 0;overflow:hidden}
details.sec>summary{list-style:none;cursor:pointer;display:flex;align-items:center;gap:12px;padding:15px 16px}
details.sec>summary::-webkit-details-marker{display:none}
.badge{font-size:.7rem;font-weight:700;letter-spacing:.04em;padding:4px 9px;border-radius:999px;white-space:nowrap}
.badge.CLEAR{color:var(--clear);background:var(--clear-bg)}.badge.ATTENTION{color:var(--att);background:var(--att-bg)}
.badge.RISK{color:var(--risk);background:var(--risk-bg)}.badge.NA{color:var(--na);background:var(--na-bg)}
.t{flex:1}.t b{display:block}.t span{display:block;font-size:.85rem;color:var(--soft);margin-top:2px}
.body{border-top:1px solid var(--line);padding:6px 16px 14px;background:var(--bg);max-height:480px;overflow:auto}
.it{padding:10px 0;border-bottom:1px solid var(--line);font-size:.88rem}.it:last-child{border-bottom:none}
.it .n{font-weight:600;overflow-wrap:anywhere}.it .d{color:var(--soft);margin-top:2px;overflow-wrap:anywhere}
.note{font-size:.82rem;color:var(--soft);padding:10px 0 0;font-style:italic}
.scope{background:var(--card);border:1px solid var(--line);border-radius:14px;padding:16px;margin:22px 0;color:var(--soft);font-size:.92rem}
.foot{text-align:center;color:var(--na);font-size:.8rem;margin-top:28px}
@media(prefers-color-scheme:dark){:root{--ink:#e8edf2;--soft:#9fb0c0;--bg:#10161c;--card:#1a232c;--line:#2a3540;
--clear-bg:#12352a;--att-bg:#3a2c10;--risk-bg:#3a1d19;--na-bg:#242d36}}
"""


def build_report(sections, started, finished):
    def esc(s):
        return html.escape(str(s if s is not None else ""))
    counts = {CLEAR: 0, ATTENTION: 0, RISK: 0, NA: 0}
    for s in sections:
        counts[s["status"] if s["status"] in counts else NA] += 1
    badge_txt = {CLEAR: "CLEAR", ATTENTION: "ATTENTION", RISK: "RISK", NA: "LIMITED"}
    parts = []
    parts.append("<!DOCTYPE html><html lang='en'><head><meta charset='utf-8'>")
    parts.append("<meta name='viewport' content='width=device-width,initial-scale=1'>")
    parts.append("<title>Mac Deep Scan — Privacy Sentinel</title><style>%s</style></head><body><div class='wrap'>" % REPORT_CSS)
    parts.append("<h1>Mac Deep Scan</h1>")
    host = esc(platform.node() or "this Mac")
    parts.append("<p class='sub'>%s · scanned %s · took %.1fs · read-only, nothing left this machine.<br>"
                 "%d clear · %d worth attention · %d risk · %d limited — click any section for details.</p>"
                 % (host, started.strftime("%Y-%m-%d %H:%M"), (finished - started).total_seconds(),
                    counts[CLEAR], counts[ATTENTION], counts[RISK], counts[NA]))
    order = {RISK: 0, ATTENTION: 1, NA: 2, CLEAR: 3}
    for s in sorted(sections, key=lambda x: order.get(x["status"], 2)):
        parts.append("<details class='sec'%s><summary>" % (" open" if s["status"] == RISK else ""))
        parts.append("<span class='badge %s'>%s</span>" % (s["status"], badge_txt.get(s["status"], "LIMITED")))
        parts.append("<span class='t'><b>%s</b><span>%s</span></span></summary><div class='body'>" % (esc(s["title"]), esc(s["summary"])))
        if not s["items"]:
            parts.append("<div class='it'><div class='d'>No individual findings for this section.</div></div>")
        for it in s["items"]:
            parts.append("<div class='it'><span class='badge %s'>%s</span> <span class='n'>%s</span><div class='d'>%s</div></div>"
                         % (it["status"], badge_txt.get(it["status"], "·"), esc(it["name"]), esc(it["detail"])))
        if s.get("note"):
            parts.append("<div class='note'>%s</div>" % esc(s["note"]))
        parts.append("</div></details>")
    parts.append("<div class='scope'><b>Scope, honestly:</b> this scan reads auto-start items, running processes, "
                 "network activity, profiles, extensions, scheduled jobs, and DNS settings on this Mac only. "
                 "It changes nothing, sends nothing anywhere, and marks anything it couldn't read as LIMITED "
                 "instead of guessing. Items signed by Apple or well-known developers are classified CLEAR on purpose — "
                 "the goal is to surface the unexplained, not to alarm you about normal software.</div>")
    parts.append("<p class='foot'>Privacy Sentinel · Mac Deep Scan · this report is a local file on your Mac.</p>")
    parts.append("</div></body></html>")
    return "".join(parts)


def main():
    started = datetime.datetime.now()
    print("Privacy Sentinel — Mac Deep Scan")
    print("Read-only audit; nothing is sent anywhere. This takes about a minute…\n")
    if not IS_MAC:
        print("NOTE: not running on macOS — macOS-only sections will be marked limited.\n")
    steps = [
        ("Launch agents & daemons", check_launch_items),
        ("Login items", check_login_items),
        ("Running processes", check_processes),
        ("Outbound connections", check_network),
        ("Listening ports", check_listeners),
        ("Configuration profiles (MDM)", check_profiles),
        ("Kernel & system extensions", check_extensions),
        ("Cron & scheduled jobs", check_cron),
        ("Browser extensions", check_browser_extensions),
        ("DNS & hosts tampering", check_dns_hosts),
        ("Gatekeeper & signatures", check_gatekeeper),
    ]
    sections = []
    for i, (name, fn) in enumerate(steps, 1):
        print("  [%2d/%d] %s…" % (i, len(steps), name), flush=True)
        try:
            sections.append(fn())
        except Exception as e:  # any single check failing must not kill the scan
            sections.append(limited(name.lower().replace(" ", "-"), name, "check crashed safely: %s" % e))
    finished = datetime.datetime.now()
    out_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "report.html")
    with open(out_path, "w", encoding="utf-8") as f:
        f.write(build_report(sections, started, finished))
    print("\nReport written: %s" % out_path)
    if IS_MAC:
        run(["open", out_path])
        print("Opening in your browser…")
    else:
        print("(Not macOS — open the file manually.)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
