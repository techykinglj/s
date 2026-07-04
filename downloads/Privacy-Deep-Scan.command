#!/bin/bash
# Privacy Sentinel — Mac Deep Scan launcher.
# Double-click me. First time: right-click → Open → Open (macOS gatekeeps downloads).
cd "$(dirname "$0")"

# If deep_scan.py isn't beside this launcher (e.g. only the .command was downloaded),
# fetch nothing — instead tell the user exactly what to do. No silent network calls.
if [ ! -f "deep_scan.py" ]; then
  echo "deep_scan.py was not found next to this launcher."
  echo "Download it from the same page (link under the Download button)"
  echo "and put both files in the same folder, then run me again."
  read -n 1 -s -r -p "Press any key to close…"
  exit 1
fi

echo "Privacy Sentinel — starting the Mac Deep Scan…"
/usr/bin/python3 deep_scan.py || python3 deep_scan.py
status=$?
echo
if [ $status -eq 0 ]; then
  echo "Done — the report opened in your browser (report.html, saved next to this file)."
else
  echo "The scan hit a problem (exit $status). If macOS asked to install"
  echo "'command line developer tools', click Install and run me again."
fi
read -n 1 -s -r -p "Press any key to close…"
echo
