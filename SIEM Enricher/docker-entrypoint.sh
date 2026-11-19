#!/bin/sh
# Entrypoint for the siem-enricher image.
#   (no args) | menu      interactive menu
#   demo                  analyze a sample SIEM log with simulated intel (no API key needed)
#   live-demo             watch a live simulated SIEM feed (Ctrl+C to stop)
#   test                  run the test suite (extra args go to pytest)
#   shell                 open a shell in the container
#   help                  show this help and the script's options
#   anything else         passed straight to siem_enricher.py, e.g.
#                         docker run ... siem-enricher /data/my.log --auto-contain malicious
set -e

APP=/app/siem_enricher.py
cmd="${1:-menu}"
[ $# -gt 0 ] && shift

check_data_writable() {
    if [ ! -w /data ]; then
        echo "ERROR: /data is not writable by this container (uid $(id -u))." >&2
        echo "On Linux, run with your own user id:  docker run --user \$(id -u):\$(id -g) ..." >&2
        echo "or make the folder writable:          chmod a+rwx ./data" >&2
        exit 1
    fi
}

case "$cmd" in
    menu)
        check_data_writable
        exec python "$APP" "$@"
        ;;
    demo)
        check_data_writable
        [ -f /data/sample_siem.log ] || cp /app/sample_siem.log /data/sample_siem.log
        echo "Demo: analyzing /data/sample_siem.log with simulated (mock) threat intel."
        exec python "$APP" /data/sample_siem.log --mock "$@"
        ;;
    live-demo)
        check_data_writable
        echo "Live demo: a simulated SIEM feed is written to /data/live_feed.log. Press Ctrl+C to stop."
        exec python "$APP" /data/live_feed.log --follow --simulate --mock "$@"
        ;;
    test|tests)
        cd /tmp
        exec python -m pytest -p no:cacheprovider -v /app/test_siem_enricher.py "$@"
        ;;
    shell|sh|bash)
        exec /bin/sh "$@"
        ;;
    help|-h|--help)
        sed -n '2,10p' "$0" | sed 's/^# \{0,1\}//'
        echo
        exec python "$APP" --help
        ;;
    *)
        check_data_writable
        exec python "$APP" "$cmd" "$@"
        ;;
esac
