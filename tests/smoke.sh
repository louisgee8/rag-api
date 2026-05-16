#!/usr/bin/env bash
#
# tests/smoke.sh — End-to-end smoke test for rag-api (Phase 1 + Phase 2 Steps 1-2).
#
# Coverage:
#   Phase 1 baseline:
#     1. /health public, version reflects new code
#     2. Protected route without auth        → 401
#     3. Protected route with empty Bearer   → 401
#     4. Protected route with bogus key      → 401
#     5. /ingest with valid key              → 200
#     6. /query/retrieve top result correct  → 200
#     7. (optional) /query/answer real call  → 200
#   Phase 2 Step 1 additions:
#     8. Revoke key via CLI                  → CLI exit 0
#     9. /ingest with revoked key            → 401
#   Phase 2 Step 2 additions:
#    10. Burst N+1 reqs vs RATE_LIMIT        → exactly N×200 + 1×429
#    11. 429 response carries Retry-After    → header > 0
#
# Usage:
#   ./tests/smoke.sh                          # default: skip Anthropic call
#   SMOKE_TEST_ANTHROPIC=1 ./tests/smoke.sh   # also exercise /query/answer
#   API_URL=http://other:9000 ./tests/smoke.sh
#
# Exit codes:
#   0 = all assertions passed
#   1 = at least one assertion failed (or stack not reachable)
#
# Requires: bash, curl, python3 (stdlib only), docker compose CLI
# Re-run safe: each run mints a fresh per-tenant key and revokes it at the
# end. The smoke-test tenant accumulates revoked rows over time, which is
# the correct audit-trail behavior.

set -u

API_URL="${API_URL:-http://localhost:8000}"
SMOKE_SOURCE="smoke-test-fixture"
SMOKE_TENANT="smoke-test"

# Color codes (graceful fallback if not a TTY)
if [[ -t 1 ]]; then
    RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; NC='\033[0m'
else
    RED=''; GREEN=''; YELLOW=''; NC=''
fi

PASS=0
FAIL=0

pass() { printf "%b\n" "${GREEN}PASS${NC} $*"; PASS=$((PASS + 1)); }
fail() { printf "%b\n" "${RED}FAIL${NC} $*"; FAIL=$((FAIL + 1)); }
skip() { printf "%b\n" "${YELLOW}SKIP${NC} $*"; }

# ----------------------------------------------------------------------------
# Setup: mint a fresh API key via the admin CLI.
#
# `docker compose exec -T` disables pseudo-TTY so the banner output is
# clean ASCII parseable by grep/awk. Without -T, control chars sneak in.
# ----------------------------------------------------------------------------
echo "rag-api Phase 2 smoke test"
echo "  API URL:  $API_URL"
echo "  Tenant:   $SMOKE_TENANT"
echo "----------------------------------------"
echo "Minting fresh key via scripts/issue_key.py ..."

ISSUE_OUTPUT=$(docker compose exec -T api python -m scripts.issue_key --tenant "$SMOKE_TENANT" 2>&1)
if [[ $? -ne 0 ]]; then
    fail "Could not mint key. Is the api container running?"
    echo "$ISSUE_OUTPUT"
    exit 1
fi

# Parse "  token      : rk_..." and "  key_prefix : rk_..." out of the banner.
TOKEN=$(echo "$ISSUE_OUTPUT" | grep -E '^[[:space:]]*token[[:space:]]*:' | awk -F': ' '{print $2}' | tr -d '[:space:]')
KEY_PREFIX=$(echo "$ISSUE_OUTPUT" | grep -E '^[[:space:]]*key_prefix[[:space:]]*:' | awk -F': ' '{print $2}' | tr -d '[:space:]')

if [[ -z "$TOKEN" || -z "$KEY_PREFIX" ]]; then
    fail "Could not parse token/key_prefix from issue_key output:"
    echo "$ISSUE_OUTPUT"
    exit 1
fi
echo "  Minted key_prefix=$KEY_PREFIX (token captured, not echoed)"
echo "----------------------------------------"

# ----------------------------------------------------------------------------
# Test 1: /health is public, no auth needed. Version surfaces in payload.
# ----------------------------------------------------------------------------
HTTP=$(curl -s -o /tmp/smoke_health.json -w "%{http_code}" "$API_URL/health")
if [[ "$HTTP" == "200" ]] && grep -q '"status":"ok"' /tmp/smoke_health.json; then
    VERSION=$(python3 -c "import json; print(json.load(open('/tmp/smoke_health.json'))['version'])")
    pass "GET /health (no auth) → 200, version=$VERSION"
else
    fail "GET /health expected 200 ok, got $HTTP: $(cat /tmp/smoke_health.json)"
fi

# ----------------------------------------------------------------------------
# Test 2: Protected route without auth → 401
# ----------------------------------------------------------------------------
HTTP=$(curl -s -o /dev/null -w "%{http_code}" \
    -X POST "$API_URL/query/retrieve" \
    -H "Content-Type: application/json" \
    -d '{"question":"test"}')
if [[ "$HTTP" == "401" ]]; then
    pass "POST /query/retrieve (no auth) → 401"
else
    fail "POST /query/retrieve no-auth expected 401, got $HTTP"
fi

# ----------------------------------------------------------------------------
# Test 3: Empty Bearer token → 401
# ----------------------------------------------------------------------------
HTTP=$(curl -s -o /dev/null -w "%{http_code}" \
    -X POST "$API_URL/query/retrieve" \
    -H "Content-Type: application/json" \
    -H "Authorization: Bearer " \
    -d '{"question":"test"}')
if [[ "$HTTP" == "401" ]]; then
    pass "POST /query/retrieve (Bearer with empty token) → 401"
else
    fail "POST /query/retrieve Bearer-empty expected 401, got $HTTP"
fi

# ----------------------------------------------------------------------------
# Test 4: Bogus key → 401 (cannot exist in api_keys table)
# ----------------------------------------------------------------------------
HTTP=$(curl -s -o /dev/null -w "%{http_code}" \
    -X POST "$API_URL/query/retrieve" \
    -H "Content-Type: application/json" \
    -H "Authorization: Bearer rk_definitely_not_a_real_key" \
    -d '{"question":"test"}')
if [[ "$HTTP" == "401" ]]; then
    pass "POST /query/retrieve (bogus key) → 401"
else
    fail "POST /query/retrieve bogus-key expected 401, got $HTTP"
fi

# ----------------------------------------------------------------------------
# Test 5: /ingest with the minted key → 200
# ----------------------------------------------------------------------------
SMOKE_TEXT="The Apollo 11 mission landed on the Moon on July 20, 1969. Neil Armstrong was the first human to walk on the lunar surface, followed by Buzz Aldrin. Michael Collins remained in lunar orbit aboard the command module Columbia."

HTTP=$(curl -s -o /tmp/smoke_ingest.json -w "%{http_code}" \
    -X POST "$API_URL/ingest" \
    -H "Content-Type: application/json" \
    -H "Authorization: Bearer $TOKEN" \
    -d "{\"source\":\"$SMOKE_SOURCE\",\"text\":\"$SMOKE_TEXT\"}")
if [[ "$HTTP" == "200" ]]; then
    CHUNKS=$(python3 -c "import json; print(json.load(open('/tmp/smoke_ingest.json'))['chunks_created'])")
    pass "POST /ingest (valid key, tenant=$SMOKE_TENANT) → 200, chunks_created=$CHUNKS"
else
    fail "POST /ingest expected 200, got $HTTP: $(cat /tmp/smoke_ingest.json)"
    echo "Cannot continue — /ingest must succeed for retrieval test."
    echo "Results: $PASS passed, $FAIL failed"
    exit 1
fi

# ----------------------------------------------------------------------------
# Test 6: /query/retrieve — top result must be our fixture
# ----------------------------------------------------------------------------
HTTP=$(curl -s -o /tmp/smoke_query.json -w "%{http_code}" \
    -X POST "$API_URL/query/retrieve" \
    -H "Content-Type: application/json" \
    -H "Authorization: Bearer $TOKEN" \
    -d '{"question":"Who was the first person to walk on the Moon?","top_k":3}')
if [[ "$HTTP" != "200" ]]; then
    fail "POST /query/retrieve expected 200, got $HTTP: $(cat /tmp/smoke_query.json)"
else
    TOP_SOURCE=$(python3 -c "import json; d=json.load(open('/tmp/smoke_query.json')); print(d['chunks'][0]['source'] if d['chunks'] else 'EMPTY')")
    if [[ "$TOP_SOURCE" == "$SMOKE_SOURCE" ]]; then
        TOP_DIST=$(python3 -c "import json; d=json.load(open('/tmp/smoke_query.json')); print(f\"{d['chunks'][0]['distance']:.4f}\")")
        pass "POST /query/retrieve top result is $SMOKE_SOURCE (cosine distance=$TOP_DIST)"
    else
        fail "POST /query/retrieve top result expected $SMOKE_SOURCE, got '$TOP_SOURCE'"
    fi
fi

# ----------------------------------------------------------------------------
# Test 7: (optional) /query/answer — real Anthropic call
# ----------------------------------------------------------------------------
if [[ "${SMOKE_TEST_ANTHROPIC:-0}" == "1" ]]; then
    HTTP=$(curl -s -o /tmp/smoke_answer.json -w "%{http_code}" \
        -X POST "$API_URL/query/answer" \
        -H "Content-Type: application/json" \
        -H "Authorization: Bearer $TOKEN" \
        -d '{"question":"Who was the first person to walk on the Moon?"}')
    if [[ "$HTTP" == "200" ]]; then
        SUMMARY=$(python3 -c "import json; d=json.load(open('/tmp/smoke_answer.json')); print(f\"model={d['model']}, in={d['input_tokens']}t, out={d['output_tokens']}t, ans_len={len(d['answer'])}c\")")
        pass "POST /query/answer (real Anthropic call) → 200, $SUMMARY"
    else
        fail "POST /query/answer expected 200, got $HTTP: $(cat /tmp/smoke_answer.json)"
    fi
else
    skip "POST /query/answer (set SMOKE_TEST_ANTHROPIC=1 to exercise — costs real tokens)"
fi

# ----------------------------------------------------------------------------
# Test 8 (Phase 2): Revoke the smoke key via CLI.
# ----------------------------------------------------------------------------
REVOKE_OUTPUT=$(docker compose exec -T api python -m scripts.issue_key \
    --tenant "$SMOKE_TENANT" --revoke "$KEY_PREFIX" 2>&1)
if [[ $? -eq 0 ]] && echo "$REVOKE_OUTPUT" | grep -q "Revoked key_id="; then
    pass "scripts/issue_key.py --revoke $KEY_PREFIX → CLI exit 0"
else
    fail "Revoke CLI failed: $REVOKE_OUTPUT"
fi

# ----------------------------------------------------------------------------
# Test 9 (Phase 2): Revoked key should now 401 on a protected route.
# Same key, same wire format — only the DB row state changed.
# ----------------------------------------------------------------------------
HTTP=$(curl -s -o /tmp/smoke_revoked.json -w "%{http_code}" \
    -X POST "$API_URL/ingest" \
    -H "Content-Type: application/json" \
    -H "Authorization: Bearer $TOKEN" \
    -d '{"source":"after-revoke","text":"should not land"}')
if [[ "$HTTP" == "401" ]]; then
    DETAIL=$(python3 -c "import json; print(json.load(open('/tmp/smoke_revoked.json'))['detail'])" 2>/dev/null || echo "?")
    pass "POST /ingest with revoked key → 401 (detail: $DETAIL)"
else
    fail "POST /ingest revoked-key expected 401, got $HTTP: $(cat /tmp/smoke_revoked.json)"
fi

# ----------------------------------------------------------------------------
# Test 10 (Phase 2 Step 2): Burst test against /query/retrieve.
#
# The original smoke key was revoked above, so we mint a separate key under
# tenant=smoke-ratelimit that starts with a clean rate-limit budget.
#
# Strategy:
#   - Read RATE_LIMIT_REQUESTS from .env (fall back to 10 if absent).
#   - Fire N+1 requests in a tight loop, capturing each HTTP code.
#   - Expect exactly N × 200 and exactly 1 × 429.
#   - The first 429 will be on request N+1 (request index == limit + 1).
# ----------------------------------------------------------------------------
RATELIMIT_TENANT="smoke-ratelimit"

# Read RATE_LIMIT_REQUESTS from .env without touching the running shell env.
# Default to 10 (matching .env's local-dev value) if not present.
RATE_LIMIT=$(grep -E '^RATE_LIMIT_REQUESTS=' .env 2>/dev/null | head -1 | cut -d'=' -f2 | tr -d '[:space:]')
RATE_LIMIT=${RATE_LIMIT:-10}

echo "----------------------------------------"
echo "Minting fresh key for rate-limit test (tenant=$RATELIMIT_TENANT, limit=$RATE_LIMIT) ..."
RL_ISSUE_OUTPUT=$(docker compose exec -T api python -m scripts.issue_key --tenant "$RATELIMIT_TENANT" 2>&1)
if [[ $? -ne 0 ]]; then
    fail "Could not mint rate-limit-test key: $RL_ISSUE_OUTPUT"
else
    RL_TOKEN=$(echo "$RL_ISSUE_OUTPUT" | grep -E '^[[:space:]]*token[[:space:]]*:' | awk -F': ' '{print $2}' | tr -d '[:space:]')
    RL_PREFIX=$(echo "$RL_ISSUE_OUTPUT" | grep -E '^[[:space:]]*key_prefix[[:space:]]*:' | awk -F': ' '{print $2}' | tr -d '[:space:]')

    # Tally results across the burst.
    BURST_TOTAL=$((RATE_LIMIT + 1))
    OK_COUNT=0
    LIMITED_COUNT=0
    OTHER_COUNT=0
    RETRY_AFTER=""

    for i in $(seq 1 $BURST_TOTAL); do
        # Capture both headers and status code.
        HTTP=$(curl -s -o /dev/null -D /tmp/smoke_burst_headers.txt -w "%{http_code}" \
            -X POST "$API_URL/query/retrieve" \
            -H "Content-Type: application/json" \
            -H "Authorization: Bearer $RL_TOKEN" \
            -d '{"question":"burst test","top_k":1}')
        case "$HTTP" in
            200) OK_COUNT=$((OK_COUNT + 1)) ;;
            429)
                LIMITED_COUNT=$((LIMITED_COUNT + 1))
                # Grab the Retry-After header from the FIRST 429 we see.
                if [[ -z "$RETRY_AFTER" ]]; then
                    RETRY_AFTER=$(grep -i '^retry-after:' /tmp/smoke_burst_headers.txt | head -1 | awk -F': ' '{print $2}' | tr -d '\r\n[:space:]')
                fi
                ;;
            *) OTHER_COUNT=$((OTHER_COUNT + 1)) ;;
        esac
    done

    # Assertion 1: exactly N × 200 and exactly 1 × 429.
    if [[ "$OK_COUNT" -eq "$RATE_LIMIT" && "$LIMITED_COUNT" -eq 1 && "$OTHER_COUNT" -eq 0 ]]; then
        pass "Burst $BURST_TOTAL reqs → $OK_COUNT × 200, $LIMITED_COUNT × 429 (limit honored)"
    else
        fail "Burst $BURST_TOTAL reqs → $OK_COUNT × 200, $LIMITED_COUNT × 429, $OTHER_COUNT × other (expected $RATE_LIMIT/1/0)"
    fi

    # Assertion 2: Retry-After is present and > 0.
    if [[ -n "$RETRY_AFTER" && "$RETRY_AFTER" =~ ^[0-9]+$ && "$RETRY_AFTER" -gt 0 ]]; then
        pass "429 response carries Retry-After: ${RETRY_AFTER}s"
    else
        fail "429 response missing/invalid Retry-After header (got: '$RETRY_AFTER')"
    fi

    # Cleanup: revoke the rate-limit-test key.
    docker compose exec -T api python -m scripts.issue_key \
        --tenant "$RATELIMIT_TENANT" --revoke "$RL_PREFIX" > /dev/null 2>&1
fi

# ----------------------------------------------------------------------------
# Summary
# ----------------------------------------------------------------------------
echo "----------------------------------------"
if [[ $FAIL -gt 0 ]]; then
    printf "%b\n" "Results: ${GREEN}${PASS} passed${NC}, ${RED}${FAIL} failed${NC}"
    exit 1
else
    printf "%b\n" "Results: ${GREEN}${PASS} passed${NC}, 0 failed"
    exit 0
fi
