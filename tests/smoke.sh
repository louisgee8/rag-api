#!/usr/bin/env bash
#
# tests/smoke.sh — End-to-end smoke test for rag-api Phase 1.
#
# Exercises the full happy + auth-failure paths against a running stack:
#   1. /health is public (no auth)
#   2. Protected route without auth → 401
#   3. Protected route with empty Bearer token → 401
#   4. Protected route with wrong key → 401
#   5. /ingest with correct key → 200, chunks created
#   6. /query/retrieve returns the freshly ingested doc as top result
#   7. (optional) /query/answer end-to-end via real Anthropic call
#
# Usage:
#   ./tests/smoke.sh                          # default: skip Anthropic call
#   SMOKE_TEST_ANTHROPIC=1 ./tests/smoke.sh   # also exercise /query/answer
#   API_URL=http://other:9000 ./tests/smoke.sh
#
# Exit codes:
#   0 = all assertions passed
#   1 = at least one assertion failed (or .env missing / API_KEY unset)
#
# Requires: bash, curl, python3 (stdlib only — for JSON parsing)
# Re-run safe: ingestion uses a fixed source name and DELETE-by-source
# semantics, so re-running the smoke does not pollute the documents table.

set -u  # Undefined-var = error. We deliberately do NOT set -e because we
        # want to handle expected curl non-zero exits gracefully.

API_URL="${API_URL:-http://localhost:8000}"
ENV_FILE="${ENV_FILE:-.env}"
SMOKE_SOURCE="smoke-test-fixture"

# Color codes (graceful fallback if not a TTY)
if [[ -t 1 ]]; then
    RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; NC='\033[0m'
else
    RED=''; GREEN=''; YELLOW=''; NC=''
fi

PASS=0
FAIL=0

pass() { echo -e "${GREEN}PASS${NC} $*"; PASS=$((PASS + 1)); }
fail() { echo -e "${RED}FAIL${NC} $*"; FAIL=$((FAIL + 1)); }
skip() { echo -e "${YELLOW}SKIP${NC} $*"; }

# ----------------------------------------------------------------------------
# Load API_KEY from .env
# ----------------------------------------------------------------------------
if [[ ! -f "$ENV_FILE" ]]; then
    fail "No .env file at $ENV_FILE — cannot load API_KEY."
    exit 1
fi

API_KEY=$(grep '^API_KEY=' "$ENV_FILE" | cut -d= -f2- | tr -d '\r\n')
if [[ -z "$API_KEY" ]]; then
    fail "API_KEY not set in $ENV_FILE (no API_KEY= line, or empty value)."
    exit 1
fi
if [[ "$API_KEY" == "replace-me-with-openssl-rand-hex-32" ]]; then
    fail "API_KEY in $ENV_FILE is the placeholder. Generate a real one: openssl rand -hex 32"
    exit 1
fi

echo "rag-api Phase 1 smoke test"
echo "  API URL:  $API_URL"
echo "  API_KEY:  ${API_KEY:0:8}... (loaded from $ENV_FILE)"
echo "  Anthropic: $([[ "${SMOKE_TEST_ANTHROPIC:-0}" == "1" ]] && echo "enabled" || echo "skipped (set SMOKE_TEST_ANTHROPIC=1 to enable)")"
echo "----------------------------------------"

# ----------------------------------------------------------------------------
# Test 1: /health is public, no auth needed
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
# Test 3: Empty Bearer token → 401 (closes Session 6 coverage gap)
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
# Test 4: Wrong key → 401
# ----------------------------------------------------------------------------
HTTP=$(curl -s -o /dev/null -w "%{http_code}" \
    -X POST "$API_URL/query/retrieve" \
    -H "Content-Type: application/json" \
    -H "Authorization: Bearer this-is-not-the-real-key" \
    -d '{"question":"test"}')
if [[ "$HTTP" == "401" ]]; then
    pass "POST /query/retrieve (wrong key) → 401"
else
    fail "POST /query/retrieve wrong-key expected 401, got $HTTP"
fi

# ----------------------------------------------------------------------------
# Test 5: /ingest with correct key → 200
# ----------------------------------------------------------------------------
SMOKE_TEXT="The Apollo 11 mission landed on the Moon on July 20, 1969. Neil Armstrong was the first human to walk on the lunar surface, followed by Buzz Aldrin. Michael Collins remained in lunar orbit aboard the command module Columbia."

HTTP=$(curl -s -o /tmp/smoke_ingest.json -w "%{http_code}" \
    -X POST "$API_URL/ingest" \
    -H "Content-Type: application/json" \
    -H "Authorization: Bearer $API_KEY" \
    -d "{\"source\":\"$SMOKE_SOURCE\",\"text\":\"$SMOKE_TEXT\"}")
if [[ "$HTTP" == "200" ]]; then
    CHUNKS=$(python3 -c "import json; print(json.load(open('/tmp/smoke_ingest.json'))['chunks_created'])")
    REPLACED=$(python3 -c "import json; print(json.load(open('/tmp/smoke_ingest.json'))['chunks_replaced'])")
    pass "POST /ingest (correct key) → 200, chunks_created=$CHUNKS replaced=$REPLACED"
else
    fail "POST /ingest expected 200, got $HTTP: $(cat /tmp/smoke_ingest.json)"
    echo "----------------------------------------"
    echo "Cannot continue — /ingest must succeed for retrieval test."
    echo "Results: $PASS passed, $FAIL failed"
    exit 1
fi

# ----------------------------------------------------------------------------
# Test 6: /query/retrieve — top result must be from our fixture
# ----------------------------------------------------------------------------
HTTP=$(curl -s -o /tmp/smoke_query.json -w "%{http_code}" \
    -X POST "$API_URL/query/retrieve" \
    -H "Content-Type: application/json" \
    -H "Authorization: Bearer $API_KEY" \
    -d '{"question":"Who was the first person to walk on the Moon?","top_k":3}')

if [[ "$HTTP" != "200" ]]; then
    fail "POST /query/retrieve expected 200, got $HTTP: $(cat /tmp/smoke_query.json)"
else
    TOP_SOURCE=$(python3 -c "
import json
d = json.load(open('/tmp/smoke_query.json'))
print(d['chunks'][0]['source'] if d['chunks'] else 'EMPTY')
")
    if [[ "$TOP_SOURCE" == "$SMOKE_SOURCE" ]]; then
        TOP_DIST=$(python3 -c "
import json
d = json.load(open('/tmp/smoke_query.json'))
print(f\"{d['chunks'][0]['distance']:.4f}\")
")
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
        -H "Authorization: Bearer $API_KEY" \
        -d '{"question":"Who was the first person to walk on the Moon?"}')
    if [[ "$HTTP" == "200" ]]; then
        SUMMARY=$(python3 -c "
import json
d = json.load(open('/tmp/smoke_answer.json'))
print(f\"model={d['model']}, in={d['input_tokens']}t, out={d['output_tokens']}t, ans_len={len(d['answer'])}c\")
")
        pass "POST /query/answer (real Anthropic call) → 200, $SUMMARY"
    else
        fail "POST /query/answer expected 200, got $HTTP: $(cat /tmp/smoke_answer.json)"
    fi
else
    skip "POST /query/answer (set SMOKE_TEST_ANTHROPIC=1 to exercise — costs real tokens)"
fi

# ----------------------------------------------------------------------------
# Summary
# ----------------------------------------------------------------------------
echo "----------------------------------------"
echo -e "Results: ${GREEN}${PASS} passed${NC}, $([[ $FAIL -gt 0 ]] && echo -e "${RED}${FAIL} failed${NC}" || echo "0 failed")"

if [[ "$FAIL" -gt 0 ]]; then
    exit 1
fi
exit 0
