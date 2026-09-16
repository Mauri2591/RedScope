#!/bin/bash

# ========================================
# REDSCOPE REDIS JOB STATE DIAGNOSTICS
# ========================================
# This script investigates where jobs are being tracked in Redis
# when they appear to be running but not showing in standard RQ registries

set -e

echo "=========================================="
echo "REDSCOPE REDIS JOB STATE INVESTIGATION"
echo "=========================================="
echo ""

# Configuration
REDIS_DB=1
LOG_DIR="/var/log/redscope"
TEMP_FILE="/tmp/active_jobs_$$.txt"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

trap "rm -f $TEMP_FILE" EXIT

# ========== SECTION 1: Extract Job IDs from Logs ==========
echo -e "${BLUE}[1/5] Extracting job IDs from active worker logs...${NC}"
echo ""

# Get recent log entries that contain job information
for worker_log in $LOG_DIR/rq-worker-osint-*.log $LOG_DIR/rq-worker-osint-*-error.log; do
    if [[ -f "$worker_log" ]]; then
        # Look for job execution patterns in logs
        grep -o "[0-9a-f]\{8\}-[0-9a-f]\{4\}-[0-9a-f]\{4\}-[0-9a-f]\{4\}-[0-9a-f]\{12\}" "$worker_log" 2>/dev/null || true
    fi
done | sort -u > "$TEMP_FILE"

if [[ -s "$TEMP_FILE" ]]; then
    echo -e "${GREEN}Found $(wc -l < "$TEMP_FILE") unique job IDs in logs:${NC}"
    head -10 "$TEMP_FILE" | sed 's/^/  /'
    [[ $(wc -l < "$TEMP_FILE") -gt 10 ]] && echo "  ... and $(($(wc -l < "$TEMP_FILE") - 10)) more"
else
    echo -e "${YELLOW}No UUID-format job IDs found in logs${NC}"
    echo "Checking for other job identifier patterns..."
    tail -50 $LOG_DIR/rq-worker-osint-*.log 2>/dev/null | grep -i "job\|task\|started\|processing" | head -5 | sed 's/^/  /'
fi
echo ""

# ========== SECTION 2: Redis Queue Registries ==========
echo -e "${BLUE}[2/5] Checking all Redis RQ queue registries...${NC}"
echo ""

echo "Queue status (jobs waiting to be processed):"
echo "  AWS Queue:   $(redis-cli -n $REDIS_DB llen rq:queue:aws 2>/dev/null || echo 'ERROR')"
echo "  OSINT Queue: $(redis-cli -n $REDIS_DB llen rq:queue:osint 2>/dev/null || echo 'ERROR')"
echo "  IA Queue:    $(redis-cli -n $REDIS_DB llen rq:queue:ia 2>/dev/null || echo 'ERROR')"
echo ""

echo "Started jobs registries (jobs currently executing):"
echo "  rq:started:aws:   $(redis-cli -n $REDIS_DB llen rq:started:aws 2>/dev/null || echo 'ERROR')"
echo "  rq:started:osint: $(redis-cli -n $REDIS_DB llen rq:started:osint 2>/dev/null || echo 'ERROR')"
echo "  rq:started:ia:    $(redis-cli -n $REDIS_DB llen rq:started:ia 2>/dev/null || echo 'ERROR')"
echo ""

echo "Worker registries:"
echo "  rq:workers:      $(redis-cli -n $REDIS_DB llen rq:workers 2>/dev/null || echo 'ERROR')"
echo "  rq:workers:osint:aws:    $(redis-cli -n $REDIS_DB llen rq:workers:osint:aws 2>/dev/null || echo 'ERROR')"
echo ""

# ========== SECTION 3: Look for jobs in all possible locations ==========
echo -e "${BLUE}[3/5] Searching for job data in Redis...${NC}"
echo ""

# Get all keys that look like job keys
echo "Scanning for job-related keys..."
redis-cli -n $REDIS_DB KEYS "rq:job:*" | head -20 | while read key; do
    echo "  Found: $key"
done

# Get all worker information
echo ""
echo "Active workers:"
redis-cli -n $REDIS_DB LRANGE rq:workers 0 -1 2>/dev/null | while read worker; do
    [[ -z "$worker" ]] && continue
    echo "  Worker: $worker"
    redis-cli -n $REDIS_DB HGETALL "$worker" 2>/dev/null | sed 's/^/    /'
done

echo ""

# ========== SECTION 4: Check job state for each ID found ==========
echo -e "${BLUE}[4/5] Detailed job state information...${NC}"
echo ""

if [[ -s "$TEMP_FILE" ]]; then
    count=0
    while IFS= read -r job_id; do
        if [[ $count -lt 5 ]]; then
            echo "Job ID: $job_id"

            # Check all possible job state locations
            echo "  In rq:started:osint? $(redis-cli -n $REDIS_DB lpos rq:started:osint "$job_id" 2>/dev/null && echo 'YES' || echo 'NO')"
            echo "  In rq:started:aws? $(redis-cli -n $REDIS_DB lpos rq:started:aws "$job_id" 2>/dev/null && echo 'YES' || echo 'NO')"
            echo "  In rq:started:ia? $(redis-cli -n $REDIS_DB lpos rq:started:ia "$job_id" 2>/dev/null && echo 'YES' || echo 'NO')"

            # Check if job data exists
            job_key="rq:job:$job_id"
            if redis-cli -n $REDIS_DB EXISTS "$job_key" 2>/dev/null | grep -q 1; then
                echo "  Job data exists at: $job_key"
                echo "    Status: $(redis-cli -n $REDIS_DB HGET "$job_key" "status" 2>/dev/null || echo 'NONE')"
                echo "    Queue: $(redis-cli -n $REDIS_DB HGET "$job_key" "origin" 2>/dev/null || echo 'NONE')"
                echo "    Function: $(redis-cli -n $REDIS_DB HGET "$job_key" "func_name" 2>/dev/null || echo 'NONE')"
            else
                echo "  Job data NOT found in Redis"
            fi
            echo ""
            ((count++))
        fi
    done < "$TEMP_FILE"
fi

# ========== SECTION 5: Compare logs vs Redis ==========
echo -e "${BLUE}[5/5] System Status Comparison...${NC}"
echo ""

echo "Logs show active execution:"
for worker_log in $LOG_DIR/rq-worker-osint-*.log; do
    if [[ -f "$worker_log" ]]; then
        # Look for heartbeat or processing messages
        last_heartbeat=$(tail -1 "$worker_log" 2>/dev/null || echo "N/A")
        echo "  $(basename $worker_log): $last_heartbeat"
    fi
done

echo ""
echo "Redis shows job state:"
echo "  Queue lengths: AWS=$(redis-cli -n $REDIS_DB llen rq:queue:aws 2>/dev/null) OSINT=$(redis-cli -n $REDIS_DB llen rq:queue:osint 2>/dev/null) IA=$(redis-cli -n $REDIS_DB llen rq:queue:ia 2>/dev/null)"
echo "  Started registries: OSINT=$(redis-cli -n $REDIS_DB llen rq:started:osint 2>/dev/null) AWS=$(redis-cli -n $REDIS_DB llen rq:started:aws 2>/dev/null) IA=$(redis-cli -n $REDIS_DB llen rq:started:ia 2>/dev/null)"

echo ""
echo "=========================================="
echo "DIAGNOSIS COMPLETE"
echo "=========================================="
echo ""
echo "Next steps:"
echo "  1. If jobs appear in logs but NOT in Redis, RQ state sync is broken"
echo "  2. If jobs exist in rq:job:* but not in rq:started, check RQ version/config"
echo "  3. If all Redis values are 0, check if REDSCOPE is using a different Redis DB"
echo ""
