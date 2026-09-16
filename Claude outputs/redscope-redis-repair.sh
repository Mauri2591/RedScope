#!/bin/bash

# ========================================
# REDSCOPE REDIS STATE REPAIR
# ========================================
# Repairs corrupted RQ registries without stopping active jobs

set -e

REDIS_DB=1
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

echo -e "${BLUE}========================================${NC}"
echo -e "${BLUE}REDSCOPE REDIS STATE REPAIR${NC}"
echo -e "${BLUE}========================================${NC}"
echo ""

# Backup before repair
echo -e "${YELLOW}[1] Backing up Redis DB $REDIS_DB...${NC}"
BACKUP_FILE="/tmp/redis-db${REDIS_DB}-backup-$(date +%s).rdb"
redis-cli -n $REDIS_DB BGSAVE
echo -e "${GREEN}✓ Backup initiated${NC}"
echo ""

# Remove corrupted rq:workers key
echo -e "${YELLOW}[2] Repairing corrupted rq:workers key...${NC}"
echo "  Current type: $(redis-cli -n $REDIS_DB TYPE rq:workers)"
echo "  Deleting corrupted key..."
redis-cli -n $REDIS_DB DEL rq:workers
echo -e "${GREEN}✓ Deleted rq:workers${NC}"
echo ""

# Verify registry types
echo -e "${YELLOW}[3] Verifying registry types...${NC}"
echo "  rq:queue:osint type: $(redis-cli -n $REDIS_DB TYPE rq:queue:osint) (should be 'list')"
echo "  rq:queue:aws type: $(redis-cli -n $REDIS_DB TYPE rq:queue:aws) (should be 'list')"
echo "  rq:started:osint type: $(redis-cli -n $REDIS_DB TYPE rq:started:osint) (should be 'list')"
echo "  rq:started:aws type: $(redis-cli -n $REDIS_DB TYPE rq:started:aws) (should be 'list')"
echo ""

# Check TTL issues - jobs disappearing after X time
echo -e "${YELLOW}[4] Checking job TTL configuration...${NC}"
echo "  Scanning first 5 job keys for TTL..."
redis-cli -n $REDIS_DB KEYS "rq:job:*" | head -5 | while read jobkey; do
    ttl=$(redis-cli -n $REDIS_DB TTL "$jobkey")
    echo "    $jobkey: TTL=$ttl seconds"
done
echo ""

# List all registries to compare
echo -e "${YELLOW}[5] Current registry contents...${NC}"
echo "  rq:queue:osint entries: $(redis-cli -n $REDIS_DB LLEN rq:queue:osint)"
echo "  rq:started:osint entries: $(redis-cli -n $REDIS_DB LLEN rq:started:osint)"
echo ""
echo "  First 3 entries in rq:started:osint:"
redis-cli -n $REDIS_DB LRANGE rq:started:osint 0 2 | sed 's/^/    /'
echo ""

# Check if job data exists for those entries
echo -e "${YELLOW}[6] Verifying job data exists for started jobs...${NC}"
missing_count=0
redis-cli -n $REDIS_DB LRANGE rq:started:osint 0 -1 | while read jobid; do
    if ! redis-cli -n $REDIS_DB EXISTS "rq:job:$jobid" | grep -q 1; then
        echo "    ⚠️  Missing data for job: $jobid"
        ((missing_count++))
    fi
done
echo ""

# Recommendation
echo -e "${BLUE}========================================${NC}"
echo -e "${BLUE}REPAIR ANALYSIS${NC}"
echo -e "${BLUE}========================================${NC}"
echo ""

if redis-cli -n $REDIS_DB LLEN rq:started:osint | grep -qE "^0$"; then
    if redis-cli -n $REDIS_DB KEYS "rq:job:*" | wc -l | grep -qvE "^0$"; then
        echo -e "${YELLOW}⚠️  ISSUE: Jobs exist in Redis but not in started registry${NC}"
        echo "    This means:"
        echo "    • Workers are not updating job status in Redis"
        echo "    • OR job data is expiring before the job completes"
        echo ""
        echo "    SOLUTION:"
        echo "    1. Check RQ worker logs for errors"
        echo "    2. Increase Redis TTL for job data"
        echo "    3. Verify Redis connection in REDSCOPE config"
    fi
else
    echo -e "${GREEN}✓ Registry counts look normal${NC}"
fi

echo ""
echo "Completed repair checks."
echo ""
