#!/bin/bash

# Real-time Memory Monitoring for golubsmtpd
# Usage: ./monitor_memory.sh [duration_seconds] [interval_seconds]

DURATION=${1:-60}
INTERVAL=${2:-1}
PPROF_URL="http://localhost:6060/debug/pprof"
OUTPUT_DIR="memory_data"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)

echo "golubsmtpd Real-time Memory Monitor"
echo "==================================="
echo "Duration: ${DURATION}s, Interval: ${INTERVAL}s"
echo "Output: ${OUTPUT_DIR}/memory_${TIMESTAMP}.csv"

# Check if server is running
if ! curl -s "$PPROF_URL/heap" > /dev/null; then
    echo "❌ Error: pprof server not accessible at $PPROF_URL"
    echo "Make sure golubsmtpd is running with pprof enabled"
    exit 1
fi

# Create output directory
mkdir -p "$OUTPUT_DIR"

# CSV header
CSV_FILE="${OUTPUT_DIR}/memory_${TIMESTAMP}.csv"
echo "timestamp,heap_alloc_mb,heap_objects,heap_inuse_mb,goroutines,gc_cycles" > "$CSV_FILE"

echo "📊 Starting real-time monitoring..."
echo "Press Ctrl+C to stop early"

END_TIME=$(($(date +%s) + DURATION))

while [ $(date +%s) -lt $END_TIME ]; do
    CURRENT_TIME=$(date +%s)
    ISO_TIME=$(date -Iseconds)
    
    # Get heap stats
    HEAP_STATS=$(curl -s "$PPROF_URL/heap?debug=1")
    GOROUTINE_COUNT=$(curl -s "$PPROF_URL/goroutine?debug=1" | head -1 | grep -o '[0-9]\+' | head -1)
    
    # Extract metrics using correct pprof format (# HeapAlloc = value)
    HEAP_ALLOC=$(echo "$HEAP_STATS" | grep "# HeapAlloc = " | sed 's/# HeapAlloc = \([0-9]*\)/\1/' | head -1)
    HEAP_OBJECTS=$(echo "$HEAP_STATS" | grep "# HeapObjects = " | sed 's/# HeapObjects = \([0-9]*\)/\1/' | head -1)
    HEAP_INUSE=$(echo "$HEAP_STATS" | grep "# HeapInuse = " | sed 's/# HeapInuse = \([0-9]*\)/\1/' | head -1)
    GC_CYCLES=$(echo "$HEAP_STATS" | grep "# NumGC = " | sed 's/# NumGC = \([0-9]*\)/\1/' | head -1)
    
    # Default to 0 if extraction failed
    HEAP_ALLOC=${HEAP_ALLOC:-0}
    HEAP_OBJECTS=${HEAP_OBJECTS:-0}
    HEAP_INUSE=${HEAP_INUSE:-0}
    GC_CYCLES=${GC_CYCLES:-0}
    
    # Convert bytes to MB for readability
    HEAP_ALLOC_MB=$(echo "scale=2; $HEAP_ALLOC / 1024 / 1024" | bc -l 2>/dev/null || echo "0")
    HEAP_INUSE_MB=$(echo "scale=2; $HEAP_INUSE / 1024 / 1024" | bc -l 2>/dev/null || echo "0")
    
    # Write to CSV
    echo "${ISO_TIME},${HEAP_ALLOC_MB},${HEAP_OBJECTS},${HEAP_INUSE_MB},${GOROUTINE_COUNT:-0},${GC_CYCLES}" >> "$CSV_FILE"
    
    # Live display
    printf "\r⏱️  %s | Heap: %s MB | Objects: %s | Goroutines: %s" \
        "$(date +%H:%M:%S)" "$HEAP_ALLOC_MB" "$HEAP_OBJECTS" "${GOROUTINE_COUNT:-0}"
    
    sleep "$INTERVAL"
done

echo ""
echo "✅ Monitoring complete!"
echo "📁 Data saved to: $CSV_FILE"
echo ""
echo "🔍 Quick analysis:"
head -1 "$CSV_FILE"
tail -5 "$CSV_FILE"

echo ""
echo "📈 Generate plots with:"
echo "  python3 plot_memory.py $CSV_FILE"
echo "  gnuplot -e \"plot '$CSV_FILE' using 2 with lines title 'Heap Alloc MB'\""