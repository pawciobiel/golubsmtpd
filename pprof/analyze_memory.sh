#!/bin/bash

# Memory Analysis Helper for golubsmtpd
# Usage: ./analyze_memory.sh [baseline|current|diff]

ACTION=${1:-current}
PPROF_URL="http://localhost:6060/debug/pprof"

echo "golubsmtpd Memory Analysis Tool"
echo "==============================="

# Check if server is running
if ! curl -s "$PPROF_URL/heap" > /dev/null; then
    echo "❌ Error: pprof server not accessible at $PPROF_URL"
    echo "Make sure golubsmtpd is running with pprof enabled:"
    echo "  ./golubsmtpd -config test-config.yaml"
    exit 1
fi

case $ACTION in
    "baseline")
        echo "📸 Taking baseline memory snapshot..."
        curl -s "$PPROF_URL/heap" -o baseline_heap.pb.gz
        go tool pprof -png -output baseline_heap.png "$PPROF_URL/heap"
        go tool pprof -text -output baseline_heap.txt "$PPROF_URL/heap"
        echo "✅ Baseline saved: baseline_heap.pb.gz, baseline_heap.png, baseline_heap.txt"
        ;;
        
    "current")
        echo "📊 Current Memory Analysis:"
        echo
        echo "=== Quick Stats ==="
        curl -s "$PPROF_URL/heap?debug=1" | grep -E "(heap profile|HeapAlloc|HeapInuse|HeapObjects|NumGC)" | head -10
        echo
        echo "=== Goroutines ==="
        curl -s "$PPROF_URL/goroutine?debug=1" | head -1
        echo
        echo "=== Top Memory Users ==="
        go tool pprof -text "$PPROF_URL/heap" | head -15
        ;;
        
    "diff")
        if [ ! -f "baseline_heap.pb.gz" ]; then
            echo "❌ Error: baseline_heap.pb.gz not found"
            echo "Run: ./analyze_memory.sh baseline first"
            exit 1
        fi
        echo "🔍 Memory difference since baseline..."
        curl -s "$PPROF_URL/heap" -o current_heap.pb.gz
        go tool pprof -png -output diff_heap.png -base baseline_heap.pb.gz "$PPROF_URL/heap"
        go tool pprof -text -base baseline_heap.pb.gz "$PPROF_URL/heap" | head -20
        echo "✅ Difference analysis saved: diff_heap.png"
        echo
        echo "=== Memory Growth Summary ==="
        if [ -f "baseline_heap.txt" ]; then
            echo "Baseline objects: $(grep 'heap profile' baseline_heap.txt | awk '{print $4}' 2>/dev/null || echo 'N/A')"
        fi
        echo "Current objects:  $(curl -s "$PPROF_URL/heap?debug=1" | grep 'heap profile' | awk '{print $4}' 2>/dev/null || echo 'N/A')"
        ;;
        
    "interactive")
        echo "🔧 Starting interactive pprof session..."
        echo "Useful commands: top, web, list <function>, traces"
        go tool pprof "$PPROF_URL/heap"
        ;;
        
    "goroutines")
        echo "🧵 Goroutine Analysis:"
        echo
        echo "=== Goroutine Count ==="
        curl -s "$PPROF_URL/goroutine?debug=1" | head -1
        echo
        echo "=== Top Goroutine Sources ==="
        go tool pprof -text "$PPROF_URL/goroutine" | head -10
        echo
        echo "Starting interactive goroutine analysis..."
        go tool pprof "$PPROF_URL/goroutine"
        ;;
        
    "help"|*)
        echo "Usage: $0 [baseline|current|diff|interactive|goroutines]"
        echo
        echo "Commands:"
        echo "  baseline     - Take baseline memory snapshot"
        echo "  current      - Show current memory stats (default)"
        echo "  diff         - Compare current vs baseline"
        echo "  interactive  - Start interactive pprof heap session"
        echo "  goroutines   - Analyze goroutine usage"
        echo
        echo "Example workflow:"
        echo "  1. ./analyze_memory.sh baseline    # Before load test"
        echo "  2. ./test_smtp.sh 100             # Run load test"
        echo "  3. ./analyze_memory.sh diff       # Check for leaks"
        ;;
esac

echo