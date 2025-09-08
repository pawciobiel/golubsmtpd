package smtp

import (
	"container/list"
	"sync"
	"time"
)

// CacheEntry represents a cached value with TTL tracking
type CacheEntry struct {
	key       string
	value     bool // cached boolean result
	timestamp time.Time
	element   *list.Element // for LRU tracking
}

// LRUCache is a thread-safe LRU cache with TTL and automatic cleanup
type LRUCache struct {
	mutex    sync.RWMutex
	capacity int
	ttl      time.Duration

	// LRU tracking
	items   map[string]*CacheEntry
	lruList *list.List

	// Cleanup management
	cleanupInterval time.Duration
	stopCleanup     chan struct{}
	wg              sync.WaitGroup

	// Statistics
	hits   int64
	misses int64
}

// NewLRUCache creates a new LRU cache with TTL and background cleanup
func NewLRUCache(capacity int, ttl time.Duration) *LRUCache {
	cache := &LRUCache{
		capacity:        capacity,
		ttl:             ttl,
		items:           make(map[string]*CacheEntry, capacity),
		lruList:         list.New(),
		cleanupInterval: ttl / 4, // Clean 4x more frequently than TTL
		stopCleanup:     make(chan struct{}),
	}

	// Start cleanup goroutine
	cache.wg.Add(1)
	go cache.cleanupRoutine()

	return cache
}

// Get retrieves a value from the cache
func (c *LRUCache) Get(key string) (bool, bool) {
	c.mutex.Lock()
	defer c.mutex.Unlock()

	entry, exists := c.items[key]
	if !exists {
		c.misses++
		return false, false
	}

	// Check TTL
	if time.Since(entry.timestamp) > c.ttl {
		c.removeLocked(key)
		c.misses++
		return false, false
	}

	// Move to front (most recently used)
	c.lruList.MoveToFront(entry.element)
	c.hits++
	return entry.value, true
}

// Put stores a value in the cache
func (c *LRUCache) Put(key string, value bool) {
	c.mutex.Lock()
	defer c.mutex.Unlock()

	// Check if key already exists
	if entry, exists := c.items[key]; exists {
		// Update existing entry
		entry.value = value
		entry.timestamp = time.Now()
		c.lruList.MoveToFront(entry.element)
		return
	}

	// Create new entry
	entry := &CacheEntry{
		key:       key,
		value:     value,
		timestamp: time.Now(),
	}

	// Add to front of LRU list
	entry.element = c.lruList.PushFront(entry)
	c.items[key] = entry

	// Check capacity - evict LRU if needed
	if len(c.items) > c.capacity {
		c.evictLRU()
	}
}

// evictLRU removes the least recently used entry
func (c *LRUCache) evictLRU() {
	if oldest := c.lruList.Back(); oldest != nil {
		entry := oldest.Value.(*CacheEntry)
		c.removeLocked(entry.key)
	}
}

// removeLocked removes an entry from cache (must hold mutex)
func (c *LRUCache) removeLocked(key string) {
	if entry, exists := c.items[key]; exists {
		c.lruList.Remove(entry.element)
		delete(c.items, key)
	}
}

// cleanupRoutine runs in background to remove expired entries
func (c *LRUCache) cleanupRoutine() {
	defer c.wg.Done()

	ticker := time.NewTicker(c.cleanupInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			c.cleanup()
		case <-c.stopCleanup:
			return
		}
	}
}

// cleanup removes expired entries from the cache
func (c *LRUCache) cleanup() {
	c.mutex.Lock()
	defer c.mutex.Unlock()

	now := time.Now()
	var keysToRemove []string

	// Find expired entries
	for key, entry := range c.items {
		if now.Sub(entry.timestamp) > c.ttl {
			keysToRemove = append(keysToRemove, key)
		}
	}

	// Remove expired entries
	for _, key := range keysToRemove {
		c.removeLocked(key)
	}
}

// Close stops the cleanup routine and waits for it to finish
func (c *LRUCache) Close() {
	close(c.stopCleanup)
	c.wg.Wait()
}

// Stats returns cache statistics
func (c *LRUCache) Stats() (size, capacity int, hitRate float64) {
	c.mutex.RLock()
	defer c.mutex.RUnlock()

	total := c.hits + c.misses
	if total > 0 {
		hitRate = float64(c.hits) / float64(total)
	}

	return len(c.items), c.capacity, hitRate
}

// Clear removes all entries from the cache
func (c *LRUCache) Clear() {
	c.mutex.Lock()
	defer c.mutex.Unlock()

	c.items = make(map[string]*CacheEntry, c.capacity)
	c.lruList = list.New()
	c.hits = 0
	c.misses = 0
}
