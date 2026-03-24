package ws

import "sync"

// RingBuffer is a fixed-capacity thread-safe circular buffer.
// When full, the oldest entry is dropped to make room for the new one.
type RingBuffer struct {
	mu    sync.Mutex
	items [][]byte
	max   int
}

func NewRingBuffer(max int) *RingBuffer {
	return &RingBuffer{
		items: make([][]byte, 0, max),
		max:   max,
	}
}

// Add appends an item, evicting the oldest if at capacity.
func (r *RingBuffer) Add(item []byte) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if len(r.items) >= r.max {
		r.items = r.items[1:]
	}
	cp := make([]byte, len(item))
	copy(cp, item)
	r.items = append(r.items, cp)
}

// Last returns the most recent n items (or all if fewer exist),
// in oldest-first order, ready to replay on the client.
func (r *RingBuffer) Last(n int) [][]byte {
	r.mu.Lock()
	defer r.mu.Unlock()
	if n >= len(r.items) {
		out := make([][]byte, len(r.items))
		copy(out, r.items)
		return out
	}
	src := r.items[len(r.items)-n:]
	out := make([][]byte, len(src))
	copy(out, src)
	return out
}

// Clear empties the buffer.
func (r *RingBuffer) Clear() {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.items = r.items[:0]
}
