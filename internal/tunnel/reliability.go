package tunnel

import (
	"errors"
	"time"
)

const (
	DefaultWindowSize        = 64
	DefaultRetransmitTimeout = 500 * time.Millisecond
	MaxRetransmitAttempts    = 10
)

var ErrWindowFull = errors.New("send window full")

// SendEntry is one unacknowledged outgoing packet.
type SendEntry struct {
	Seq      uint32
	Data     []byte // full wire bytes
	SentAt   time.Time
	Attempts int
}

// SendQueue is the per-session retransmit queue.
// Not safe for concurrent use; callers must hold session.mu.
type SendQueue struct {
	entries    []*SendEntry
	nextSeq    uint32
	windowSize uint32
}

// NewSendQueue initialises a SendQueue.
func NewSendQueue(initialSeq uint32, windowSize uint32) *SendQueue {
	if windowSize == 0 {
		windowSize = DefaultWindowSize
	}
	return &SendQueue{nextSeq: initialSeq, windowSize: windowSize}
}

// Enqueue adds wireBytes to the send queue and returns the assigned sequence
// number. Returns ErrWindowFull when the window is exhausted.
func (q *SendQueue) Enqueue(wireBytes []byte) (uint32, error) {
	if uint32(len(q.entries)) >= q.windowSize {
		return 0, ErrWindowFull
	}
	seq := q.nextSeq
	q.nextSeq++
	q.entries = append(q.entries, &SendEntry{
		Seq:    seq,
		Data:   wireBytes,
		SentAt: time.Now(),
	})
	return seq, nil
}

// Acknowledge removes all entries with Seq <= ack (cumulative ACK).
func (q *SendQueue) Acknowledge(ack uint32) int {
	removed := 0
	i := 0
	for i < len(q.entries) {
		if seqLE(q.entries[i].Seq, ack) {
			removed++
			i++
		} else {
			break
		}
	}
	q.entries = q.entries[i:]
	return removed
}

// TimedOut returns entries whose SentAt is older than timeout. Callers should
// re-send them and update SentAt + Attempts.
func (q *SendQueue) TimedOut(timeout time.Duration) []*SendEntry {
	var out []*SendEntry
	deadline := time.Now().Add(-timeout)
	for _, e := range q.entries {
		if e.SentAt.Before(deadline) {
			out = append(out, e)
		}
	}
	return out
}

// PeekNext returns the next sequence number that will be assigned.
func (q *SendQueue) PeekNext() uint32 { return q.nextSeq }

// InFlight returns the number of unacknowledged entries.
func (q *SendQueue) InFlight() int { return len(q.entries) }

// seqLE compares two uint32 sequence numbers with wrap-around handling.
func seqLE(a, b uint32) bool {
	return int32(a-b) <= 0
}

// RecvTracker tracks received sequence numbers to detect duplicates.
// Uses a 512-bit sliding window bitmap.
type RecvTracker struct {
	nextExpected uint32
	windowBits   [8]uint64 // 512 slots
}

// NewRecvTracker creates a RecvTracker expecting the given first sequence.
func NewRecvTracker(initialSeq uint32) *RecvTracker {
	return &RecvTracker{nextExpected: initialSeq}
}

// Receive checks whether seq is new. If new, marks it received and advances
// nextExpected. Returns (isNew, advancedBy).
func (r *RecvTracker) Receive(seq uint32) (isNew bool, advancedBy uint32) {
	diff := int32(seq - r.nextExpected)
	if diff < 0 {
		// Older than window — duplicate.
		return false, 0
	}
	if diff >= 512 {
		// Way ahead — drop as suspicious.
		return false, 0
	}

	wordIdx := diff / 64
	bitIdx := diff % 64
	mask := uint64(1) << bitIdx

	if r.windowBits[wordIdx]&mask != 0 {
		return false, 0 // duplicate
	}
	r.windowBits[wordIdx] |= mask

	// Advance nextExpected as far as consecutive bits are set.
	advanced := uint32(0)
	for r.windowBits[0]&1 != 0 {
		r.shiftWindow()
		r.nextExpected++
		advanced++
	}
	return true, advanced
}

// NextExpected returns the sequence number of the next expected packet.
func (r *RecvTracker) NextExpected() uint32 { return r.nextExpected }

// shiftWindow shifts the 512-bit bitmap right by one bit.
func (r *RecvTracker) shiftWindow() {
	for i := 0; i < 7; i++ {
		carry := r.windowBits[i+1] & 1
		r.windowBits[i] >>= 1
		r.windowBits[i] |= carry << 63
	}
	r.windowBits[7] >>= 1
}
