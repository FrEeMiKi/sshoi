package tunnel

import (
	"testing"
	"time"
)

func TestSendQueue_EnqueueAck(t *testing.T) {
	q := NewSendQueue(0, 10)

	wire := []byte("pkt")
	seq, err := q.Enqueue(wire)
	if err != nil {
		t.Fatalf("Enqueue: %v", err)
	}
	if seq != 0 {
		t.Errorf("expected seq 0, got %d", seq)
	}
	if q.InFlight() != 1 {
		t.Errorf("expected 1 in-flight, got %d", q.InFlight())
	}

	q.Enqueue(wire)
	q.Enqueue(wire)
	if q.InFlight() != 3 {
		t.Errorf("expected 3 in-flight")
	}

	removed := q.Acknowledge(1)
	if removed != 2 {
		t.Errorf("expected 2 removed, got %d", removed)
	}
	if q.InFlight() != 1 {
		t.Errorf("expected 1 in-flight after ack")
	}
}

func TestSendQueue_WindowFull(t *testing.T) {
	q := NewSendQueue(0, 3)
	wire := []byte("x")
	q.Enqueue(wire)
	q.Enqueue(wire)
	q.Enqueue(wire)
	_, err := q.Enqueue(wire)
	if err != ErrWindowFull {
		t.Errorf("expected ErrWindowFull, got %v", err)
	}
}

func TestSendQueue_TimedOut(t *testing.T) {
	q := NewSendQueue(0, 10)
	wire := []byte("x")
	q.Enqueue(wire)

	// No timeout yet.
	if len(q.TimedOut(100*time.Millisecond)) != 0 {
		t.Error("expected no timed-out entries")
	}

	// Backdate SentAt.
	q.entries[0].SentAt = time.Now().Add(-200 * time.Millisecond)

	if len(q.TimedOut(100*time.Millisecond)) != 1 {
		t.Error("expected one timed-out entry")
	}
}

func TestRecvTracker_Basic(t *testing.T) {
	r := NewRecvTracker(0)

	isNew, _ := r.Receive(0)
	if !isNew {
		t.Error("seq 0 should be new")
	}
	if r.NextExpected() != 1 {
		t.Errorf("expected NextExpected=1, got %d", r.NextExpected())
	}

	// Duplicate.
	isNew, _ = r.Receive(0)
	if isNew {
		t.Error("seq 0 should be duplicate")
	}
}

func TestRecvTracker_OutOfOrder(t *testing.T) {
	r := NewRecvTracker(0)

	// Receive 1 before 0.
	isNew, adv := r.Receive(1)
	if !isNew {
		t.Error("seq 1 should be new")
	}
	if adv != 0 {
		t.Errorf("no advance expected yet, got %d", adv)
	}
	if r.NextExpected() != 0 {
		t.Errorf("NextExpected should still be 0, got %d", r.NextExpected())
	}

	// Now receive 0 — should advance to 2.
	isNew, adv = r.Receive(0)
	if !isNew {
		t.Error("seq 0 should be new")
	}
	if r.NextExpected() != 2 {
		t.Errorf("expected NextExpected=2, got %d", r.NextExpected())
	}
	_ = adv
}

func TestRecvTracker_Wrap(t *testing.T) {
	r := NewRecvTracker(0xFFFFFFFE)
	isNew, _ := r.Receive(0xFFFFFFFE)
	if !isNew {
		t.Error("should be new")
	}
	isNew, _ = r.Receive(0xFFFFFFFF)
	if !isNew {
		t.Error("should be new")
	}
	// 0xFFFFFFFF+1 wraps to 0
	if r.NextExpected() != 0 {
		t.Errorf("expected wrap to 0, got %d", r.NextExpected())
	}
}
