package events

import (
	"database/sql"
	"testing"

	_ "modernc.org/sqlite"
)

func TestSubscribeAfterReplaysWithoutGap(t *testing.T) {
	bus := &Bus{jobEvents: map[string][]*Event{}, subscribers: map[string][]chan *Event{}, jobSeq: map[string]int64{}, lastErr: map[string]error{}}
	bus.Emit("job-a", New("job-a", "", TypeJobAccepted, LevelInfo, "accepted", nil))
	replay, ch, err := bus.SubscribeAfter("job-a", 0)
	if err != nil {
		t.Fatal(err)
	}
	defer bus.Unsubscribe("job-a", ch)
	if len(replay) != 1 || replay[0].SeqNum != 1 {
		t.Fatalf("unexpected replay: %#v", replay)
	}
	bus.Emit("job-a", New("job-a", "", TypeAssessmentStarted, LevelInfo, "started", nil))
	select {
	case ev := <-ch:
		if ev.SeqNum != 2 {
			t.Fatalf("live sequence = %d, want 2", ev.SeqNum)
		}
	default:
		t.Fatal("event emitted after subscribe was not delivered")
	}
}

func TestPersistentBusSurvivesRestartAndPaginates(t *testing.T) {
	db, err := sql.Open("sqlite", "file:event-store-test?mode=memory&cache=shared")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	db.SetMaxOpenConns(1)
	first, err := NewPersistentBus(db)
	if err != nil {
		t.Fatal(err)
	}
	first.Emit("job-a", New("job-a", "", TypeJobAccepted, LevelInfo, "accepted", nil))
	first.Emit("job-a", New("job-a", "", TypeAssessmentStarted, LevelInfo, "started", nil))
	second, err := NewPersistentBus(db)
	if err != nil {
		t.Fatal(err)
	}
	second.Emit("job-a", New("job-a", "", TypeJobCompleted, LevelSuccess, "complete", nil))
	page, err := second.HistoryAfter("job-a", 1, 1)
	if err != nil {
		t.Fatal(err)
	}
	if len(page) != 1 || page[0].SeqNum != 2 {
		t.Fatalf("first page = %#v", page)
	}
	page, err = second.HistoryAfter("job-a", 2, 1)
	if err != nil {
		t.Fatal(err)
	}
	if len(page) != 1 || page[0].SeqNum != 3 || page[0].EventType != TypeJobCompleted {
		t.Fatalf("second page = %#v", page)
	}
}

func TestPersistentWriteFailureIsNotPublished(t *testing.T) {
	db, err := sql.Open("sqlite", "file:event-store-failure?mode=memory&cache=shared")
	if err != nil {
		t.Fatal(err)
	}
	db.SetMaxOpenConns(1)
	bus, err := NewPersistentBus(db)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`DROP TABLE job_events`); err != nil {
		t.Fatal(err)
	}
	ch := bus.Subscribe("job-a")
	defer bus.Unsubscribe("job-a", ch)
	bus.Emit("job-a", New("job-a", "", TypeJobAccepted, LevelInfo, "accepted", nil))
	if bus.TakeError("job-a") == nil {
		t.Fatal("expected persistence error")
	}
	select {
	case <-ch:
		t.Fatal("event with failed persistence was published")
	default:
	}
}
