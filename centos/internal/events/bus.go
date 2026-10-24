package events

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"sync"
	"time"
)

// EventType constants — emitted at real execution boundaries.
const (
	TypeJobAccepted                = "JOB_ACCEPTED"
	TypeTargetDiscoveryStarted     = "TARGET_DISCOVERY_STARTED"
	TypeTargetDiscoveryCompleted   = "TARGET_DISCOVERY_COMPLETED"
	TypePolicyValidationCompleted  = "POLICY_VALIDATION_COMPLETED"
	TypeAssessmentStarted          = "ASSESSMENT_STARTED"
	TypeControlAssessmentCompleted = "CONTROL_ASSESSMENT_COMPLETED"
	TypeFindingCreated             = "FINDING_CREATED"
	TypePlanGenerated              = "PLAN_GENERATED"
	TypeRiskDecision               = "RISK_DECISION"
	TypeStateCaptureStarted        = "STATE_CAPTURE_STARTED"
	TypeStateCaptureCompleted      = "STATE_CAPTURE_COMPLETED"
	TypeActionStarted              = "ACTION_STARTED"
	TypeActionCompleted            = "ACTION_COMPLETED"
	TypeCommandStarted             = "COMMAND_STARTED"
	TypeCommandCompleted           = "COMMAND_COMPLETED"
	TypeVerificationStarted        = "VERIFICATION_STARTED"
	TypeVerificationCompleted      = "VERIFICATION_COMPLETED"
	TypeRecoveryStarted            = "RECOVERY_STARTED"
	TypeRecoveryCompleted          = "RECOVERY_COMPLETED"
	TypeAuditEventRecorded         = "AUDIT_EVENT_RECORDED"
	TypeJobCompleted               = "JOB_COMPLETED"
	TypeJobFailed                  = "JOB_FAILED"
	TypeJobBlocked                 = "JOB_BLOCKED"
	TypeApprovalRequired           = "APPROVAL_REQUIRED"
)

// Level constants for event severity.
const (
	LevelInfo    = "INFO"
	LevelWarn    = "WARN"
	LevelError   = "ERROR"
	LevelSuccess = "SUCCESS"
)

// Event is a structured lifecycle event emitted by a real operation.
type Event struct {
	EventID    string    `json:"event_id"`
	SeqNum     int64     `json:"sequence_number"`
	Timestamp  time.Time `json:"timestamp"`
	JobID      string    `json:"job_id"`
	ControlID  string    `json:"control_id,omitempty"`
	EventType  string    `json:"event_type"`
	Stage      string    `json:"stage,omitempty"`
	Level      string    `json:"level"`
	Status     string    `json:"status,omitempty"`
	Message    string    `json:"message"`
	Details    any       `json:"details,omitempty"`
	DurationMs int64     `json:"duration_ms,omitempty"`
	ErrorCode  string    `json:"error_code,omitempty"`
}

// Bus persists job events and fans them out to ordered SSE subscribers.
// The in-memory event list is used only by the storage-free test/fallback bus.
type Bus struct {
	mu          sync.RWMutex
	jobEvents   map[string][]*Event      // job_id → ordered events
	subscribers map[string][]chan *Event // job_id → subscriber channels
	jobSeq      map[string]int64
	db          *sql.DB
	lastErr     map[string]error
}

var GlobalBus = &Bus{
	jobEvents:   make(map[string][]*Event),
	subscribers: make(map[string][]chan *Event),
	jobSeq:      make(map[string]int64),
	lastErr:     make(map[string]error),
}

// NewPersistentBus stores each event before publishing it to subscribers.
// SQLite provides durable per-job ordering across process restarts.
func NewPersistentBus(db *sql.DB) (*Bus, error) {
	if db == nil {
		return nil, fmt.Errorf("event database is nil")
	}
	if _, err := db.Exec(`CREATE TABLE IF NOT EXISTS job_events (
		job_id TEXT NOT NULL,
		sequence_number INTEGER NOT NULL,
		event_id TEXT NOT NULL UNIQUE,
		event_json TEXT NOT NULL,
		created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
		PRIMARY KEY (job_id, sequence_number)
	)`); err != nil {
		return nil, fmt.Errorf("create job_events table: %w", err)
	}
	if _, err := db.Exec(`DELETE FROM job_events WHERE created_at < datetime('now', '-90 days')`); err != nil {
		return nil, fmt.Errorf("apply event retention: %w", err)
	}
	bus := &Bus{jobEvents: make(map[string][]*Event), subscribers: make(map[string][]chan *Event), jobSeq: make(map[string]int64), lastErr: make(map[string]error), db: db}
	rows, err := db.Query(`SELECT job_id, MAX(sequence_number) FROM job_events GROUP BY job_id`)
	if err != nil {
		return nil, fmt.Errorf("load event sequence state: %w", err)
	}
	defer rows.Close()
	for rows.Next() {
		var jobID string
		var seq int64
		if err := rows.Scan(&jobID, &seq); err != nil {
			return nil, err
		}
		bus.jobSeq[jobID] = seq
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return bus, nil
}

// LastError reports the latest persistence failure. A failed write is not
// published to live subscribers or treated as a durable event.
func (b *Bus) LastError(jobID string) error {
	b.mu.RLock()
	defer b.mu.RUnlock()
	return b.lastErr[jobID]
}

// TakeError returns and clears the most recent persistence failure so the
// operation handler can avoid reporting success when its event trail failed.
func (b *Bus) TakeError(jobID string) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	err := b.lastErr[jobID]
	delete(b.lastErr, jobID)
	return err
}

// Emit records an event and fans it out to all current SSE subscribers for that job.
func (b *Bus) Emit(jobID string, ev *Event) {
	b.mu.Lock()
	defer b.mu.Unlock()

	seq := b.jobSeq[jobID] + 1
	ev.SeqNum = seq
	if ev.Timestamp.IsZero() {
		ev.Timestamp = time.Now()
	}
	// The sequence is unique within a job and produces stable SSE IDs across
	// restarts; avoid timestamp-based IDs that can collide at clock resolution.
	ev.EventID = fmt.Sprintf("%s-%d", jobID, seq)
	if b.db != nil {
		payload, err := json.Marshal(ev)
		if err == nil {
			_, err = b.db.Exec(`INSERT INTO job_events(job_id, sequence_number, event_id, event_json) VALUES (?, ?, ?, ?)`, jobID, seq, ev.EventID, string(payload))
		}
		if err != nil {
			b.lastErr[jobID] = err
			return
		}
	}
	b.jobSeq[jobID] = seq

	if b.db == nil {
		b.jobEvents[jobID] = append(b.jobEvents[jobID], ev)
	}

	subs := b.subscribers[jobID]
	kept := subs[:0]
	for _, ch := range subs {
		// Non-blocking send — slow clients don't block the operation.
		select {
		case ch <- ev:
			kept = append(kept, ch)
		default:
			// Disconnect a slow subscriber so it can reconnect and replay from
			// durable history using Last-Event-ID.
			close(ch)
		}
	}
	b.subscribers[jobID] = kept
}

// History returns all stored events for a job in order.
func (b *Bus) History(jobID string) []*Event {
	b.mu.RLock()
	defer b.mu.RUnlock()
	if b.db != nil {
		evs, err := b.historyLocked(jobID, 0, 500)
		if err == nil {
			return evs
		}
		return nil
	}
	evs := b.jobEvents[jobID]
	out := make([]*Event, len(evs))
	copy(out, evs)
	return out
}

// HistoryAfter returns a bounded, ordered page of events with sequence numbers
// greater than after. The returned cursor can be used for the next page.
func (b *Bus) HistoryAfter(jobID string, after int64, limit int) ([]*Event, error) {
	if limit < 1 || limit > 500 {
		limit = 200
	}
	b.mu.RLock()
	defer b.mu.RUnlock()
	if b.db != nil {
		return b.historyLocked(jobID, after, limit)
	}
	out := make([]*Event, 0, limit)
	for _, ev := range b.jobEvents[jobID] {
		if ev.SeqNum > after && len(out) < limit {
			copyEvent := *ev
			out = append(out, &copyEvent)
		}
	}
	return out, nil
}

func (b *Bus) historyLocked(jobID string, after int64, limit int) ([]*Event, error) {
	rows, err := b.db.Query(`SELECT event_json FROM job_events WHERE job_id = ? AND sequence_number > ? ORDER BY sequence_number LIMIT ?`, jobID, after, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := make([]*Event, 0)
	for rows.Next() {
		var raw string
		var ev Event
		if err := rows.Scan(&raw); err != nil {
			return nil, err
		}
		if err := json.Unmarshal([]byte(raw), &ev); err != nil {
			return nil, err
		}
		out = append(out, &ev)
	}
	return out, rows.Err()
}

// Subscribe registers a channel to receive new events for a job.
// The caller must call Unsubscribe when done.
func (b *Bus) Subscribe(jobID string) chan *Event {
	ch := make(chan *Event, 64)
	b.mu.Lock()
	b.subscribers[jobID] = append(b.subscribers[jobID], ch)
	b.mu.Unlock()
	return ch
}

// SubscribeAfter atomically captures the replay and registers the live channel,
// closing the history-to-subscription race. EventSource's Last-Event-ID is a
// per-job sequence number and is passed as after.
func (b *Bus) SubscribeAfter(jobID string, after int64) ([]*Event, chan *Event, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	var replay []*Event
	var err error
	if b.db != nil {
		cursor := after
		for {
			var page []*Event
			page, err = b.historyLocked(jobID, cursor, 500)
			if err != nil {
				break
			}
			replay = append(replay, page...)
			if len(page) < 500 {
				break
			}
			cursor = page[len(page)-1].SeqNum
		}
	} else {
		for _, ev := range b.jobEvents[jobID] {
			if ev.SeqNum > after {
				copyEvent := *ev
				replay = append(replay, &copyEvent)
			}
		}
	}
	if err != nil {
		return nil, nil, err
	}
	ch := make(chan *Event, 128)
	b.subscribers[jobID] = append(b.subscribers[jobID], ch)
	return replay, ch, nil
}

// Unsubscribe removes and closes a subscriber channel.
func (b *Bus) Unsubscribe(jobID string, ch chan *Event) {
	b.mu.Lock()
	defer b.mu.Unlock()
	subs := b.subscribers[jobID]
	for i, s := range subs {
		if s == ch {
			b.subscribers[jobID] = append(subs[:i], subs[i+1:]...)
			close(ch)
			return
		}
	}
}

// SSEHandler streams job events as text/event-stream to the browser.
// It first replays historical events then streams new ones.
// Usage: GET /api/events/stream?job=<job_id>
func SSEHandler(w http.ResponseWriter, r *http.Request) {
	jobID := r.URL.Query().Get("job")
	if jobID == "" {
		http.Error(w, "job parameter required", http.StatusBadRequest)
		return
	}

	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.Header().Set("X-Accel-Buffering", "no")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "streaming not supported", http.StatusInternalServerError)
		return
	}
	// Reconnect from the last delivered per-job sequence, and register before
	// releasing the bus lock so no event can fall between replay and live mode.
	var after int64
	if raw := r.Header.Get("Last-Event-ID"); raw != "" {
		if parsed, err := strconv.ParseInt(raw, 10, 64); err == nil && parsed > 0 {
			after = parsed
		}
	}
	replay, ch, err := GlobalBus.SubscribeAfter(jobID, after)
	if err != nil {
		http.Error(w, "event history unavailable", http.StatusInternalServerError)
		return
	}
	fmt.Fprint(w, "retry: 3000\n\n")
	flusher.Flush()
	for _, ev := range replay {
		writeSSEEvent(w, ev)
		flusher.Flush()
	}
	defer GlobalBus.Unsubscribe(jobID, ch)

	// Heartbeat ticker to keep the connection alive.
	heartbeat := time.NewTicker(15 * time.Second)
	defer heartbeat.Stop()

	for {
		select {
		case <-r.Context().Done():
			return
		case ev, ok := <-ch:
			if !ok {
				return
			}
			writeSSEEvent(w, ev)
			flusher.Flush()
		case <-heartbeat.C:
			fmt.Fprintf(w, ": heartbeat\n\n")
			flusher.Flush()
		}
	}
}

func writeSSEEvent(w http.ResponseWriter, ev *Event) {
	data, _ := json.Marshal(ev)
	fmt.Fprintf(w, "id: %d\nevent: job_event\ndata: %s\n\n", ev.SeqNum, data)
}

// Convenience constructor.
func New(jobID, controlID, eventType, level, message string, details any) *Event {
	return &Event{
		EventID:   fmt.Sprintf("%s-%d", jobID, time.Now().UnixNano()),
		JobID:     jobID,
		ControlID: controlID,
		EventType: eventType,
		Level:     level,
		Message:   message,
		Details:   details,
		Timestamp: time.Now(),
	}
}
