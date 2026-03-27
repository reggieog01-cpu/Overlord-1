package main

import (
	"encoding/json"
	"sync"
	"time"
)

type HostInfo struct {
	ClientID string `json:"clientId"`
	OS       string `json:"os"`
	Arch     string `json:"arch"`
	Version  string `json:"version"`
}

// EntryView is serialised to the UI — no kill metadata.
type EntryView struct {
	ID       string   `json:"id"`
	Type     string   `json:"type"`     // run_key | startup_file | scheduled_task | service | winlogon | ifeo | appinit | lsa | boot_execute | wmi
	Name     string   `json:"name"`
	Command  string   `json:"command"`
	BinPath  string   `json:"binPath"`
	Location string   `json:"location"`
	Risk     string   `json:"risk"`    // high | medium | low
	Reasons  []string `json:"reasons"`
	Killed   bool     `json:"killed"`
}

// PersistenceEntry adds kill metadata fields (never serialised — json:"-").
type PersistenceEntry struct {
	EntryView
	KillRegRoot  string `json:"-"`
	KillRegPath  string `json:"-"`
	KillRegValue string `json:"-"`
	KillFilePath string `json:"-"`
	KillTaskName string `json:"-"`
	KillSvcName  string `json:"-"`
	KillWMIName  string `json:"-"`
}

type ScanResult struct {
	Entries   []PersistenceEntry `json:"entries"`
	Total     int                `json:"total"`
	HighCount int                `json:"highCount"`
	MedCount  int                `json:"medCount"`
	LowCount  int                `json:"lowCount"`
	ScannedAt string             `json:"scannedAt"`
	Errors    []string           `json:"errors,omitempty"`
}

type KillRequest struct {
	IDs []string `json:"ids"`
}

type KillResult struct {
	Killed []string   `json:"killed"`
	Failed []KillFail `json:"failed,omitempty"`
}

type KillFail struct {
	ID    string `json:"id"`
	Name  string `json:"name"`
	Error string `json:"error"`
}

var (
	hostInfo HostInfo
	sendFn   func(event string, payload []byte)
	mu       sync.Mutex
	lastScan map[string]PersistenceEntry
)

func setSend(fn func(event string, payload []byte)) {
	mu.Lock()
	sendFn = fn
	mu.Unlock()
}

func sendEvent(event string, payload interface{}) {
	mu.Lock()
	fn := sendFn
	mu.Unlock()
	if fn == nil {
		return
	}
	data, err := json.Marshal(payload)
	if err != nil {
		return
	}
	fn(event, data)
}

func handleInit(hostJSON []byte) error {
	if err := json.Unmarshal(hostJSON, &hostInfo); err != nil {
		return err
	}
	sendEvent("ready", map[string]string{"message": "bot-killer plugin ready"})
	go func() {
		result := performScan()
		sendEvent("scan_result", result)
	}()
	return nil
}

func handleEvent(event string, payload []byte) error {
	switch event {
	case "scan":
		go func() {
			result := performScan()
			sendEvent("scan_result", result)
		}()
	case "kill":
		var req KillRequest
		if err := json.Unmarshal(payload, &req); err != nil {
			return err
		}
		go func() {
			result := killEntries(req.IDs)
			sendEvent("kill_result", result)
		}()
	}
	return nil
}

func handleUnload() {}

func performScan() ScanResult {
	entries, errors := scanAll()

	m := make(map[string]PersistenceEntry, len(entries))
	for _, e := range entries {
		m[e.ID] = e
	}
	mu.Lock()
	lastScan = m
	mu.Unlock()

	var high, med, low int
	for _, e := range entries {
		switch e.Risk {
		case "high":
			high++
		case "medium":
			med++
		default:
			low++
		}
	}

	if entries == nil {
		entries = []PersistenceEntry{}
	}

	return ScanResult{
		Entries:   entries,
		Total:     len(entries),
		HighCount: high,
		MedCount:  med,
		LowCount:  low,
		ScannedAt: time.Now().UTC().Format(time.RFC3339),
		Errors:    errors,
	}
}
