// Package scan implements the SpiderFoot-Go scan orchestrator.
package scan

import "errors"

// ErrScanAborted is returned by Start when the scan is cancelled before completion.
var ErrScanAborted = errors.New("scan aborted")

// Status represents the lifecycle state of a scan.
type Status string

// Scan lifecycle constants.
const (
	StatusCreated        Status = "CREATED"
	StatusRunning        Status = "RUNNING"
	StatusFinished       Status = "FINISHED"
	StatusAbortRequested Status = "ABORT-REQUESTED"
	StatusAborted        Status = "ABORTED"
	StatusErrorFailed    Status = "ERROR-FAILED"
)
