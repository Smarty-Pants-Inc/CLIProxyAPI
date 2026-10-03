package common

import "errors"

// Limits apply per response before retaining any event, source fragment or call record.
const ApplyPatchMaxRecords = 1024
const applyPatchMaxBytes = 16 << 20
const applyPatchMaxEvents = 131072

type ApplyPatchResourceBudget struct{ bytes, events int }

func (b *ApplyPatchResourceBudget) Accept(size int) error {
	if size < 0 || size > applyPatchMaxBytes-b.bytes || b.events >= applyPatchMaxEvents {
		return errors.New("apply_patch response resource limit exceeded")
	}
	b.bytes += size
	b.events++
	return nil
}
