package pluginhost

import (
	"encoding/json"
	"fmt"
)

func (instance *hostCallbackInstance) reserveCallback(id string) bool {
	if instance == nil {
		return true
	}
	instance.admissionMu.Lock()
	defer instance.admissionMu.Unlock()
	if instance.closed.Load() || instance.callbackID != "" || instance.calling {
		return false
	}
	instance.callbackID = id
	return true
}

func (instance *hostCallbackInstance) releaseCallback(id string) {
	if instance == nil {
		return
	}
	instance.admissionMu.Lock()
	defer instance.admissionMu.Unlock()
	if instance.callbackID == id {
		instance.callbackID = ""
	}
}

// ponytail: fail closed instead of pretending selectable native callback handles
// authenticate concurrent invocations. A stream retains its lease until cleanup;
// canceled calls retain the actual native-call lease until the code returns.
func (instance *hostCallbackInstance) beginCall(request []byte) (func(), error) {
	var envelope struct {
		HostCallbackID string `json:"host_callback_id"`
	}
	if len(bytesTrimSpace(request)) > 0 {
		if err := json.Unmarshal(request, &envelope); err != nil {
			return nil, err
		}
	}
	instance.admissionMu.Lock()
	if instance.closed.Load() || instance.calling || instance.callbackID != envelope.HostCallbackID {
		instance.admissionMu.Unlock()
		return nil, fmt.Errorf("native plugin instance already owns another invocation; use a separate instance")
	}
	instance.calling = true
	instance.admissionMu.Unlock()
	return func() { instance.admissionMu.Lock(); instance.calling = false; instance.admissionMu.Unlock() }, nil
}
