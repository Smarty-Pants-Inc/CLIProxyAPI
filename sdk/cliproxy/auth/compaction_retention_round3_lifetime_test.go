package auth

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	core "github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/executor"
)

func TestCompactionRetentionRound3CapturedOriginReloadNoHook(t *testing.T) {
	for _, path := range []string{"execute", "stream"} {
		t.Run(path, func(t *testing.T) {
			a, b, model := t.Name()+"-A", t.Name()+"-B", "retention-reload-model"
			origin := NewSessionAffinitySelector(&compactionAffinityFallback{preferredID:a})
			defer origin.Stop()
			origin.Cache().Stop()
			e := &compactionAffinityExecutor{provider:"codex", firstID:a,
				output:[]byte(`{"output":[{"type":"compaction","encrypted_content":"signed-block"}]}`),
				streamOutput:[][]byte{[]byte("data: {\"type\":\"response.output_item.done\",\"item\":{\"type\":\"compaction\",\"encrypted_content\":\"signed-block\"}}\n\n")},
			}
			m := newCompactionAffinityManager(t,origin,e,model,b)
			req, opts := compactionAffinityRequest(model,"none",false,false)
			if err := runCompactionAffinityRequest(t,m,e,path,req,opts); err != nil { t.Fatal(err) }
			e.output,e.streamOutput = nil,nil
			req, opts = compactionAffinityRequest(model,"none",true,false)
			var err error
			opts,err = m.PrepareCompactionRequest(model,opts,context.Background())
			if err != nil { t.Fatal(err) }
			before := round3ShiftSignerExpiry(t,origin,opts.OriginalRequest,-5*time.Hour)
			// Selection no longer runs through the origin's Pick. Only the
			// final actual-account nil-hook dispatch gate can renew evidence.
			m.SetSelector(&compactionAffinityFallback{preferredID:a})
			if err := runCompactionAffinityRequest(t,m,e,path,req,opts); err != nil { t.Fatal(err) }
			for key,expiry := range before { if !round3SignerExpiry(t,origin,key).After(expiry) { t.Fatal("captured origin lost retention after selector reload") } }
			// Reusing these public options is another admission, not an old
			// selection receipt. Ordinary output still contains no capsule.
			round3ShiftSignerExpiry(t,origin,opts.OriginalRequest,-2*time.Hour)
			if err := runCompactionAffinityRequest(t,m,e,path,req,opts); err != nil { t.Fatal(err) }
			assertCompactionAffinityOnlyA(t,e,false)
		})
	}
}

func TestCompactionRetentionRound3ReceiptClonesCancellationAndRetry(t *testing.T) {
	origin, dir := populatedCompactionPublicationSelector(t)
	origin.Cache().Stop()
	blocks := publicationCompactionBlocks(32)
	if err := origin.RecordCompactionOutput("A",core.Options{},[]byte(`{"output":[`+blocks+`]}`)); err != nil { t.Fatal(err) }
	m := NewManager(nil,origin,nil)
	opts,err := m.PrepareCompactionRequest("model",core.Options{OriginalRequest:[]byte(`{"input":[`+blocks+`]}`)},context.Background())
	if err != nil { t.Fatal(err) }
	if _,err := origin.Pick(context.Background(),"codex","model",opts,[]*Auth{{ID:"A"}}); err != nil { t.Fatal(err) }
	clone := func() core.Options {
		copy := opts
		copy.Metadata = make(map[string]any,len(opts.Metadata))
		for key,value := range opts.Metadata { copy.Metadata[key]=value }
		return copy
	}
	// Two attempt-local metadata clones cannot each claim the same receipt.
	count := watchCompactionPublications(t,dir)
	errors := make(chan error,2)
	for i:=0;i<2;i++ {
		copy := clone()
		go func() { errors <- validateCompactionSelectedAuth(context.Background(),"A",copy) }()
	}
	for i:=0;i<2;i++ { if err := <-errors; err != nil { t.Fatal(err) } }
	if publications := count(); publications!=1 { t.Fatalf("two cloned dispatches made %d publications after selection; want one one-use receipt plus one fresh admission",publications) }
	// A subsequent admission with the same original options must renew again.
	before := round3ShiftSignerExpiry(t,origin,opts.OriginalRequest,-time.Hour)
	if err := validateCompactionSelectedAuth(context.Background(),"A",opts); err != nil { t.Fatal(err) }
	for key,expiry := range before { if !round3SignerExpiry(t,origin,key).After(expiry) { t.Fatal("consumed receipt suppressed later admission") } }
	// Cancellation cannot be hidden by a newly installed cached receipt.
	ctx,cancel := context.WithCancel(context.Background())
	cancelOpts,err := m.PrepareCompactionRequest("model",clone(),ctx)
	if err != nil { t.Fatal(err) }
	if _,err := origin.Pick(ctx,"codex","model",cancelOpts,[]*Auth{{ID:"A"}}); err != nil { t.Fatal(err) }
	before=round3ShiftSignerExpiry(t,origin,opts.OriginalRequest,0)
	statePath:=filepath.Join(dir,"affinity.state")
	state,err:=os.ReadFile(statePath)
	if err!=nil { t.Fatal(err) }
	cancel()
	if err:=validateCompactionSelectedAuth(ctx,"A",cancelOpts); err==nil { t.Fatal("canceled receipt accepted") }
	for key,expiry:=range before { if !round3SignerExpiry(t,origin,key).Equal(expiry) { t.Fatal("canceled receipt refreshed signer") } }
	after,err:=os.ReadFile(statePath)
	if err!=nil || string(state)!=string(after) { t.Fatal("canceled receipt published state") }
}
