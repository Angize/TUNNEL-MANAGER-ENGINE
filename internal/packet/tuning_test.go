package packet

import (
	"reflect"
	"testing"
	"time"
)

// TestApplyTuning checks that non-zero config values override the defaults (clamped to range) while
// zero/empty values leave the compiled-in default untouched. Globals are saved and restored so the
// rest of the package's tests keep seeing the real defaults.
func TestApplyTuning(t *testing.T) {
	save := struct {
		sb                 []int64
		dr, pt, dgw        int64
		dft                int
		im, ims, ssm, ssmn int64
		plt                int32
		ml, pto, fr        time.Duration
	}{suspectBackoff, deadRetest, pinTTL, dataGoodWindow, dataFailThreshold,
		idleMult, idleMinSecs, sessionStaleMult, sessionStaleMinSecs, pingLossThreshold,
		minLiveness, probeTimeout, defaultFluxRotate}
	defer func() {
		suspectBackoff, deadRetest, pinTTL, dataGoodWindow, dataFailThreshold = save.sb, save.dr, save.pt, save.dgw, save.dft
		idleMult, idleMinSecs, sessionStaleMult, sessionStaleMinSecs = save.im, save.ims, save.ssm, save.ssmn
		pingLossThreshold = save.plt
		minLiveness, probeTimeout, defaultFluxRotate = save.ml, save.pto, save.fr
	}()

	// A zero input must be a no-op: every default survives.
	ApplyTuning(TuningInput{})
	if pinTTL != save.pt || deadRetest != save.dr || !reflect.DeepEqual(suspectBackoff, save.sb) {
		t.Fatalf("zero input mutated a default: pinTTL=%d deadRetest=%d backoff=%v", pinTTL, deadRetest, suspectBackoff)
	}

	// Real values apply.
	ApplyTuning(TuningInput{
		SuspectBackoff: []int64{5, 10, 20}, DeadRetestSecs: 900, PinTTLSecs: 45,
		DataFailThreshold: 4, DataGoodWindowSecs: 200, IdleMult: 6, IdleMinSecs: 30,
		SessionStaleMult: 2, SessionStaleMinSecs: 8, PingLossThreshold: 5,
		MinLivenessSecs: 12, ProbeTimeoutSecs: 7,
	})
	if !reflect.DeepEqual(suspectBackoff, []int64{5, 10, 20}) {
		t.Errorf("suspectBackoff=%v", suspectBackoff)
	}
	if deadRetest != 900 || pinTTL != 45 || dataFailThreshold != 4 || dataGoodWindow != 200 {
		t.Errorf("health FSM: deadRetest=%d pinTTL=%d dft=%d dgw=%d", deadRetest, pinTTL, dataFailThreshold, dataGoodWindow)
	}
	if idleMult != 6 || idleMinSecs != 30 || sessionStaleMult != 2 || sessionStaleMinSecs != 8 || pingLossThreshold != 5 {
		t.Errorf("dead-detect: im=%d ims=%d ssm=%d ssmn=%d plt=%d", idleMult, idleMinSecs, sessionStaleMult, sessionStaleMinSecs, pingLossThreshold)
	}
	if minLiveness != 12*time.Second || probeTimeout != 7*time.Second {
		t.Errorf("durations: minLiveness=%v probeTimeout=%v flux=%v", minLiveness, probeTimeout, defaultFluxRotate)
	}
	// idleFor / the stale window now track the tuned multipliers.
	if got := idleFor(10 * time.Second); got != 60*time.Second { // 6×10s=60s, above the 30s floor
		t.Errorf("idleFor(10s)=%v want 60s", got)
	}
	if got := idleFor(2 * time.Second); got != 30*time.Second { // 6×2s=12s -> floored to 30s
		t.Errorf("idleFor(2s)=%v want 30s (floor)", got)
	}

	// Regression: a SHORT custom suspect_backoff must not panic the fixed-index caller (ws_pool used a
	// literal suspectBackoff[2]). suspectStep clamps to the last element instead of indexing out of range.
	ApplyTuning(TuningInput{SuspectBackoff: []int64{7}})
	if got := suspectStep(2); got != 7 { // len==1 -> clamped to [0]
		t.Errorf("suspectStep(2) on a 1-element schedule = %d, want 7 (clamped)", got)
	}
	if got := suspectStep(0); got != 7 {
		t.Errorf("suspectStep(0) = %d, want 7", got)
	}
	ApplyTuning(TuningInput{SuspectBackoff: []int64{5, 10, 20}})
	if got := suspectStep(2); got != 20 {
		t.Errorf("suspectStep(2) = %d, want 20", got)
	}

	// Out-of-range values clamp instead of taking effect verbatim.
	ApplyTuning(TuningInput{PinTTLSecs: 999999, ProbeTimeoutSecs: 999999, DataFailThreshold: -3})
	if pinTTL != 3600 {
		t.Errorf("pinTTL not clamped: %d", pinTTL)
	}
	if probeTimeout != 120*time.Second {
		t.Errorf("probeTimeout not clamped: %v", probeTimeout)
	}
	if dataFailThreshold != 4 { // negative is <=0 -> ignored, keeps the prior applied 4
		t.Errorf("negative dataFailThreshold should be ignored, got %d", dataFailThreshold)
	}
}
