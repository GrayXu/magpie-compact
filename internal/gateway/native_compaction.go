package gateway

// Native compaction is passed through unchanged on Responses. Its sealed
// context follows the ordinary route across accounts, providers and
// clients; the destination upstream decides whether it can read it.

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/tidwall/gjson"
	"github.com/yetone/magpie/internal/edit"
	"github.com/yetone/magpie/internal/provider"
	"github.com/yetone/magpie/internal/steady"
)

const (
	// checkpointKeep is how long who sealed a compaction is remembered: a
	// conversation goes on from its compaction for days.
	checkpointKeep = 30 * 24 * time.Hour
	// checkpointsKept is how many compactions, the latest, are kept.
	checkpointsKept = 1024
)

// compactionTriggerIn says whether a Responses request's input holds
// Codex's compaction_trigger.
func compactionTriggerIn(body []byte) bool {
	if !bytes.Contains(body, []byte(`"compaction_trigger"`)) {
		return false
	}
	for _, it := range getIn(body, "input").Array() {
		if it.Get("type").Str == "compaction_trigger" {
			return true
		}
	}
	return false
}

// sealedCompactions are the encrypted_content of the compaction items in
// a Responses request's input that a vendor sealed: magpie's own
// ("magpie1:") are text by the time a request is sent, and aren't.
func sealedCompactions(body []byte) []string {
	if !bytes.Contains(body, []byte(`"compaction`)) {
		return nil
	}
	var out []string
	for _, it := range getIn(body, "input").Array() {
		if !slices.Contains(compactionKinds, it.Get("type").Str) {
			continue
		}
		if enc := it.Get("encrypted_content").Str; enc != "" && !strings.HasPrefix(enc, magpieCompaction) {
			out = append(out, enc)
		}
	}
	return out
}

// carriesCompaction is whether c's provider can be asked Codex's own
// compaction for model: its wire carries it, and model is asked on
// Responses there.
func (s *Server) carriesCompaction(p provider.Provider, model string) bool {
	return p.CarriesCompaction() && slices.Contains(s.usable(p, model), provider.Responses)
}

// compactsNatively is whether a Codex compaction for model at p goes to it
// as Codex sent it (provider.Provider.CompactsOn).
func (s *Server) compactsNatively(p provider.Provider, model string) bool {
	return p.CompactsOn(model) && s.carriesCompaction(p, model)
}

// nativeCompactionFor is whether Codex's compaction_trigger for the model
// it asked (a provider's model, or a routing group) goes on as Codex sent
// it: every member of a group compacting natively, as any of them may
// answer it, and a key or account the request would go over able to be
// asked it (plannedCarrier, #2725). A group with one that doesn't keeps
// magpie's summary, which any member can read; so does a provider whose
// vendor lists the model only to keys that speak no Responses there, as
// with native compaction off, where the trigger was refused before.
func (s *Server) nativeCompactionFor(asked string) bool {
	if _, ms, ok := provider.FindGroup(asked); ok {
		if len(ms) == 0 {
			return false
		}
		for _, m := range ms {
			if !s.compactsNatively(m.Provider, m.Model) {
				return false
			}
		}
		return slices.ContainsFunc(ms, func(m provider.Member) bool { return s.plannedCarrier(m.Provider, m.Model) })
	}
	p, model, ok := provider.Resolve(asked)
	if !ok || !s.compactsNatively(p, model) {
		return false
	}
	// the request goes over the provider's keys, then its fallbacks' (plan)
	if s.plannedCarrier(p, model) {
		return true
	}
	for _, m := range provider.FallbackModels(p) {
		if (m.Provider.ID != p.ID || m.Model != model) && s.plannedCarrier(m.Provider, m.Model) {
			return true
		}
	}
	return false
}

// plannedCarrier is whether one of the keys or accounts plan would put in
// a Responses request's candidates for model at p — those it goes over,
// those made for another protocol, and the held and capped ones, not those
// whose own list lacks the model — can be asked Codex's compaction, as
// compactionCarriers keeps them. It reads perKeyBarred alone, not plan:
// a plan weighs the keys, and a provider routed in turn would move its
// turn along for a request that never went (every Codex turn is decided).
func (s *Server) plannedCarrier(p provider.Provider, model string) bool {
	cs, aside, _, barred := perKeyBarred(p, model, provider.Responses)
	for _, l := range [][]candidate{cs, aside, creditsHeld(barred), capHeldOnly(barred)} {
		if slices.ContainsFunc(l, func(c candidate) bool { return s.carriesCompaction(c.p, c.model) }) {
			return true
		}
	}
	return false
}

// keepsCompaction says whether a Responses request needs its native
// compaction preserved, including one produced by another provider or
// client. Translating it would silently lose the earlier context.
func keepsCompaction(from provider.Protocol, body []byte) bool {
	return from == provider.Responses && (compactionTriggerIn(body) || len(sealedCompactions(body)) > 0)
}

// checkpointWriter is who sealed a compaction: the key or account
// (candidate.who), its provider and the model it answered as.
type checkpointWriter struct {
	Who      string    `json:"who"`
	Provider string    `json:"provider"`
	Model    string    `json:"model,omitempty"`
	At       time.Time `json:"at"`
}

var checkpoints = struct {
	sync.Mutex
	m map[string]checkpointWriter // hex sha256 of encrypted_content → who wrote it
	// the file as last read or written
	from string
	mod  time.Time
}{m: map[string]checkpointWriter{}}

var checkpointsSaving sync.Mutex

func checkpointsPath() string {
	return filepath.Join(filepath.Dir(provider.Path()), "compactions.json")
}

func checkpointKey(enc string) string {
	h := sha256.Sum256([]byte(enc))
	return hex.EncodeToString(h[:])
}

// checkpointFor is who sealed the compaction enc, read from the file
// again when it isn't known here and the file changed since. Called with
// checkpoints held.
func checkpointFor(enc string) (checkpointWriter, bool) {
	path := checkpointsPath()
	if path != checkpoints.from && checkpoints.from != "" {
		// another home (a test's): what was known is of the other's
		checkpoints.m = map[string]checkpointWriter{}
		checkpoints.mod = time.Time{}
	}
	k := checkpointKey(enc)
	if cp, ok := checkpoints.m[k]; ok && time.Since(cp.At) <= checkpointKeep {
		return cp, true
	}
	fi, err := os.Stat(path)
	if err != nil || path == checkpoints.from && fi.ModTime().Equal(checkpoints.mod) {
		checkpoints.from = path
		return checkpointWriter{}, false
	}
	checkpoints.from, checkpoints.mod = path, fi.ModTime()
	b, err := os.ReadFile(path)
	if err != nil {
		return checkpointWriter{}, false
	}
	var saved map[string]checkpointWriter
	if decodeJSON(b, &saved) != nil {
		return checkpointWriter{}, false
	}
	for sk, v := range saved {
		if v.Who == "" || time.Since(v.At) > checkpointKeep {
			continue
		}
		if had, ok := checkpoints.m[sk]; ok && !had.At.Before(v.At) {
			continue
		}
		checkpoints.m[sk] = v
	}
	cp, ok := checkpoints.m[k]
	return cp, ok
}

// checkpointOf is who sealed the latest compaction in a Responses
// request's input that magpie knows the writer of.
func checkpointOf(body []byte) (checkpointWriter, bool) {
	encs := sealedCompactions(body)
	if len(encs) == 0 {
		return checkpointWriter{}, false
	}
	checkpoints.Lock()
	defer checkpoints.Unlock()
	for _, enc := range slices.Backward(encs) {
		if cp, ok := checkpointFor(enc); ok {
			return cp, true
		}
	}
	return checkpointWriter{}, false
}

// wroteCheckpoint remembers that c sealed the compaction enc.
func wroteCheckpoint(enc string, c candidate) {
	now := time.Now()
	checkpoints.Lock()
	checkpointFor(enc) // the file's, read in first so the write keeps them
	checkpoints.m[checkpointKey(enc)] = checkpointWriter{Who: c.who(), Provider: c.p.ID, Model: c.model, At: now}
	checkpoints.Unlock()
	saveCheckpoints()
}

// saveCheckpoints writes the latest compactions' writers to the file,
// only for this user to read.
func saveCheckpoints() {
	checkpointsSaving.Lock()
	defer checkpointsSaving.Unlock()
	type kept struct {
		k string
		v checkpointWriter
	}
	var ks []kept
	checkpoints.Lock()
	for k, v := range checkpoints.m {
		if time.Since(v.At) <= checkpointKeep {
			ks = append(ks, kept{k, v})
		}
	}
	checkpoints.Unlock()
	slices.SortFunc(ks, func(a, b kept) int { return b.v.At.Compare(a.v.At) })
	ks = ks[:min(len(ks), checkpointsKept)]
	out := make(map[string]checkpointWriter, len(ks))
	for _, k := range ks {
		out[k.k] = k.v
	}
	b, err := json.Marshal(out)
	if err != nil {
		return
	}
	path := checkpointsPath()
	if os.MkdirAll(filepath.Dir(path), 0o700) != nil {
		return
	}
	target, err := edit.Target(path) // a symlink stays, its target written
	if err != nil {
		return
	}
	tmp := target + ".magpie-tmp"
	if os.WriteFile(tmp, b, 0o600) != nil {
		return
	}
	if steady.Rename(tmp, target) != nil {
		os.Remove(tmp)
		return
	}
	if fi, err := os.Stat(path); err == nil {
		checkpoints.Lock()
		// what this magpie wrote isn't read back as another's
		checkpoints.from, checkpoints.mod = path, fi.ModTime()
		checkpoints.Unlock()
	}
}

// compactionCarriers keeps candidates whose Responses API can carry the
// trigger or sealed context, without binding it to its original writer.
func (s *Server) compactionCarriers(cands []candidate, pl planned) (_ []candidate, _ planned, left bool) {
	return keepCandidates(cands, pl, func(c candidate) bool { return s.carriesCompaction(c.p, c.model) })
}

func keepCandidates(cands []candidate, pl planned, keep func(candidate) bool) ([]candidate, planned, bool) {
	var kept []candidate
	var order []Weighed
	for i, c := range cands {
		if keep(c) {
			kept = append(kept, c)
			if i < len(pl.order) {
				order = append(order, pl.order[i])
			}
		}
	}
	cands, pl.order = kept, order
	pl.held = slices.DeleteFunc(slices.Clone(pl.held), func(c candidate) bool { return !keep(c) })
	pl.capped = slices.DeleteFunc(slices.Clone(pl.capped), func(c candidate) bool { return !keep(c) })
	return cands, pl, len(cands) > 0 || len(pl.held) > 0 || len(pl.capped) > 0
}

// carrierError explains why a request carrying native compaction cannot
// use the chosen route without losing its earlier context.
func carrierError(model string) string {
	return fmt.Sprintf("The request for %s carries native compaction, but none of its available keys or accounts can carry it on the Responses API. Choose a provider and model with a Responses API, or start a new conversation using magpie's summaries.", model)
}

// compactionWatch reads, on the way past, the compaction a native
// compaction request's reply seals, for wroteCheckpoint.
type compactionWatch struct {
	w    http.ResponseWriter
	buf  bytes.Buffer
	over bool
}

// compactionWatchMax is how much of a reply is read for its compaction.
const compactionWatchMax = 64 << 20

func (c *compactionWatch) Header() http.Header         { return c.w.Header() }
func (c *compactionWatch) WriteHeader(code int)        { c.w.WriteHeader(code) }
func (c *compactionWatch) Unwrap() http.ResponseWriter { return c.w }

func (c *compactionWatch) Write(p []byte) (int, error) {
	if !c.over {
		if c.buf.Len()+len(p) > compactionWatchMax {
			c.over = true
			c.buf = bytes.Buffer{}
		} else {
			c.buf.Write(p)
		}
	}
	return c.w.Write(p)
}

func (c *compactionWatch) Flush() {
	if f, ok := c.w.(http.Flusher); ok {
		f.Flush()
	}
}

// sealed is the encrypted_content of the last compaction item the reply
// gave: in a stream's output_item.done or response.completed, or a JSON
// body's output.
func (c *compactionWatch) sealed() string {
	b := bytes.TrimSpace(c.buf.Bytes())
	if len(b) == 0 {
		return ""
	}
	found := ""
	fromItems := func(items []gjson.Result) {
		for _, it := range items {
			if slices.Contains(compactionKinds, it.Get("type").Str) {
				if enc := it.Get("encrypted_content").Str; enc != "" && !strings.HasPrefix(enc, magpieCompaction) {
					found = enc
				}
			}
		}
	}
	if b[0] == '{' {
		fromItems(gjson.GetBytes(b, "output").Array())
		return found
	}
	for line := range bytes.SplitSeq(b, []byte("\n")) {
		data, ok := bytes.CutPrefix(bytes.TrimSpace(line), []byte("data:"))
		if !ok || !bytes.Contains(data, []byte(`"compaction`)) {
			continue
		}
		ev := gjson.ParseBytes(bytes.TrimSpace(data))
		if it := ev.Get("item"); it.Exists() {
			fromItems([]gjson.Result{it})
		}
		fromItems(ev.Get("response.output").Array())
	}
	return found
}
