// liveview — a tiny terminal-to-browser bridge for the OWASP ASI scanner.
//
// It does NOT change the scanner. It spawns your EXISTING demo commands
// (demo\run_anythingllm_demo.ps1 / demo\run_odysseus_demo.ps1) exactly as you
// run them in the terminal, captures their live output, and streams it to a
// browser via Server-Sent Events rendered with xterm.js.
//
// Stdlib only — `go build` works offline, produces a single liveview.exe.
//
// Run from the Security_module folder:
//   go run ./liveview                 # dev
//   go build -o liveview.exe ./liveview && .\liveview.exe   # binary
// then open http://127.0.0.1:8080
//
// Tokens: read from env ANYTHINGLLM_TOKEN / ODYSSEUS_TOKEN, else the baked
// demo defaults, else whatever you type in the browser.
package main

import (
	"bufio"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"time"
)

// ---- config ---------------------------------------------------------------

const (
	defaultAnythingLLMToken = "4NJ570K-T3N48A3-J8B8FE0-WXBKJ6K"
	defaultOdysseusToken    = "ody_CoYk9ja7LDNmNCLTfEkl_3Nvz7TimsP3caJOoeexmi4"
)

type agentDef struct {
	Label     string
	Target    string // host:port for the reachability dot
	TokenEnv  string
	TokenDef  string
	Script    string // relative to repo root
	TokenFlag string // -ApiKey or -Token
}

var agents = map[string]agentDef{
	"anythingllm": {
		Label: "AnythingLLM", Target: "127.0.0.1:3001",
		TokenEnv: "ANYTHINGLLM_TOKEN", TokenDef: defaultAnythingLLMToken,
		Script: `demo\run_anythingllm_demo.ps1`, TokenFlag: "-ApiKey",
	},
	"odysseus": {
		Label: "Odysseus", Target: "127.0.0.1:7000",
		TokenEnv: "ODYSSEUS_TOKEN", TokenDef: defaultOdysseusToken,
		Script: `demo\run_odysseus_demo.ps1`, TokenFlag: "-Token",
	},
}

func tokenFor(a agentDef, override string) string {
	if strings.TrimSpace(override) != "" {
		return override
	}
	if v := os.Getenv(a.TokenEnv); v != "" {
		return v
	}
	return a.TokenDef
}

// ---- hub: fan-out of output lines to all connected browsers ---------------

type event struct {
	Type    string `json:"type"`              // "line" | "status"
	Text    string `json:"text,omitempty"`
	Running bool   `json:"running,omitempty"`
	Agent   string `json:"agent,omitempty"`
}

type hub struct {
	mu      sync.Mutex
	subs    map[chan event]bool
	buffer  []event // replay buffer (last N lines)
	running bool
	agent   string
	cmd     *exec.Cmd
	root    string
}

func newHub(root string) *hub {
	return &hub{subs: map[chan event]bool{}, root: root}
}

func (h *hub) subscribe() (chan event, []event) {
	ch := make(chan event, 256)
	h.mu.Lock()
	h.subs[ch] = true
	replay := append([]event(nil), h.buffer...)
	h.mu.Unlock()
	return ch, replay
}

func (h *hub) unsubscribe(ch chan event) {
	h.mu.Lock()
	delete(h.subs, ch)
	h.mu.Unlock()
	close(ch)
}

func (h *hub) broadcast(ev event) {
	h.mu.Lock()
	if ev.Type == "line" {
		h.buffer = append(h.buffer, ev)
		if len(h.buffer) > 4000 {
			h.buffer = h.buffer[len(h.buffer)-4000:]
		}
	}
	for ch := range h.subs {
		select {
		case ch <- ev:
		default: // drop for slow clients; never block the scanner
		}
	}
	h.mu.Unlock()
}

func (h *hub) statusEvent() event {
	h.mu.Lock()
	defer h.mu.Unlock()
	return event{Type: "status", Running: h.running, Agent: h.agent}
}

func (h *hub) run(agentKey, tokenOverride string, llm bool) error {
	a, ok := agents[agentKey]
	if !ok {
		return fmt.Errorf("unknown agent %q", agentKey)
	}
	h.mu.Lock()
	if h.running {
		h.mu.Unlock()
		return fmt.Errorf("a scan is already running")
	}
	h.buffer = nil // fresh screen for a new run
	h.mu.Unlock()

	token := tokenFor(a, tokenOverride)
	args := []string{
		"-NoProfile", "-ExecutionPolicy", "Bypass",
		"-File", a.Script, "-SkipDockerBootstrap", a.TokenFlag, token,
	}
	if llm {
		args = append(args, "-UseLlm", "-MaxLlmSpendUsd", "0.50")
	}

	cmd := exec.Command("powershell.exe", args...)
	cmd.Dir = h.root
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return err
	}
	stderr, err := cmd.StderrPipe()
	if err != nil {
		return err
	}
	if err := cmd.Start(); err != nil {
		return fmt.Errorf("failed to start: %w", err)
	}

	h.mu.Lock()
	h.cmd = cmd
	h.running = true
	h.agent = agentKey
	h.mu.Unlock()
	h.broadcast(event{Type: "line", Text: fmt.Sprintf("\x1b[36m[liveview] launching %s scan%s ...\x1b[0m", a.Label, llmSuffix(llm))})
	h.broadcast(h.statusEvent())

	scan := func(rc io.Reader) {
		s := bufio.NewScanner(rc)
		s.Buffer(make([]byte, 1024*1024), 1024*1024)
		for s.Scan() {
			h.broadcast(event{Type: "line", Text: s.Text()})
		}
	}
	go scan(stdout)
	go scan(stderr)
	go func() {
		_ = cmd.Wait()
		h.mu.Lock()
		h.running = false
		h.cmd = nil
		h.mu.Unlock()
		h.broadcast(event{Type: "line", Text: "\x1b[33m[liveview] process exited.\x1b[0m"})
		h.broadcast(h.statusEvent())
	}()
	return nil
}

func llmSuffix(llm bool) string {
	if llm {
		return " (+LLM)"
	}
	return ""
}

func (h *hub) stop() error {
	h.mu.Lock()
	cmd := h.cmd
	h.mu.Unlock()
	if cmd == nil || cmd.Process == nil {
		return fmt.Errorf("nothing running")
	}
	// Kill the whole process tree (powershell -> python -> ...).
	pid := strconv.Itoa(cmd.Process.Pid)
	_ = exec.Command("taskkill", "/PID", pid, "/T", "/F").Run()
	return nil
}

// ---- http -----------------------------------------------------------------

func dialable(hostport string) bool {
	c, err := net.DialTimeout("tcp", hostport, 1200*time.Millisecond)
	if err != nil {
		return false
	}
	_ = c.Close()
	return true
}

func main() {
	port := flag.Int("port", 8080, "HTTP port")
	root := flag.String("root", ".", "Security_module folder (where demo\\ lives)")
	flag.Parse()

	abs, _ := os.Getwd()
	if *root != "." {
		abs = *root
	}
	h := newHub(abs)

	mux := http.NewServeMux()

	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = io.WriteString(w, indexHTML)
	})

	mux.HandleFunc("/agents", func(w http.ResponseWriter, r *http.Request) {
		type ai struct {
			Key, Label, Target string
			Reachable          bool
		}
		out := []ai{}
		for k, a := range agents {
			out = append(out, ai{k, a.Label, a.Target, dialable(a.Target)})
		}
		writeJSON(w, map[string]any{"agents": out})
	})

	mux.HandleFunc("/run", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "POST only", 405)
			return
		}
		q := r.URL.Query()
		agent := q.Get("agent")
		llm := q.Get("llm") == "true" || q.Get("llm") == "1"
		token := q.Get("token")
		if err := h.run(agent, token, llm); err != nil {
			writeJSON(w, map[string]any{"ok": false, "error": err.Error()})
			return
		}
		writeJSON(w, map[string]any{"ok": true})
	})

	mux.HandleFunc("/stop", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "POST only", 405)
			return
		}
		if err := h.stop(); err != nil {
			writeJSON(w, map[string]any{"ok": false, "error": err.Error()})
			return
		}
		writeJSON(w, map[string]any{"ok": true})
	})

	mux.HandleFunc("/events", func(w http.ResponseWriter, r *http.Request) {
		flusher, ok := w.(http.Flusher)
		if !ok {
			http.Error(w, "streaming unsupported", 500)
			return
		}
		w.Header().Set("Content-Type", "text/event-stream")
		w.Header().Set("Cache-Control", "no-cache")
		w.Header().Set("Connection", "keep-alive")

		ch, replay := h.subscribe()
		defer h.unsubscribe(ch)

		send := func(ev event) {
			b, _ := json.Marshal(ev)
			fmt.Fprintf(w, "data: %s\n\n", b)
		}
		for _, ev := range replay {
			send(ev)
		}
		send(h.statusEvent())
		flusher.Flush()

		ka := time.NewTicker(15 * time.Second)
		defer ka.Stop()
		notify := r.Context().Done()
		for {
			select {
			case <-notify:
				return
			case ev := <-ch:
				send(ev)
				flusher.Flush()
			case <-ka.C:
				fmt.Fprint(w, ": ping\n\n")
				flusher.Flush()
			}
		}
	})

	addr := fmt.Sprintf("127.0.0.1:%d", *port)
	log.Printf("liveview on http://%s  (root=%s)", addr, abs)
	log.Fatal(http.ListenAndServe(addr, mux))
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}

// ---- the page (xterm.js from CDN; renders ANSI colors the scanner emits) ---

const indexHTML = `<!DOCTYPE html><html lang="en"><head><meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>OWASP ASI — Live Scanner</title>
<link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/xterm@5.3.0/css/xterm.min.css">
<style>
:root{--bg:#0f172a;--card:#1e293b;--text:#e2e8f0;--muted:#94a3b8;--border:#334155;--green:#22c55e;--red:#ef4444;--blue:#3b82f6}
*{box-sizing:border-box;margin:0;padding:0}
body{font-family:Inter,system-ui,sans-serif;background:var(--bg);color:var(--text);padding:1rem}
h1{font-size:1.2rem;margin-bottom:.8rem}
.row{display:flex;gap:.7rem;flex-wrap:wrap;align-items:center;margin-bottom:.7rem}
.muted{color:var(--muted);font-size:.85rem}
button{background:var(--blue);color:#fff;border:0;border-radius:8px;padding:.55rem 1rem;font-weight:600;cursor:pointer}
button:disabled{opacity:.5;cursor:not-allowed}
button.agent{background:var(--card);border:1px solid var(--border)}
button.agent.sel{border-color:var(--blue);box-shadow:0 0 0 1px var(--blue)}
button.start{background:var(--green);color:#04210f}button.stop{background:#475569}
input[type=text]{background:#0b1220;border:1px solid var(--border);color:var(--text);border-radius:6px;padding:.5rem;width:300px}
.dot{display:inline-block;width:9px;height:9px;border-radius:50%;margin-right:6px}
#term{height:74vh;border:1px solid var(--border);border-radius:8px;padding:6px;background:#0b1020}
</style></head><body>
<h1>🛡️ OWASP ASI — Live Scanner</h1>
<div class="row">
  <span class="muted">Agent:</span>
  <button class="agent" data-a="anythingllm" id="ag-anythingllm">● AnythingLLM</button>
  <button class="agent" data-a="odysseus" id="ag-odysseus">● Odysseus</button>
  <input type="text" id="token" placeholder="token (optional — uses env/default)">
  <label class="muted"><input type="checkbox" id="llm"> Use LLM</label>
  <button id="run" disabled>▶ Run scan</button>
  <button id="stop" class="stop" disabled>■ Stop</button>
  <button id="clear">Clear</button>
  <span id="status" class="muted"></span>
</div>
<div id="term"></div>
<script src="https://cdn.jsdelivr.net/npm/xterm@5.3.0/lib/xterm.min.js"></script>
<script src="https://cdn.jsdelivr.net/npm/xterm-addon-fit@0.8.0/lib/xterm-addon-fit.min.js"></script>
<script>
const $=s=>document.querySelector(s);
const term=new Terminal({fontSize:12,convertEol:true,scrollback:8000,
  theme:{background:'#0b1020'}});
const fit=new FitAddon.FitAddon(); term.loadAddon(fit);
term.open($('#term')); fit.fit(); addEventListener('resize',()=>fit.fit());
let agent=null;

async function loadAgents(){
  try{
    const {agents}=await (await fetch('/agents')).json();
    for(const a of agents){
      const b=$('#ag-'+a.Key); if(!b)continue;
      const c=a.Reachable?'var(--green)':'var(--red)';
      b.innerHTML='<span class="dot" style="background:'+c+'"></span>'+a.Label;
      b.title=a.Target+(a.Reachable?' reachable':' DOWN');
    }
  }catch(e){}
}
loadAgents(); setInterval(loadAgents,8000);

document.querySelectorAll('.agent').forEach(b=>b.onclick=()=>{
  agent=b.dataset.a;
  document.querySelectorAll('.agent').forEach(x=>x.classList.remove('sel'));
  b.classList.add('sel'); $('#run').disabled=false;
});
$('#run').onclick=async()=>{
  if(!agent)return;
  const tok=encodeURIComponent($('#token').value||'');
  const llm=$('#llm').checked;
  const r=await (await fetch('/run?agent='+agent+'&llm='+llm+'&token='+tok,{method:'POST'})).json();
  if(!r.ok){ $('#status').textContent='✗ '+r.error; }
};
$('#stop').onclick=()=>fetch('/stop',{method:'POST'});
$('#clear').onclick=()=>term.clear();

const es=new EventSource('/events');
es.onmessage=e=>{
  const ev=JSON.parse(e.data);
  if(ev.type==='line'){ term.writeln(ev.text); }
  else if(ev.type==='status'){
    $('#run').disabled=ev.running||!agent;
    $('#stop').disabled=!ev.running;
    $('#status').textContent=ev.running?('● running '+(ev.agent||'')):'idle';
  }
};
es.onerror=()=>{ $('#status').textContent='stream reconnecting…'; };
</script></body></html>`
