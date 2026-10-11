#!/usr/bin/env python3
"""Old-build compacted-session replay (smarty-dev#4273, #8742).

The BASE build compacts one Codex session (POST /v1/responses/compact) and one Claude session (POST /v1/messages with
a compaction request) against a local stub upstream that returns canned compaction blocks. BASE is stopped, then the
HEAD build is cold-started twice: (i) on a copy of BASE's state dir, (ii) on an empty state dir. Each start replays
both compacted sessions. All four replays must answer 200; a 409 or a compaction_* 4xx fails.

No real accounts and no network: scratch HOME, config and auth dir; only loopback; HTTP(S)_PROXY points at a closed
loopback port, so any request meant for a real provider fails instead of leaving the host.

usage: compaction-replay.py BASE_BINARY HEAD_BINARY
"""
import http.server, json, os, shutil, signal, socket, subprocess, sys, tempfile, threading, time
import urllib.error, urllib.request
from pathlib import Path

KEY = 'replay-client-key'
CODEX_BLOCK, CLAUDE_BLOCK = 'REPLAY-STUB-CODEX-BLOCK', 'REPLAY-STUB-CLAUDE-BLOCK'


def free_port():
    with socket.socket() as s:
        s.bind(('127.0.0.1', 0))
        return s.getsockname()[1]


class Stub(http.server.BaseHTTPRequestHandler):
    """Canned upstream: Codex /responses/compact and /responses, Anthropic /messages."""
    protocol_version = 'HTTP/1.1'
    seen = []

    def do_POST(self):
        body = self.rfile.read(int(self.headers.get('Content-Length', 0) or 0))
        Stub.seen.append((self.path, body.decode(errors='replace')))
        if 'compact' in self.path:
            return self.json({'id': 'resp_stub', 'object': 'response.compaction', 'created_at': 1,
                              'output': [{'type': 'compaction', 'id': 'cmp_1', 'encrypted_content': CODEX_BLOCK}],
                              'usage': {'input_tokens': 1, 'output_tokens': 1, 'total_tokens': 2}})
        if '/messages' in self.path:
            req = json.loads(body or b'{}')
            content = ([{'type': 'compaction', 'content': CLAUDE_BLOCK}] if req.get('compaction')
                       else [{'type': 'text', 'text': 'replayed'}])
            return self.json({'id': 'msg_stub', 'type': 'message', 'role': 'assistant', 'model': req.get('model', 'm'),
                              'content': content, 'stop_reason': 'end_turn', 'stop_sequence': None,
                              'usage': {'input_tokens': 1, 'output_tokens': 1}})
        if '/responses' in self.path:
            sse = ('event: response.completed\ndata: ' + json.dumps({'type': 'response.completed', 'response': {
                'id': 'resp_2', 'object': 'response', 'status': 'completed',
                'model': json.loads(body or b'{}').get('model', 'gpt-6-luna'), 'output': [
                    {'type': 'message', 'role': 'assistant', 'content': [{'type': 'output_text', 'text': 'replayed'}]}],
                'usage': {'input_tokens': 1, 'output_tokens': 1, 'total_tokens': 2}}}) + '\n\n').encode()
            self.send_response(200)
            self.send_header('Content-Type', 'text/event-stream')
            self.send_header('Content-Length', str(len(sse)))
            self.end_headers()
            return self.wfile.write(sse)
        self.json({'error': 'stub: unknown path ' + self.path}, 404)

    def do_GET(self):
        self.json({'data': []})

    def json(self, doc, code=200):
        data = json.dumps(doc).encode()
        self.send_response(code)
        self.send_header('Content-Type', 'application/json')
        self.send_header('Content-Length', str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def log_message(self, *args):
        pass


def config(root, port, stub_port):
    (root / 'auth').mkdir(mode=0o700)
    path = root / 'config.yaml'
    path.write_text(f'''host: 127.0.0.1
port: {port}
auth-dir: "{root / 'auth'}"
api-keys:
- {KEY}
usage-statistics-enabled: false
routing:
  strategy: round-robin
  session-affinity: true
  session-affinity-state-dir: "{root / 'state'}"
codex-api-key:
- api-key: stub-codex-key
  base-url: http://127.0.0.1:{stub_port}
  models:
  - name: gpt-6-luna
    alias: gpt-6-luna
claude-api-key:
- api-key: stub-claude-key
  base-url: http://127.0.0.1:{stub_port}
  models:
  - name: claude-opus-5-5
    alias: claude-opus-5-5
''')
    return path


class Gateway:
    def __init__(self, binary, root, stub_port, name):
        self.root, self.port, self.name = root, free_port(), name
        cfg = config(root, self.port, stub_port)
        env = {'PATH': os.environ.get('PATH', '/usr/bin:/bin'), 'HOME': str(root / 'home'),
               'XDG_STATE_HOME': str(root / 'xdg-state'), 'HTTP_PROXY': 'http://127.0.0.1:9',
               'HTTPS_PROXY': 'http://127.0.0.1:9', 'NO_PROXY': '127.0.0.1,localhost'}
        (root / 'home').mkdir()
        self.log = open(root / f'{name}.log', 'wb')
        self.proc = subprocess.Popen([binary, '-config', str(cfg)], cwd=root, env=env, stdout=self.log,
                                     stderr=subprocess.STDOUT, start_new_session=True)
        deadline = time.time() + 60
        while time.time() < deadline:
            if self.proc.poll() is not None:
                raise SystemExit(f'{name}: exited {self.proc.returncode} at start; see {root}/{name}.log')
            try:
                status, _ = self.call('GET', '/v1/models')
                if status == 200:
                    return
            except OSError:
                pass
            time.sleep(0.25)
        raise SystemExit(f'{name}: not ready in 60 s')

    def call(self, method, path, doc=None, headers=None):
        req = urllib.request.Request(f'http://127.0.0.1:{self.port}{path}', None if doc is None else json.dumps(doc).encode(),
                                     {'Authorization': f'Bearer {KEY}', 'Content-Type': 'application/json',
                                      **(headers or {})}, method=method)
        try:
            with urllib.request.urlopen(req, timeout=60) as resp:
                return resp.status, resp.read().decode(errors='replace')
        except urllib.error.HTTPError as error:
            return error.code, error.read().decode(errors='replace')

    def stop(self):
        if self.proc.poll() is None:
            os.killpg(self.proc.pid, signal.SIGTERM)
            try:
                self.proc.wait(20)
            except subprocess.TimeoutExpired:
                os.killpg(self.proc.pid, signal.SIGKILL)
                self.proc.wait()
        self.log.close()


CLAUDE_HEADERS = {'anthropic-version': '2023-06-01'}


def compact(gateway):
    """BASE: compact one Codex and one Claude session; return the two replay requests."""
    status, body = gateway.call('POST', '/v1/responses/compact', {
        'model': 'gpt-6-luna', 'prompt_cache_key': 'replay-codex-session',
        'input': [{'type': 'message', 'role': 'user', 'content': [{'type': 'input_text', 'text': 'remember PLUM-42'}]}]})
    if status != 200:
        raise SystemExit(f'BASE codex compact: HTTP {status} {body[:300]}')
    codex = [item for item in json.loads(body).get('output', []) if item.get('type') == 'compaction']
    status, body = gateway.call('POST', '/v1/messages', {
        'model': 'claude-opus-5-5', 'max_tokens': 32, 'compaction': {'type': 'summarize'},
        'messages': [{'role': 'user', 'content': 'remember PLUM-42'}]},
        {**CLAUDE_HEADERS, 'X-Claude-Code-Session-Id': 'replay-claude-session'})
    if status != 200:
        raise SystemExit(f'BASE claude compact: HTTP {status} {body[:300]}')
    claude = [item for item in json.loads(body).get('content', []) if item.get('type') == 'compaction']
    if not codex or not claude:
        raise SystemExit(f'BASE returned no compaction block (codex {codex}, claude {claude})')
    return [
        ('codex', '/v1/responses', {'model': 'gpt-6-luna', 'prompt_cache_key': 'replay-codex-session', 'stream': False,
                                    'input': codex + [{'type': 'message', 'role': 'user',
                                                       'content': [{'type': 'input_text', 'text': 'continue'}]}]}, {}),
        ('claude', '/v1/messages', {'model': 'claude-opus-5-5', 'max_tokens': 32, 'messages': [
            {'role': 'user', 'content': 'remember PLUM-42'}, {'role': 'assistant', 'content': claude},
            {'role': 'user', 'content': 'continue'}]},
         {**CLAUDE_HEADERS, 'X-Claude-Code-Session-Id': 'replay-claude-session'}),
    ]


def main():
    base, head = (str(Path(arg).resolve()) for arg in sys.argv[1:3])
    work = Path(tempfile.mkdtemp(prefix='cpa-replay-'))
    stub = http.server.ThreadingHTTPServer(('127.0.0.1', 0), Stub)
    threading.Thread(target=stub.serve_forever, daemon=True).start()
    stub_port = stub.server_address[1]
    failures, results = [], []
    try:
        root = work / 'base'
        root.mkdir()
        gateway = Gateway(base, root, stub_port, 'base')
        try:
            replays = compact(gateway)
        finally:
            gateway.stop()
        state = root / 'state'
        print(f'BASE state dir: {sorted(p.name for p in state.iterdir()) if state.is_dir() else "absent"}')
        for case in ('base-state', 'empty-state'):
            root = work / case
            root.mkdir()
            if case == 'base-state' and state.is_dir():
                shutil.copytree(state, root / 'state')
            gateway = Gateway(head, root, stub_port, 'head-' + case)
            try:
                for name, path, doc, headers in replays:
                    status, body = gateway.call('POST', path, doc, headers)
                    ok = status == 200
                    results.append(f'{case:12} {name:7} HTTP {status}' + ('' if ok else f'  {body[:240]}'))
                    if not ok:
                        failures.append(f'{case}/{name}')
            finally:
                gateway.stop()
    finally:
        stub.shutdown()
    print('\n'.join(results))
    if failures:
        print(f'FAIL: {len(failures)} of 4 replays refused: {", ".join(failures)} (logs in {work})')
        return 1
    shutil.rmtree(work, ignore_errors=True)
    print('PASS: 4 of 4 replays answered 200')
    return 0


if __name__ == '__main__':
    sys.exit(main())
