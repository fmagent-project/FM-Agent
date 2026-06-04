import json
import os
import subprocess
import threading


class JsonRpcLspClient:
    """Minimal JSON-RPC client for short-lived LSP analysis runs."""

    def __init__(self, command, cwd, timeout=30):
        self.command = command
        self.cwd = cwd
        self.timeout = timeout
        self._next_id = 1
        self._responses = {}
        self._lock = threading.Lock()
        self._closed = False
        self.proc = subprocess.Popen(
            command,
            cwd=cwd,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=False,
        )
        self._reader = threading.Thread(target=self._read_loop, daemon=True)
        self._reader.start()

    def _read_loop(self):
        """Read LSP responses framed with Content-Length headers."""
        while not self._closed and self.proc.stdout:
            headers = {}
            while True:
                line = self.proc.stdout.readline()
                if not line:
                    return
                if line in (b"\r\n", b"\n"):
                    break
                try:
                    key, value = line.decode("ascii", errors="replace").split(":", 1)
                except ValueError:
                    continue
                headers[key.lower()] = value.strip()
            length = int(headers.get("content-length", "0"))
            if length <= 0:
                continue
            raw = self.proc.stdout.read(length)
            try:
                message = json.loads(raw.decode("utf-8"))
            except json.JSONDecodeError:
                continue
            if "id" in message:
                with self._lock:
                    self._responses[message["id"]] = message

    def _send(self, payload):
        if not self.proc.stdin:
            raise RuntimeError("LSP stdin is closed")
        body = json.dumps(payload).encode("utf-8")
        header = f"Content-Length: {len(body)}\r\n\r\n".encode("ascii")
        self.proc.stdin.write(header + body)
        self.proc.stdin.flush()

    def request(self, method, params=None):
        import time

        with self._lock:
            req_id = self._next_id
            self._next_id += 1
        self._send({"jsonrpc": "2.0", "id": req_id, "method": method, "params": params or {}})
        deadline = time.time() + self.timeout
        while time.time() < deadline:
            with self._lock:
                response = self._responses.pop(req_id, None)
            if response is not None:
                if "error" in response:
                    raise RuntimeError(response["error"])
                return response.get("result")
            if self.proc.poll() is not None:
                raise RuntimeError(f"LSP process exited with code {self.proc.returncode}")
            time.sleep(0.05)
        raise TimeoutError(f"LSP request timed out: {method}")

    def notify(self, method, params=None):
        self._send({"jsonrpc": "2.0", "method": method, "params": params or {}})

    def initialize(self):
        root_uri = path_to_uri(self.cwd)
        result = self.request("initialize", {
            "processId": os.getpid(),
            "rootUri": root_uri,
            "capabilities": {},
        })
        self.notify("initialized", {})
        return result

    def did_open(self, path, language_id):
        with open(path, "r", encoding="utf-8", errors="replace") as f:
            text = f.read()
        self.notify("textDocument/didOpen", {
            "textDocument": {
                "uri": path_to_uri(path),
                "languageId": language_id,
                "version": 1,
                "text": text,
            }
        })

    def shutdown(self):
        try:
            self.request("shutdown", {})
            self.notify("exit", {})
        except Exception:
            pass
        self._closed = True
        try:
            if self.proc.poll() is None:
                self.proc.terminate()
        except OSError:
            pass


def path_to_uri(path):
    from urllib.parse import quote

    # LSP file URIs require absolute paths; quote keeps path separators intact.
    return "file://" + quote(os.path.abspath(path))
