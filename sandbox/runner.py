#!/usr/bin/env python3
"""CyberLab isolated code runner. Executes one bounded job in a disposable container."""
from __future__ import annotations
import json, os, secrets, selectors, subprocess, tempfile, time, threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

HOST = os.environ.get("CYBERLAB_SANDBOX_BIND", "127.0.0.1")
PORT = int(os.environ.get("CYBERLAB_SANDBOX_PORT", "8787"))
TOKEN = os.environ.get("CYBERLAB_SANDBOX_TOKEN", "")
IMAGE = os.environ.get("CYBERLAB_SANDBOX_IMAGE", "cyberlab-sandbox:latest")
RUNTIME = os.environ.get("CYBERLAB_SANDBOX_RUNTIME", "runsc")
JOB_SLOTS = threading.BoundedSemaphore(2)
MAX_BODY = 64 * 1024
MAX_OUTPUT = 64 * 1024
MAX_RUNTIME = 20
LANGUAGES = {"python": ("main.py", ["python3", "/workspace/main.py"]),
             "javascript": ("main.js", ["node", "/workspace/main.js"]),
             "shell": ("main.sh", ["bash", "/workspace/main.sh"])}

def run_job(data: dict) -> dict:
    if not isinstance(data, dict) or set(data) - {"language", "source"}:
        raise ValueError("Only language and source fields are accepted.")
    language, source = data.get("language"), data.get("source")
    if language not in LANGUAGES:
        raise ValueError("Choose python, javascript or shell.")
    if not isinstance(source, str) or not source.strip() or len(source.encode("utf-8")) > 48 * 1024:
        raise ValueError("Source must be non-empty UTF-8 text no larger than 48 KB.")
    filename, command = LANGUAGES[language]
    started = time.monotonic()
    with tempfile.TemporaryDirectory(prefix="cyberlab-job-") as tmp:
        path = Path(tmp) / filename
        path.write_text(source, encoding="utf-8")
        path.chmod(0o444)
        docker_command = [
            "docker", "run", "--rm", "--pull=never", "--runtime=" + RUNTIME,
            "--network=none", "--memory=384m", "--memory-swap=384m",
            "--cpus=1", "--pids-limit=64", "--read-only",
            "--tmpfs", "/tmp:rw,noexec,nosuid,nodev,size=64m",
            "--cap-drop=ALL", "--security-opt=no-new-privileges",
            "--user=10001:10001", "--workdir=/workspace",
            "--ulimit", "nofile=64:64", "--ulimit", "fsize=10485760:10485760",
            "--mount", f"type=bind,src={tmp},dst=/workspace,readonly",
            IMAGE, *command
        ]
        process = subprocess.Popen(docker_command, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, stdin=subprocess.DEVNULL, bufsize=0)
        output = bytearray()
        truncated = False
        with selectors.DefaultSelector() as selector:
            selector.register(process.stdout, selectors.EVENT_READ)
            deadline = time.monotonic() + MAX_RUNTIME
            while selector.get_map() and time.monotonic() < deadline:
                for key, _ in selector.select(timeout=0.2):
                    chunk = os.read(key.fd, 8192)
                    if not chunk:
                        selector.unregister(key.fileobj)
                        continue
                    remaining = MAX_OUTPUT - len(output)
                    if remaining > 0:
                        output.extend(chunk[:remaining])
                    if len(chunk) > remaining:
                        truncated = True
                        process.kill()
                        break
                if process.poll() is not None and not selector.get_map():
                    break
            timed_out = process.poll() is None and time.monotonic() >= deadline
            if process.poll() is None:
                process.kill()
            try:
                process.wait(timeout=2)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait()
        return {
            "jobId": secrets.token_hex(12), "status": "timed_out" if timed_out else ("output_limited" if truncated else "completed"),
            "language": language, "exitCode": process.returncode, "output": output.decode("utf-8", errors="replace"),
            "outputTruncated": truncated, "durationMs": round((time.monotonic() - started) * 1000),
            "isolation": {"network": "disabled", "container": "disposable", "memoryLimit": "384 MiB", "cpuLimit": "1 vCPU", "pidsLimit": 64, "readOnlyRoot": True}
        }

class Handler(BaseHTTPRequestHandler):
    server_version = "CyberLabSandbox/0.1"
    def _json(self, status, payload):
        body = json.dumps(payload).encode()
        self.send_response(status); self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body))); self.send_header("Cache-Control", "no-store")
        self.end_headers(); self.wfile.write(body)
    def do_GET(self):
        if self.path == "/health":
            return self._json(200, {"status": "ok", "service": "cyberlab-sandbox", "image": IMAGE})
        self._json(404, {"error": "Not found"})
    def do_POST(self):
        if self.path != "/v1/run":
            return self._json(404, {"error": "Not found"})
        if not TOKEN or not secrets.compare_digest(self.headers.get("Authorization", ""), "Bearer " + TOKEN):
            return self._json(401, {"error": "Unauthorised"})
        try:
            length = int(self.headers.get("Content-Length", "0"))
            if length < 2 or length > MAX_BODY:
                raise ValueError("Request body is missing or too large.")
            data = json.loads(self.rfile.read(length))
            result = run_job(data)
            self._json(200, result)
        except (ValueError, json.JSONDecodeError) as exc:
            self._json(400, {"error": str(exc)})
        except FileNotFoundError:
            self._json(503, {"error": "Docker is unavailable on the sandbox host."})
        except Exception:
            self._json(500, {"error": "Sandbox execution failed. Check the sandbox host logs."})
    def log_message(self, *_args):
        return

if __name__ == "__main__":
    if not TOKEN:
        raise SystemExit("Set CYBERLAB_SANDBOX_TOKEN before starting the runner.")
    ThreadingHTTPServer((HOST, PORT), Handler).serve_forever()
