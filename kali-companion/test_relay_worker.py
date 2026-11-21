import importlib.util
import json
import unittest
from pathlib import Path
from unittest.mock import patch

MODULE_PATH = Path(__file__).with_name("relay_worker.py")
SPEC = importlib.util.spec_from_file_location("cyberlab_relay_worker", MODULE_PATH)
worker = importlib.util.module_from_spec(SPEC)
assert SPEC and SPEC.loader
SPEC.loader.exec_module(worker)


class RemoteBridgeDispatchTests(unittest.TestCase):
    def test_rejects_arbitrary_hosts_and_unlisted_routes(self):
        with patch.object(worker.urllib.request, "urlopen") as urlopen:
            with self.assertRaisesRegex(ValueError, "Invalid local bridge path"):
                worker.bridge_request("GET", "https://example.com/")
            with self.assertRaisesRegex(ValueError, "not in the worker allowlist"):
                worker.bridge_request("POST", "/admin/execute", {})
            with self.assertRaisesRegex(ValueError, "not in the worker allowlist"):
                worker.bridge_request("POST", "/wallet/recovery-run", {"seed": "not forwarded"})
            with self.assertRaisesRegex(ValueError, "not in the worker allowlist"):
                worker.bridge_request("POST", "/web/request", {"headers": {"Cookie": "secret"}})
            urlopen.assert_not_called()

    def test_allows_known_route_and_preserves_bridge_status(self):
        class FakeResponse:
            status = 200
            def __enter__(self): return self
            def __exit__(self, *args): return False
            def read(self, size=-1): return json.dumps({"status": "connected"}).encode()

        with patch.object(worker.urllib.request, "urlopen", return_value=FakeResponse()) as urlopen:
            result = worker.bridge_request("GET", "/burp/scanner/tasks")
        self.assertEqual(result["bridge_status"], 200)
        self.assertEqual(result["bridge_body"]["status"], "connected")
        self.assertIn("/burp/scanner/tasks", urlopen.call_args.args[0].full_url)

    def test_post_requires_local_allowlisted_path(self):
        class FakeResponse:
            status = 200
            def __enter__(self): return self
            def __exit__(self, *args): return False
            def read(self, size=-1): return b'{"status":"ok"}'
        with patch.object(worker.urllib.request, "urlopen", return_value=FakeResponse()) as urlopen:
            result = worker.bridge_request("POST", "/plan", {"prompt": "Inspect this lab"})
        self.assertEqual(result["bridge_status"], 200)
        self.assertEqual(json.loads(urlopen.call_args.args[0].data), {"prompt": "Inspect this lab"})

if __name__ == "__main__":
    unittest.main()
