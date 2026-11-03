#!/usr/bin/env python3
"""Fake model upstream for the ADR-0044 launcher e2e (Slice G).

Serves, on one plain-HTTP port bound to a loopback secondary IP:
  POST /v1/chat/completions  -> OpenAI chat-completions SSE (pi, codex)
  POST /v1/messages          -> Anthropic messages SSE (claude)
Every request's interesting headers (host, authorization, x-api-key) are
appended to $LOGFILE (one JSON object per line) so the test can assert the
gate swapped the Placeholder for the real value. Fake values only.
"""
import http.server
import json
import os
import sys


class H(http.server.BaseHTTPRequestHandler):
    def _log(self):
        doc = {
            "path": self.path,
            "host": self.headers.get("Host", ""),
            "authorization": self.headers.get("Authorization", ""),
            "x_api_key": self.headers.get("x-api-key", ""),
        }
        with open(os.environ.get("FAKE_MODEL_LOG", "/tmp/fake-model.log"), "a") as fh:
            fh.write(json.dumps(doc) + "\n")

    def _drain(self):
        length = int(self.headers.get("Content-Length", 0))
        if length:
            self.rfile.read(length)

    def do_POST(self):
        self._drain()
        self._log()
        if self.path.rstrip("/").endswith("/chat/completions"):
            self.send_response(200)
            self.send_header("content-type", "text/event-stream")
            self.end_headers()
            base = {"id": "e2e-1", "object": "chat.completion.chunk", "created": 0,
                    "model": "fake-model"}
            self.wfile.write(b'data: ' + json.dumps(
                {**base, "choices": [{"index": 0, "delta": {"role": "assistant",
                                                            "content": "ok"},
                                     "finish_reason": None}]}).encode() + b"\n\n")
            self.wfile.write(b'data: ' + json.dumps(
                {**base, "choices": [{"index": 0, "delta": {}, "finish_reason": "stop"}],
                 "usage": {"prompt_tokens": 1, "completion_tokens": 1,
                           "total_tokens": 2}}).encode() + b"\n\n")
            self.wfile.write(b"data: [DONE]\n\n")
        elif self.path.rstrip("/").endswith("/messages"):
            self.send_response(200)
            self.send_header("content-type", "text/event-stream")
            self.end_headers()
            msg = {"id": "msg_e2e", "type": "message", "role": "assistant",
                   "model": "fake-model",
                   "content": [{"type": "text", "text": "ok"}],
                   "stop_reason": "end_turn", "stop_sequence": None,
                   "usage": {"input_tokens": 1, "output_tokens": 1}}
            events = [
                {"type": "message_start", "message": msg},
                {"type": "content_block_start", "index": 0,
                 "content_block": {"type": "text", "text": ""}},
                {"type": "content_block_delta", "index": 0,
                 "delta": {"type": "text_delta", "text": "ok"}},
                {"type": "content_block_stop", "index": 0},
                {"type": "message_delta", "delta": {"stop_reason": "end_turn",
                                                    "stop_sequence": None},
                 "usage": {"output_tokens": 1}},
                {"type": "message_stop"},
            ]
            for e in events:
                self.wfile.write(b"event: " + e["type"].encode() + b"\n")
                self.wfile.write(b"data: " + json.dumps(e).encode() + b"\n\n")
        else:
            self.send_response(404)
            self.end_headers()

    def log_message(self, *a):
        pass


if __name__ == "__main__":
    ip, port = sys.argv[1], int(sys.argv[2])
    http.server.ThreadingHTTPServer((ip, port), H).serve_forever()
