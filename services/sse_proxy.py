from __future__ import annotations

import queue
import threading
import time
from typing import Callable, Generator, Optional
from urllib.parse import urlparse

import requests

from config import Config


def stream_exporter_sse(config: Config, enqueue_fn: Callable[[str], None]) -> Generator[str, None, None]:
	"""Proxy Cowrie SSE stream and enqueue lines for playback persistence."""
	retry_delay = 3.0
	label = _exporter_label(config)
	while True:
		if _has_placeholder_token(config.exporter_ssh_stream_url) and not config.cowrie_api_token:
			yield _status_event("error: exporter token not configured (set EXPORTER_SSH_STREAM_URL or COWRIE_API_TOKEN)")
			time.sleep(retry_delay)
			continue
		resp = None
		try:
			yield _status_event("connecting")
			resp = _open_exporter_stream(config)
			yield _status_event("connected")
			yield from _stream_response(resp, enqueue_fn)
			yield _status_event("disconnected")
		except requests.HTTPError as exc:
			status = exc.response.status_code if exc.response is not None else "unknown"
			yield _status_event(f"error: exporter HTTP {status} ({label})")
		except requests.RequestException:
			yield _status_event(f"error: exporter unavailable ({label})")
		except Exception:
			yield _status_event("error: exporter stream failed")
		finally:
			if resp is not None:
				try:
					resp.close()
				except Exception:
					pass
		time.sleep(retry_delay)


def _has_placeholder_token(url: str) -> bool:
	return "CHANGE_THIS_TO_LONG_RANDOM" in url


def _exporter_label(config: Config) -> str:
	raw = config.exporter_ssh_stream_url
	parsed = urlparse(raw)
	if not parsed.hostname:
		parsed = urlparse(f"http://{raw}")
	host = parsed.hostname or raw.split("://", 1)[-1].split("/", 1)[0].split("?", 1)[0] or "exporter"
	if parsed.port:
		return f"{host}:{parsed.port}"
	return host


def _status_event(message: str) -> str:
	return f"event: status\ndata: {message}\n\n"


def _open_exporter_stream(config: Config) -> requests.Response:
	headers = {}
	if config.cowrie_api_token:
		headers["X-API-Token"] = config.cowrie_api_token
	resp = requests.get(
		config.exporter_ssh_stream_url,
		stream=True,
		headers=headers or None,
		timeout=(5, 3600),
	)
	if resp.status_code != 200:
		resp.close()
		raise requests.HTTPError(f"unexpected status {resp.status_code}", response=resp)
	return resp


def _normalize_line(line: str) -> Optional[str]:
	text = line.strip()
	if not text:
		return None
	if text.startswith(":") or text.startswith("event:") or text.startswith("retry:"):
		return None
	if text.startswith("data:"):
		return text[5:].lstrip()
	return text


def _stream_response(resp: requests.Response, enqueue_fn: Callable[[str], None]) -> Generator[str, None, None]:
	q: queue.Queue[Optional[str]] = queue.Queue()

	def _reader():
		try:
			for line in resp.iter_lines(decode_unicode=True):
				if line is None:
					continue
				q.put(line)
		finally:
			q.put(None)

	t = threading.Thread(target=_reader, daemon=True)
	t.start()

	last_send = time.time()
	while True:
		try:
			item = q.get(timeout=1.0)
		except queue.Empty:
			item = None

		now = time.time()

		if item is None:
			if not t.is_alive():
				break
		else:
			payload = _normalize_line(item)
			if payload:
				enqueue_fn(payload)
				yield f"data: {payload}\n\n"
				last_send = now

		if now - last_send >= 15:
			yield ": keepalive\n\n"
			last_send = time.time()
