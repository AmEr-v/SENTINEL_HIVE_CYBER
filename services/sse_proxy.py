from __future__ import annotations

import queue
import threading
import time
from typing import Callable, Generator, Optional

import requests

from config import Config


def stream_exporter_sse(config: Config, enqueue_fn: Callable[[str], None]) -> Generator[str, None, None]:
	"""Proxy Cowrie SSE stream and enqueue lines for playback persistence."""
	resp = requests.get(
		config.exporter_ssh_stream_url,
		stream=True,
		timeout=(5, 3600),
	)

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
	try:
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
				enqueue_fn(item)
				yield f"data: {item}\n\n"
				last_send = now

			if now - last_send >= 15:
				yield ": keepalive\n\n"
				last_send = time.time()
	finally:
		resp.close()
