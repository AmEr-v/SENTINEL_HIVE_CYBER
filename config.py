import os
from dataclasses import dataclass
from pathlib import Path


def _bool(value: str) -> bool:
	return value.lower() in {"1", "true", "yes", "on"}


@dataclass
class Config:
	http_log_path: Path
	ssh_log_path: Path
	max_events: int
	exporter_ssh_stream_url: str
	playback_db_path: Path
	playback_retention_days: int
	cowrie_tty_path: Path
	playlog_bin: Path
	cowrie_exporter_stats_url: str
	cowrie_api_token: str | None
	http_exporter_base_url: str
	http_api_token: str | None
	sim_node_target: int
	sim_seed: int
	host: str
	port: int
	flask_debug: bool


def load_config() -> Config:
	"""Load configuration from environment with sane defaults."""
	cwd = Path.cwd()
	http_log_env = os.getenv("HTTP_LOG_PATH")
	if not http_log_env:
		local_http = cwd / "http-honeypot.log"
		http_log_env = str(local_http) if local_http.exists() else str(Path.home() / "http-honeypot.log")
	ssh_log_env = os.getenv("SSH_LOG_PATH")
	if not ssh_log_env:
		local_ssh = cwd / "cowrie.json"
		ssh_log_env = (
			str(local_ssh)
			if local_ssh.exists()
			else str(Path.home() / "cowrie" / "var" / "log" / "cowrie" / "cowrie.json")
		)
	return Config(
		http_log_path=Path(http_log_env).expanduser(),
		ssh_log_path=Path(ssh_log_env).expanduser(),
		max_events=int(os.getenv("MAX_EVENTS", "500")),
		exporter_ssh_stream_url=os.getenv(
			"EXPORTER_SSH_STREAM_URL",
			"http://10.0.96.70:8088/stream/cowrie-log?token=CHANGE_THIS_TO_LONG_RANDOM",
		),
		playback_db_path=Path(os.getenv("PLAYBACK_DB_PATH", "data/playback.db")).expanduser(),
		playback_retention_days=int(os.getenv("PLAYBACK_RETENTION_DAYS", "0")),
		cowrie_tty_path=Path(os.getenv("COWRIE_TTY_PATH", "/cowrie/var/lib/cowrie/tty")).expanduser(),
		playlog_bin=Path(os.getenv("PLAYLOG_BIN", "/cowrie/bin/playlog")).expanduser(),
		cowrie_exporter_stats_url=os.getenv(
			"COWRIE_EXPORTER_STATS_URL", "http://10.0.96.70:8088/stats/cowrie"
		).strip(),
		cowrie_api_token=os.getenv("COWRIE_API_TOKEN"),
		http_exporter_base_url=os.getenv("HTTP_EXPORTER_BASE_URL", "").rstrip("/"),
		http_api_token=os.getenv("HTTP_API_TOKEN"),
		sim_node_target=int(os.getenv("SIM_NODE_TARGET", "600")),
		sim_seed=int(os.getenv("SIM_SEED", "12345")),
		host=os.getenv("HOST", "0.0.0.0"),
		port=int(os.getenv("PORT", "5000")),
		flask_debug=_bool(os.getenv("FLASK_DEBUG", "false")),
	)
