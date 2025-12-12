from __future__ import annotations

import datetime
import random
import time
from typing import Any, Dict, List

from config import Config


class SimTelemetry:
	"""Simple seeded simulator for dashboard widgets."""

	def __init__(self, config: Config):
		self.config = config
		self.rng = random.Random(config.sim_seed)
		self.nodes: List[Dict[str, Any]] = []
		self.attackers: List[Dict[str, Any]] = []
		self.timeline: Dict[str, Any] = {"labels": [], "ssh": [], "http": []}
		self.alerts: List[Dict[str, Any]] = []

	def _init_world(self) -> None:
		places = [
			("New York, US", "NA", 40.7128, -74.0060),
			("Chicago, US", "NA", 41.8781, -87.6298),
			("Dallas, US", "NA", 32.7767, -96.7970),
			("Seattle, US", "NA", 47.6062, -122.3321),
			("Toronto, CA", "NA", 43.6532, -79.3832),
			("London, UK", "EU", 51.5074, -0.1278),
			("Frankfurt, DE", "EU", 50.1109, 8.6821),
			("Amsterdam, NL", "EU", 52.3676, 4.9041),
			("Paris, FR", "EU", 48.8566, 2.3522),
			("Madrid, ES", "EU", 40.4168, -3.7038),
			("Warsaw, PL", "EU", 52.2297, 21.0122),
			("Helsinki, FI", "EU", 60.1699, 24.9384),
			("Stockholm, SE", "EU", 59.3293, 18.0686),
			("Dubai, AE", "ME", 25.2048, 55.2708),
			("Tel Aviv, IL", "ME", 32.0853, 34.7818),
			("Doha, QA", "ME", 25.2854, 51.5310),
			("Riyadh, SA", "ME", 24.7136, 46.6753),
			("Mumbai, IN", "APAC", 19.0760, 72.8777),
			("Bangalore, IN", "APAC", 12.9716, 77.5946),
			("Chennai, IN", "APAC", 13.0827, 80.2707),
			("Singapore, SG", "APAC", 1.3521, 103.8198),
			("Hong Kong, HK", "APAC", 22.3193, 114.1694),
			("Tokyo, JP", "APAC", 35.6762, 139.6503),
			("Osaka, JP", "APAC", 34.6937, 135.5023),
			("Seoul, KR", "APAC", 37.5665, 126.9780),
			("Sydney, AU", "APAC", -33.8688, 151.2093),
			("Melbourne, AU", "APAC", -37.8136, 144.9631),
			("Sao Paulo, BR", "SA", -23.5505, -46.6333),
			("Bogota, CO", "SA", 4.7110, -74.0721),
			("Johannesburg, ZA", "AF", -26.2041, 28.0473),
			("Nairobi, KE", "AF", -1.2921, 36.8219),
		]
		_nodes: List[Dict[str, Any]] = []
		for i in range(self.config.sim_node_target):
			city, region, lat, lon = self.rng.choice(places)
			status_roll = self.rng.random()
			if status_roll < 0.92:
				status = "healthy"
			elif status_roll < 0.98:
				status = "degraded"
			else:
				status = "under_attack"
			_nodes.append(
				{
					"id": f"node-{i}",
					"name": city,
					"region": region,
					"lat": lat + self.rng.uniform(-0.4, 0.4),
					"lon": lon + self.rng.uniform(-0.4, 0.4),
					"status": status,
					"last_update": datetime.datetime.utcnow().isoformat(),
				},
			)
		self.nodes = _nodes

		asn_pool = ["AS15169 Google", "AS16509 AWS", "AS14061 DigitalOcean", "AS9009 M247", "AS54600 Comcast", "AS3320 Deutsche Telekom"]
		country_pool = ["US", "RU", "CN", "BR", "DE", "NL", "FR", "GB", "IN", "IR", "VN"]
		self.attackers = []
		for i in range(8):
			ip = f"203.0.{self.rng.randint(60,120)}.{self.rng.randint(1,254)}"
			self.attackers.append(
				{
					"ip": ip,
					"country": self.rng.choice(country_pool),
					"asn": self.rng.choice(asn_pool),
					"count": self.rng.randint(40, 180),
					"last_seen": datetime.datetime.utcnow().isoformat(),
				},
			)

		now = int(time.time())
		labels: List[int] = []
		ssh_vals: List[int] = []
		http_vals: List[int] = []
		for i in range(60):
			minute_ts = now - (59 - i) * 60
			labels.append(minute_ts)
			ssh_vals.append(self.rng.randint(4, 18))
			http_vals.append(self.rng.randint(8, 30))
		self.timeline = {"labels": labels, "ssh": ssh_vals, "http": http_vals}
		self.alerts = []

	def _tick_nodes(self) -> None:
		if not self.nodes:
			return
		flip_count = max(1, int(len(self.nodes) * 0.02))
		indices = [self.rng.randrange(len(self.nodes)) for _ in range(flip_count)]
		for idx in indices:
			node = self.nodes[idx]
			roll = self.rng.random()
			if roll < 0.6:
				node["status"] = "healthy"
			elif roll < 0.9:
				node["status"] = "degraded"
			else:
				node["status"] = "under_attack"
			node["last_update"] = datetime.datetime.utcnow().isoformat()

	def _tick_attackers(self, spike_factor: float) -> None:
		if not self.attackers:
			return
		for attacker in self.attackers:
			inc = int(self.rng.uniform(1, 8) * spike_factor)
			attacker["count"] += inc
			attacker["last_seen"] = datetime.datetime.utcnow().isoformat()
		if self.rng.random() < 0.15 and len(self.attackers) < 10:
			asn_pool = ["AS15169 Google", "AS16509 AWS", "AS14061 DigitalOcean", "AS9009 M247", "AS54600 Comcast", "AS3320 Deutsche Telekom"]
			country_pool = ["US", "RU", "CN", "BR", "DE", "NL", "FR", "GB", "IN", "IR", "VN"]
			self.attackers.append(
				{
					"ip": f"198.51.{self.rng.randint(50,150)}.{self.rng.randint(1,254)}",
					"country": self.rng.choice(country_pool),
					"asn": self.rng.choice(asn_pool),
					"count": self.rng.randint(15, 60),
					"last_seen": datetime.datetime.utcnow().isoformat(),
				},
			)

	def _tick_timeline(self) -> None:
		if not self.timeline.get("labels"):
			return
		labels = self.timeline["labels"]
		ssh_vals = self.timeline["ssh"]
		http_vals = self.timeline["http"]
		now_minute = int(time.time() // 60)
		last_label_minute = int(labels[-1] // 60)
		steps = now_minute - last_label_minute
		for _ in range(max(1, steps)):
			labels.pop(0)
			ssh_vals.pop(0)
			http_vals.pop(0)
			labels.append((last_label_minute + 1) * 60)
			last_label_minute += 1

		def _spike(val: int, base: int, low: int, high: int) -> int:
			return max(0, int(val + self.rng.uniform(low, high) + base))

		spike = self.rng.random() < 0.25
		ssh_base = self.rng.randint(4, 18)
		http_base = self.rng.randint(8, 30)
		if spike:
			ssh_base += self.rng.randint(20, 120)
			http_base += self.rng.randint(40, 200)
		ssh_vals[-1] = _spike(ssh_vals[-2], ssh_base - ssh_vals[-2], -5, 8)
		http_vals[-1] = _spike(http_vals[-2], http_base - http_vals[-2], -7, 12)
		self.timeline = {"labels": labels, "ssh": ssh_vals, "http": http_vals}

	def _tick_alerts(self, spike_factor: float, under_attack_count: int) -> None:
		labels = [
			("Bruteforce wave detected", "SSH auth failures rising across nodes"),
			("HTTP credential stuffing", "Repeated POST bursts with reused creds"),
			("New IP cluster", "Unseen /16 hitting web honeypot"),
			("Spike in auth failures", "Cowrie exporter reports elevated failures"),
			("Node performance drop", "Edge sensor reporting high latency"),
		]
		sev_choices = ["low", "med", "high", "critical"]
		if spike_factor > 2 or under_attack_count > max(3, int(self.config.sim_node_target * 0.02)):
			sev = self.rng.choices(sev_choices, weights=[1, 2, 3, 2], k=1)[0]
		else:
			sev = self.rng.choices(sev_choices, weights=[3, 4, 1, 0.5], k=1)[0]
		if self.rng.random() < 0.6:
			title, detail = self.rng.choice(labels)
			self.alerts.append(
				{
					"ts": datetime.datetime.utcnow().isoformat(),
					"severity": sev,
					"title": title,
					"detail": detail,
				},
			)
		self.alerts = self.alerts[-8:]

	def _threat_from_state(self) -> Dict[str, Any]:
		ssh_recent = max(self.timeline.get("ssh", [])[-10:] or [0])
		http_recent = max(self.timeline.get("http", [])[-10:] or [0])
		under_attack = sum(1 for n in self.nodes if n.get("status") == "under_attack")
		unique_ips = len(self.attackers)
		score = min(100, int(ssh_recent * 0.4 + http_recent * 0.2 + under_attack * 3 + unique_ips * 2))
		if score < 25:
			label = "LOW"
		elif score < 50:
			label = "MEDIUM"
		elif score < 75:
			label = "HIGH"
		else:
			label = "CRITICAL"
		return {"label": label, "score": score}

	def _node_health_summary(self) -> Dict[str, Any]:
		healthy = sum(1 for n in self.nodes if n["status"] == "healthy")
		deg = sum(1 for n in self.nodes if n["status"] == "degraded")
		attack = sum(1 for n in self.nodes if n["status"] == "under_attack")
		return {"healthy": healthy, "degraded": deg, "under_attack": attack, "total": len(self.nodes)}

	def _protocol_split_from_timeline(self) -> Dict[str, int]:
		ssh_sum = sum(self.timeline.get("ssh", []))
		http_sum = sum(self.timeline.get("http", []))
		return {"ssh": ssh_sum, "http": http_sum}

	def tick_world(self) -> Dict[str, Any]:
		if not self.nodes:
			self._init_world()
		self._tick_nodes()
		self._tick_timeline()
		under_attack = sum(1 for n in self.nodes if n.get("status") == "under_attack")
		spike_factor = 1.0 + (under_attack / max(1, self.config.sim_node_target)) * 8.0
		self._tick_attackers(spike_factor)
		self._tick_alerts(spike_factor, under_attack)
		return {
			"threat_level": self._threat_from_state(),
			"protocol_split": self._protocol_split_from_timeline(),
			"top_attackers": self.attackers,
			"node_health": self._node_health_summary(),
			"global_nodes": self.nodes,
			"timeline_60m": self.timeline,
			"alerts": self.alerts,
		}

	def payload(self, stats: Dict[str, Any]) -> Dict[str, Any]:
		world = self.tick_world()
		labels_iso = [
			datetime.datetime.fromtimestamp(ts, tz=datetime.timezone.utc).isoformat()
			for ts in world.get("timeline_60m", {}).get("labels", [])
		]
		world["timeline_60m"] = {
			"labels": labels_iso,
			"ssh": world.get("timeline_60m", {}).get("ssh", []),
			"http": world.get("timeline_60m", {}).get("http", []),
		}
		world["stats"] = stats
		world["sim_label"] = "SIMULATED"
		return world
