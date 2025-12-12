from __future__ import annotations

from flask import Flask

from config import load_config
from routes.dashboard_routes import create_dashboard_blueprint
from routes.live_routes import create_live_blueprint
from routes.playback_routes import create_playback_blueprint
from routes.proxy_routes import create_proxy_blueprint
from routes.session_routes import create_session_blueprint
from routes.sim_routes import create_sim_blueprint
from services.playback_db import PlaybackDB
from services.sim_telemetry import SimTelemetry


def create_app() -> Flask:
	config = load_config()
	app = Flask(__name__, template_folder="templates")

	playback_db = PlaybackDB(config)
	playback_db.start()
	sim = SimTelemetry(config)

	app.config["APP_CONFIG"] = config
	app.config["PLAYBACK_DB"] = playback_db
	app.config["SIM_TELEMETRY"] = sim

	app.register_blueprint(create_dashboard_blueprint(config))
	app.register_blueprint(create_live_blueprint(config))
	app.register_blueprint(create_playback_blueprint(config, playback_db))
	app.register_blueprint(create_session_blueprint(config))
	app.register_blueprint(create_proxy_blueprint(config, playback_db))
	app.register_blueprint(create_sim_blueprint(config, sim))

	return app


app = create_app()


if __name__ == "__main__":
	cfg = app.config["APP_CONFIG"]
	app.run(host=cfg.host, port=cfg.port, debug=cfg.flask_debug)
