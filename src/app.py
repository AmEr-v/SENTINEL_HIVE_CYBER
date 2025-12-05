from flask import Flask

def create_app():
    app = Flask(__name__)

    @app.route("/")
    def home():
        return "<h1>Adaptive Honeypot Dashboard</h1><p>Project structure is working.</p>"

    return app

if __name__ == "__main__":
    app = create_app()
    app.run(host="0.0.0.0", port=5000, debug=True)
