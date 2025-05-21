from flask import Flask, request
from flask_jwt_extended import JWTManager
from flask_pymongo import PyMongo
from flask_bcrypt import Bcrypt
from config import Config
from routes.auth_routes import auth_bp, init_auth_routes
from routes.gula_routes import gula_bp
from routes.air_routes import air_bp
from models.user_model import UserModel

jwt = JWTManager()
bcrypt = Bcrypt()
mongo = PyMongo()

def create_app():
    app = Flask(__name__)
    app.config.from_object(Config)

    jwt.init_app(app)
    bcrypt.init_app(app)
    mongo.init_app(app)

    @app.before_request
    def attach_mongo_to_request():
        request.mongo = mongo

    user_model_instance = UserModel(mongo.db)
    init_auth_routes(user_model_instance, bcrypt)

    # ✅ Register semua blueprint dengan prefix /api
    app.register_blueprint(auth_bp, url_prefix="/api/auth")
    app.register_blueprint(gula_bp, url_prefix="/api")
    app.register_blueprint(air_bp, url_prefix="/api")

    # ✅ Tambahkan route untuk /api/
    @app.route("/api/")
    def api_root():
        return "ScanSek API Root 🧪"

    # ✅ Index MongoDB
    mongo.db.riwayat_gula.create_index([
        ("user_id", 1),
        ("waktuInput", -1)
    ])
    mongo.db.riwayat_air.create_index([
        ("user_id", 1),
        ("tanggal", 1)
    ])

    @app.route("/")
    def index():
        return "ScanSek API Online 😎"

    print("REFRESH TOKEN EXPIRE:", app.config.get("JWT_REFRESH_TOKEN_EXPIRES"))
    return app

if __name__ == "__main__":
    app = create_app()
    app.run(debug=True)

