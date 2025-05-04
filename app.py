from flask import Flask, request
from flask_jwt_extended import JWTManager
from flask_pymongo import PyMongo
from flask_bcrypt import Bcrypt
from config import MONGO_URI, JWT_SECRET_KEY
from routes.auth_routes import auth_bp, init_auth_routes
from routes.gula_routes import gula_bp
from models.user_model import UserModel

app = Flask(__name__)
app.config["MONGO_URI"] = MONGO_URI
app.config["JWT_SECRET_KEY"] = JWT_SECRET_KEY

jwt = JWTManager(app)
bcrypt = Bcrypt(app)
mongo = PyMongo(app)

# Inject mongo ke setiap request biar bisa akses lewat request.mongo
@app.before_request
def attach_mongo_to_request():
    request.mongo = mongo

# Inisialisasi model user
user_model_instance = UserModel(mongo.db)
init_auth_routes(user_model_instance)

# Register blueprint routes
app.register_blueprint(auth_bp, url_prefix="/api/auth")
app.register_blueprint(gula_bp, url_prefix="/api")

# Buat index biar query cepat
mongo.db.riwayat_gula.create_index([
    ("user_id", 1),
    ("waktuInput", -1)
])

@app.route("/")
def index():
    return "ScanSek API Online 😎"

if __name__ == "__main__":
    app.run(debug=True)
