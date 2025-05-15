from flask import Blueprint, request, jsonify
from flask_jwt_extended import create_refresh_token, create_access_token, jwt_required, get_jwt_identity
from bson.objectid import ObjectId
import re

auth_bp = Blueprint("auth", __name__)

user_model = None
bcrypt = None

def init_auth_routes(model, bcrypt_instance):
    global user_model, bcrypt
    user_model = model
    bcrypt = bcrypt_instance

@auth_bp.route("/register", methods=["POST"])
def register():
    data = request.json
    email = data.get("email", "").strip()
    password = data.get("password", "").strip()
    username = data.get("username", "").strip()

    if not email or not password or not username:
        return jsonify({"success": False, "message": "Semua field wajib diisi"}), 400

    if not re.match(r"[^@]+@[^@]+\.[^@]+", email):
        return jsonify({"success": False, "message": "Email tidak valid"}), 400

    if len(password) < 6:
        return jsonify({"success": False, "message": "Password minimal 6 karakter"}), 400

    if user_model.find_by_email(email):
        return jsonify({"success": False, "message": "Email sudah digunakan"}), 400

    hashed = bcrypt.generate_password_hash(password).decode("utf-8")
    user_id = user_model.insert_user(email, username, hashed)
    return jsonify({
        "success": True,
        "message": "Registrasi berhasil",
        "data": {"username": username, "email": email, "user_id": str(user_id)}
    }), 201

@auth_bp.route("/login", methods=["POST"])
def login():
    data = request.json
    email = data.get("email", "").strip()
    password = data.get("password", "").strip()

    user = user_model.find_by_email(email)
    if not user:
        return jsonify({"success": False, "message": "Email tidak terdaftar"}), 404

    if not bcrypt.check_password_hash(user["password"], password):
        return jsonify({"success": False, "message": "Password tidak sesuai"}), 401

    access_token = create_access_token(identity=str(user["_id"]))
    refresh_token = create_refresh_token(identity=str(user["_id"]))

    return jsonify({
        "success": True,
        "message": "Login berhasil",
        "data": {
            "token": access_token,
            "refresh_token": refresh_token,
            "user": {
                "username": user["username"],
                "email": user["email"]
            }
        }
    }), 200

@auth_bp.route("/refresh", methods=["POST"])
@jwt_required(refresh=True)
def refresh():
    current_user = get_jwt_identity()
    new_token = create_access_token(identity=current_user)
    return jsonify({"success": True, "token": new_token}), 200

@auth_bp.route("/update-profile", methods=["PUT"])
@jwt_required()
def update_profile():
    user_id = get_jwt_identity()
    data = request.json

    try:
        result = user_model.update_user(user_id, data)
        if result == 0:
            return jsonify({"success": False, "message": "Tidak ada data yang diubah."}), 400
        return jsonify({"success": True, "message": "Profil berhasil diperbarui."}), 200
    except Exception as e:
        return jsonify({"success": False, "message": f"Gagal update profil: {str(e)}"}), 400
