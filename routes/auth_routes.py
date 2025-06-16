from flask import Blueprint, request, jsonify
from flask_jwt_extended import (
    create_refresh_token,
    create_access_token,
    jwt_required,
    get_jwt_identity,
)
import re
import requests
import random
from utils.email_utils import send_otp_email
from datetime import datetime, timedelta
from bson import ObjectId

auth_bp = Blueprint("auth", __name__)

user_model = None
bcrypt = None

def init_auth_routes(model, bcrypt_instance):
    global user_model, bcrypt
    user_model = model
    bcrypt = bcrypt_instance


def is_strong_password(password):
    if len(password) < 6:
        return False, "Password minimal 6 karakter."
    if not re.search(r"[A-Z]", password):
        return False, "Password harus mengandung huruf besar, angka, dan simbol."
    if not re.search(r"[a-z]", password):
        return False, "Password harus mengandung huruf kecil."
    if not re.search(r"\d", password):
        return False, "Password harus mengandung angka."
    if not re.search(r"[!@#$%^&*(),.?\":{}|<>]", password):
        return False, "Password harus mengandung simbol."
    return True, ""


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

    # validasi password kompleks
    is_strong, message = is_strong_password(password)
    if not is_strong:
        return jsonify({"success": False, "message": message}), 400

    if user_model.find_by_email(email):
        return jsonify({"success": False, "message": "Email sudah digunakan"}), 400

    hashed = bcrypt.generate_password_hash(password).decode("utf-8")

    otp = str(random.randint(100000, 999999))
    print(f"✅ Kirim OTP ke {email}: {otp}")
    email_sent = send_otp_email(email, otp, "verifikasi")
    if not email_sent:
        return jsonify({"success": False, "message": "Gagal mengirim OTP ke email"}), 500

    user_model.insert_user(email, username, hashed, otp, "verifikasi")

    return jsonify({
        "success": True,
        "message": "Registrasi berhasil. OTP telah dikirim ke email.",
        "data": {"username": username, "email": email}
    }), 201


@auth_bp.route("/login", methods=["POST"])
def login():
    data = request.json
    email = data.get("email", "").strip()
    password = data.get("password", "").strip()

    user = user_model.find_by_email(email)
    if not user:
        return jsonify({"success": False, "message": "Email tidak terdaftar"}), 404

    # 🔥 Ubah pengecekan password kosong jadi lebih aman
    user_password = user.get("password")
    if user_password is None or user_password.strip() == "":
        return jsonify({"success": False, "message": "Akun ini login menggunakan Google. Silakan buat password dulu di profil."}), 400

    if not bcrypt.check_password_hash(user_password, password):
        return jsonify({"success": False, "message": "Password tidak sesuai"}), 401

    if not user.get("is_verified", False):
        otp = str(random.randint(100000, 999999))
        send_otp_email(email, otp, "verifikasi")
        user_model.set_otp_for_reset(email, otp, "verifikasi")
        refresh_token = create_refresh_token(identity=str(user["_id"]))
        return jsonify({
            "success": False,
            "message": "Email belum diverifikasi. OTP dikirim ke email.",
            "otp_sent": True,
            "refresh_token": refresh_token,
            "user": {"email": email, "username": user["username"]}
        }), 403

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


@auth_bp.route("/log-login", methods=["POST"])
@jwt_required()
def log_login():
    try:
        user_id = get_jwt_identity()
        data = request.get_json()
        print(f"🟡 Log Login - user_id: {user_id}, data: {data}")

        timestamp = data.get("timestamp")
        device = data.get("device")

        if not timestamp or not device:
            print("❌ Log login gagal: data kosong")
            return jsonify({"success": False, "message": "Data login tidak lengkap"}), 400

        print("✅ Cek user di Mongo:", user_model.find_by_id(ObjectId(user_id)))
        result = user_model.log_login_activity(user_id, timestamp, device)

        if result.modified_count > 0:
            print("✅ Log login berhasil disimpan")
            print("📌 Modified Count:", result.modified_count)
            return jsonify({"success": True, "message": "Riwayat login tersimpan"}), 200
        else:
            print("❌ Gagal update MongoDB login_history")
            return jsonify({"success": False, "message": "Gagal menyimpan login"}), 500

    except Exception as e:
        import traceback
        print(f"❌ Exception log_login(): {e}")
        traceback.print_exc()
        return jsonify({"success": False, "message": str(e)}), 500

@auth_bp.route("/login-history", methods=["GET"])
@jwt_required()
def get_login_history():
    try:
        user_id = get_jwt_identity()
        user = user_model.find_by_id(user_id)
        if not user:
            return jsonify({"success": False, "message": "User tidak ditemukan"}), 404

        login_history = user.get("login_history", [])
        # Urutkan berdasarkan timestamp terbaru
        sorted_history = sorted(login_history, key=lambda x: x["timestamp"], reverse=True)

        return jsonify({"success": True, "data": sorted_history}), 200

    except Exception as e:
        print(f"❌ Exception get_login_history(): {e}")
        return jsonify({"success": False, "message": str(e)}), 500



@auth_bp.route("/verify-otp", methods=["POST"])
def verify_otp():
    data = request.json
    email = data.get("email", "").strip()
    otp_input = data.get("otp", "").strip()
    refresh_token = data.get("refresh_token")

    if not email or not otp_input:
        return jsonify({"success": False, "message": "Email dan OTP wajib diisi"}), 400

    if not user_model.verify_otp(email, otp_input, "verifikasi"):
        return jsonify({"success": False, "message": "OTP tidak valid atau kadaluarsa"}), 400

    user_model.set_verified(email)
    user = user_model.find_by_email(email)
    user_id = str(user["_id"])

    # 🔥 Auto-login setelah OTP valid
    access_token = create_access_token(identity=user_id)
    new_refresh_token = create_refresh_token(identity=user_id)

    return jsonify({
        "success": True,
        "message": "Email berhasil diverifikasi & auto-login",
        "data": {
            "token": access_token,
            "refresh_token": new_refresh_token,
            "user": {
                "username": user["username"],
                "email": user["email"]
            }
        }
    }), 200


@auth_bp.route("/google-login", methods=["POST"])
def google_login():
    data = request.json
    id_token = data.get("id_token")
    if not id_token:
        return jsonify({"success": False, "message": "id_token tidak terdaftar"}), 400

    try:
        resp = requests.get("https://oauth2.googleapis.com/tokeninfo", params={"id_token": id_token}, timeout=5)
        info = resp.json()
    except Exception as e:
        return jsonify({"success": False, "message": f"Token tidak valid: {str(e)}"}), 400

    if "email" not in info:
        return jsonify({"success": False, "message": "Token Google tidak valid"}), 401

    email = info["email"]
    username = info.get("name", "Pengguna Google")
    user = user_model.find_by_email(email)

    if not user:
        # Buat user baru belum verifikasi
        user_model.insert_user(email, username, None)
        user = user_model.find_by_email(email)

    if not user.get("is_verified", False):
        # Kirim OTP otomatis
        otp = str(random.randint(100000, 999999))
        send_otp_email(email, otp, "verifikasi")
        user_model.set_otp_for_reset(email, otp, "verifikasi")
        return jsonify({
            "success": False,
            "message": "Email belum diverifikasi. OTP telah dikirim ke email.",
            "user": {
                "username": user["username"],
                "email": user["email"]
            }
        }), 403

    user_id = str(user["_id"])
    access_token = create_access_token(identity=user_id)
    refresh_token = create_refresh_token(identity=user_id)
    return jsonify({
        "success": True,
        "message": "Login Google berhasil",
        "data": {
            "token": access_token,
            "refresh_token": refresh_token,
            "user": {
                "username": user.get("username", "Pengguna"),
                "email": user.get("email")
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
    user = user_model.find_by_id(user_id)

    if not user:
        return jsonify({"success": False, "message": "User tidak ditemukan"}), 404

    updates = {}

    #  Update username/email
    if "username" in data:
        updates["username"] = data["username"]
    if "email" in data:
        updates["email"] = data["email"]

    #  validasi current password & kompleksitas
    if "password" in data:
        pw_data = data["password"]
        current_pw = pw_data.get("current")
        new_pw = pw_data.get("new")
        if not current_pw or not new_pw:
            return jsonify({"success": False, "message": "Harap masukkan password saat ini dan password baru"}), 400
        if not bcrypt.check_password_hash(user.get("password", ""), current_pw):
            return jsonify({"success": False, "message": "Password saat ini salah"}), 400
        is_strong, message = is_strong_password(new_pw)
        if not is_strong:
            return jsonify({"success": False, "message": message}), 400
        updates["password"] = bcrypt.generate_password_hash(new_pw).decode("utf-8")

    if not updates:
        return jsonify({"success": False, "message": "Tidak ada data yang diubah"}), 400

    result = user_model.collection.update_one(
        {"_id": user["_id"]},
        {"$set": updates}
    )

    if result.modified_count == 0:
        return jsonify({"success": False, "message": "Data tidak diubah"}), 400

    return jsonify({"success": True, "message": "Profil berhasil diperbarui"}), 200


@auth_bp.route("/resend-otp", methods=["POST"])
def resend_otp():
    data = request.json
    email = data.get("email", "").strip()
    purpose = data.get("purpose", "verifikasi").strip()

    user = user_model.find_by_email(email)
    if not user:
        return jsonify({"success": False, "message": "Email tidak terdaftar."}), 404

    if purpose == "verifikasi" and user.get("is_verified", False):
        return jsonify({"success": False, "message": "Email sudah terverifikasi."}), 400

    if user.get("otp_last_sent") and datetime.utcnow() - user["otp_last_sent"] < timedelta(minutes=5):
        if user.get("otp_request_count", 0) >= 3:
            return jsonify({"success": False, "message": "Terlalu banyak permintaan OTP. Coba lagi nanti."}), 429
        new_count = user.get("otp_request_count", 0) + 1
    else:
        new_count = 1

    otp = str(random.randint(100000, 999999))
    updated = user_model.set_otp_for_reset(email, otp, purpose)

    if updated:
        user_model.collection.update_one({"email": email}, {"$set": {
            "otp_last_sent": datetime.utcnow(),
            "otp_request_count": new_count
        }})
        send_otp_email(email, otp, purpose)
        return jsonify({"success": True, "message": f"OTP {purpose} baru telah dikirim ke email."}), 200
    else:
        return jsonify({"success": False, "message": "Gagal mengirim OTP baru."}), 500


@auth_bp.route("/verify-reset-otp", methods=["POST"])
def verify_reset_otp():
    data = request.json
    email = data.get("email", "").strip()
    otp_input = data.get("otp", "").strip()

    if not email or not otp_input:
        return jsonify({"success": False, "message": "Email dan OTP wajib diisi"}), 400

    if not user_model.verify_otp(email, otp_input, "reset"):
        return jsonify({"success": False, "message": "OTP salah atau kadaluarsa"}), 400

    return jsonify({"success": True, "message": "OTP valid, silahkan buat buar password baru"}), 200


@auth_bp.route("/forgot-password", methods=["POST"])
def forgot_password():
    data = request.json
    email = data.get("email", "").strip()

    user = user_model.find_by_email(email)
    if not user:
        return jsonify({"success": False, "message": "Email tidak terdaftar"}), 404

    if user.get("otp_last_sent") and datetime.utcnow() - user["otp_last_sent"] < timedelta(minutes=5):
        if user.get("otp_request_count", 0) >= 3:
            return jsonify({"success": False, "message": "Terlalu banyak permintaan OTP. Coba lagi nanti."}), 429
        new_count = user.get("otp_request_count", 0) + 1
    else:
        new_count = 1

    otp = str(random.randint(100000, 999999))
    updated = user_model.set_otp_for_reset(email, otp, "reset")

    if updated:
        user_model.collection.update_one({"email": email}, {"$set": {
            "otp_last_sent": datetime.utcnow(),
            "otp_request_count": new_count
        }})
        send_otp_email(email, otp, "reset")
        return jsonify({"success": True, "message": "OTP untuk reset password telah dikirim ke email."}), 200
    else:
        return jsonify({"success": False, "message": "Gagal mengatur OTP."}), 500

@auth_bp.route("/reset-password", methods=["POST"])
def reset_password():
    data = request.json
    email = data.get("email", "").strip()
    otp_input = data.get("otp", "").strip()
    new_password = data.get("new_password", "").strip()

    is_strong, message = is_strong_password(new_password)
    if not is_strong:
        return jsonify({"success": False, "message": message}), 400

    if not email or not otp_input or not new_password:
        return jsonify({"success": False, "message": "Email, OTP, dan password baru wajib diisi."}), 400

    if not user_model.verify_otp(email, otp_input, "reset"):
        return jsonify({"success": False, "message": "OTP salah atau kadaluarsa."}), 400

    updated = user_model.reset_password(email, new_password)
    if updated:
        return jsonify({"success": True, "message": "Password berhasil direset."}), 200
    else:
        return jsonify({"success": False, "message": "Gagal reset password."}), 500


@auth_bp.route("/user/info", methods=["GET"])
@jwt_required()
def user_info():
    user_id = get_jwt_identity()
    user = user_model.find_by_id(user_id)
    if user:
        reminder = ""
        if not user.get("password"):
            reminder = "Akun Anda belum memiliki password. Silakan buat password untuk login manual."
        return jsonify({
            "success": True,
            "data": {
                "username": user.get("username"),
                "email": user.get("email"),
                "reminder": reminder
            }
        }), 200
    return jsonify({"success": False, "message": "User tidak ditemukan"}), 404
