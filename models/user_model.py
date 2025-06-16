from flask_bcrypt import generate_password_hash, check_password_hash
from bson.objectid import ObjectId
from datetime import datetime, timedelta

class UserModel:
    def __init__(self, db):
        self.collection = db["users"]
        # Buat index email unik
        self.collection.create_index("email", unique=True)

    def find_by_email(self, email):
        return self.collection.find_one({"email": email})

    def find_by_id(self, user_id):
        return self.collection.find_one({"_id": ObjectId(user_id)})

    def insert_user(self, email, username, password_hashed=None, otp=None, otp_purpose=None):
        data = {
            "email": email,
            "username": username,
            "is_verified": False,
            "otp_last_sent": None,
            "otp_request_count": 0,
            "login_history": []
        }
        if password_hashed:
            data["password"] = password_hashed
        if otp:
            data["otp"] = otp
            data["otp_expiry"] = datetime.utcnow() + timedelta(minutes=5)
        if otp_purpose:
            data["otp_purpose"] = otp_purpose

        return self.collection.insert_one(data).inserted_id

    def verify_password(self, plain_pw, hashed_pw):
        return check_password_hash(hashed_pw, plain_pw)

    def update_user(self, user_id, updates):
        update_data = {}

        if "username" in updates:
            update_data["username"] = updates["username"]
        if "email" in updates:
            update_data["email"] = updates["email"]
        if "password" in updates:
            update_data["password"] = generate_password_hash(updates["password"]).decode("utf-8")

        if not update_data:
            return 0

        result = self.collection.update_one(
            {"_id": ObjectId(user_id)},
            {"$set": update_data}
        )
        return result.modified_count

    def verify_otp(self, email, otp_input, purpose=None):
        user = self.find_by_email(email)
        if not user or "otp" not in user:
            return False

        otp_matches = user["otp"] == otp_input
        purpose_matches = purpose is None or user.get("otp_purpose") == purpose
        not_expired = datetime.utcnow() < user["otp_expiry"]

        return otp_matches and purpose_matches and not_expired

    def set_verified(self, email):
        return self.collection.update_one(
            {"email": email},
            {"$set": {"is_verified": True}, "$unset": {"otp": "", "otp_expiry": "", "otp_purpose": ""}}
        ).modified_count

    def set_otp_for_reset(self, email, otp_code, purpose):
        return self.collection.update_one(
            {"email": email},
            {"$set": {
                "otp": otp_code,
                "otp_expiry": datetime.utcnow() + timedelta(minutes=5),
                "otp_purpose": purpose
            }}
        ).modified_count

    def reset_password(self, email, new_password):
        return self.collection.update_one(
            {"email": email},
            {"$set": {"password": generate_password_hash(new_password).decode("utf-8")},
             "$unset": {"otp": "", "otp_expiry": "", "otp_purpose": ""}}
        ).modified_count

    def delete_unverified_users(self, days=1):
        cutoff = datetime.utcnow() - timedelta(days=days)
        result = self.collection.delete_many({
            "is_verified": False,
            "otp_expiry": {"$lt": cutoff}
        })
        return result.deleted_count

    def log_login_activity(self, user_id, timestamp, device_info):
        return self.collection.update_one(
            {"_id": ObjectId(user_id)},
            {"$push": {
                "login_history": {
                    "timestamp": timestamp,
                    "device": device_info
                }
            }}
        )


