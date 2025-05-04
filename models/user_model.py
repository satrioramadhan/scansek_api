from flask_bcrypt import generate_password_hash, check_password_hash
from bson.objectid import ObjectId

class UserModel:
    def __init__(self, db):
        self.collection = db["users"]

    def find_by_email(self, email):
        return self.collection.find_one({"email": email})

    def insert_user(self, email, username, password_hashed):
        return self.collection.insert_one({
            "email": email,
            "username": username,
            "password": password_hashed
        }).inserted_id

    def verify_password(self, plain_pw, hashed_pw):
        return check_password_hash(hashed_pw, plain_pw)

    def update_user(self, user_id, updates):
        """Update user fields secara fleksibel"""
        update_data = {}

        if "username" in updates:
            update_data["username"] = updates["username"]
        if "email" in updates:
            update_data["email"] = updates["email"]
        if "password" in updates:
            update_data["password"] = generate_password_hash(updates["password"]).decode("utf-8")

        if not update_data:
            return 0  # Tidak ada perubahan

        result = self.collection.update_one(
            {"_id": ObjectId(user_id)},
            {"$set": update_data}
        )
        return result.modified_count
