from flask import Blueprint, request, jsonify
from flask_jwt_extended import jwt_required, get_jwt_identity
from bson.objectid import ObjectId
from bson.errors import InvalidId
from datetime import datetime, timedelta

gula_bp = Blueprint("gula", __name__)

def validate_gula_payload(data):
    try:
        gula = int(data.get("gulaPerBungkus", 0))
        jumlah = int(data.get("jumlahBungkus", 0))
        total = float(data.get("totalGula", 0))
        sendok = float(data.get("sendokTeh", 0))

        if gula <= 0 or jumlah <= 0:
            return False, "Gula per bungkus dan jumlah bungkus harus lebih dari 0"
        if total <= 0 or sendok <= 0:
            return False, "Total gula dan konversi sendok teh harus lebih dari 0"
        return True, ""
    except Exception:
        return False, "Input tidak valid (harus angka)"


@gula_bp.route("/gula", methods=["POST"])
@jwt_required()
def tambah_gula():
    db = request.mongo.db
    user_id = get_jwt_identity()
    data = request.json

    valid, msg = validate_gula_payload(data)
    if not valid:
        return jsonify({"success": False, "message": msg}), 400

    try:
        item = {
            "user_id": ObjectId(user_id),
            "namaMakanan": data.get("namaMakanan", ""),
            "gulaPerBungkus": data["gulaPerBungkus"],
            "jumlahBungkus": data["jumlahBungkus"],
            "isiPerBungkus": data.get("isiPerBungkus"),
            "totalGula": data["totalGula"],
            "sendokTeh": data["sendokTeh"],
            "waktuInput": data.get("waktuInput", datetime.utcnow().isoformat())
        }
        result = db.riwayat_gula.insert_one(item)
        item["_id"] = str(result.inserted_id)
        item["user_id"] = str(item["user_id"])  # ← FIX INI
        return jsonify({"success": True, "message": "Data berhasil ditambahkan", "data": item}), 201
    except Exception as e:
        return jsonify({"success": False, "message": f"Gagal menambahkan data: {str(e)}"}), 400


@gula_bp.route("/gula", methods=["GET"])
@jwt_required()
def ambil_gula():
    db = request.mongo.db
    user_id = get_jwt_identity()
    date_str = request.args.get("date")
    keyword = request.args.get("search")

    try:
        query = {"user_id": ObjectId(user_id)}

        if date_str:
            tanggal = datetime.strptime(date_str, "%Y-%m-%d")
            next_day = tanggal + timedelta(days=1)
            query["waktuInput"] = {
                "$gte": tanggal.isoformat(),
                "$lt": next_day.isoformat()
            }

        if keyword:
            query["namaMakanan"] = {"$regex": keyword, "$options": "i"}

        data = list(db.riwayat_gula.find(query))
        for item in data:
            item["_id"] = str(item["_id"])
            item["user_id"] = str(item["user_id"])

        return jsonify({"success": True, "message": "Data ditemukan", "data": data}), 200
    except Exception as e:
        return jsonify({"success": False, "message": f"Gagal mengambil data: {str(e)}"}), 400


@gula_bp.route("/gula/<id>", methods=["PUT"])
@jwt_required()
def update_gula(id):
    db = request.mongo.db
    user_id = get_jwt_identity()
    data = request.json

    try:
        try:
            obj_id = ObjectId(id)
        except InvalidId:
            return jsonify({"success": False, "message": "ID tidak valid"}), 400

        valid, msg = validate_gula_payload(data)
        if not valid:
            return jsonify({"success": False, "message": msg}), 400

        query = {"_id": obj_id, "user_id": ObjectId(user_id)}
        update = {"$set": {
            "namaMakanan": data.get("namaMakanan", ""),
            "gulaPerBungkus": data["gulaPerBungkus"],
            "jumlahBungkus": data["jumlahBungkus"],
            "isiPerBungkus": data.get("isiPerBungkus"),
            "totalGula": data["totalGula"],
            "sendokTeh": data["sendokTeh"]
        }}

        result = db.riwayat_gula.update_one(query, update)
        if result.matched_count == 0:
            return jsonify({"success": False, "message": "Data tidak ditemukan atau tidak punya akses"}), 404

        return jsonify({"success": True, "message": "Data berhasil diperbarui"}), 200
    except Exception as e:
        return jsonify({"success": False, "message": f"Gagal update data: {str(e)}"}), 400


@gula_bp.route("/gula/<id>", methods=["DELETE"])
@jwt_required()
def hapus_gula(id):
    db = request.mongo.db
    user_id = get_jwt_identity()

    try:
        try:
            obj_id = ObjectId(id)
        except InvalidId:
            return jsonify({"success": False, "message": "ID tidak valid"}), 400

        result = db.riwayat_gula.delete_one({"_id": obj_id, "user_id": ObjectId(user_id)})
        if result.deleted_count == 0:
            return jsonify({"success": False, "message": "Data tidak ditemukan atau tidak punya akses"}), 404

        return jsonify({"success": True, "message": "Data berhasil dihapus"}), 200
    except Exception as e:
        return jsonify({"success": False, "message": f"Gagal hapus data: {str(e)}"}), 400
