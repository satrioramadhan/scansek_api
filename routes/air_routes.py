from flask import Blueprint, request, jsonify
from flask_jwt_extended import jwt_required, get_jwt_identity
from bson.objectid import ObjectId
from datetime import datetime

air_bp = Blueprint("air", __name__)

@air_bp.route("/air", methods=["GET"])
@jwt_required()
def get_riwayat_air():
    db = request.mongo.db
    user_id = get_jwt_identity()
    tanggal = request.args.get("tanggal")

    if not tanggal:
        return jsonify({"success": False, "message": "Tanggal harus diisi"}), 400

    try:
        data = db.riwayat_air.find_one({
            "user_id": ObjectId(user_id),
            "tanggal": tanggal
        })

        if data:
            data["_id"] = str(data["_id"])
            data["user_id"] = str(data["user_id"])
            return jsonify({"success": True, "data": data}), 200
        else:
            return jsonify({"success": True, "data": {
                "tanggal": tanggal,
                "riwayatJamMinum": []
            }}), 200

    except Exception as e:
        return jsonify({"success": False, "message": f"Gagal ambil data: {str(e)}"}), 400


@air_bp.route("/air", methods=["POST"])
@jwt_required()
def tambah_jam_minum():
    db = request.mongo.db
    user_id = get_jwt_identity()
    data = request.json

    tanggal = data.get("tanggal")
    jam = data.get("jam")

    if not tanggal or not jam:
        return jsonify({"success": False, "message": "Tanggal dan jam harus diisi"}), 400

    try:
        datetime.strptime(jam, "%H:%M")
    except ValueError:
        return jsonify({"success": False, "message": "Format jam tidak valid (HH:mm)"}), 400

    try:
        db.riwayat_air.update_one(
            {"user_id": ObjectId(user_id), "tanggal": tanggal},
            {"$addToSet": {"riwayatJamMinum": jam}},  # anti-duplikat
            upsert=True
        )
        return jsonify({"success": True, "message": "Jam minum berhasil ditambahkan"}), 201
    except Exception as e:
        return jsonify({"success": False, "message": f"Gagal tambah jam: {str(e)}"}), 400


@air_bp.route("/air/<tanggal>", methods=["DELETE"])
@jwt_required()
def hapus_riwayat_air(tanggal):
    db = request.mongo.db
    user_id = get_jwt_identity()

    try:
        result = db.riwayat_air.delete_one({
            "user_id": ObjectId(user_id),
            "tanggal": tanggal
        })

        if result.deleted_count == 0:
            return jsonify({"success": False, "message": "Data tidak ditemukan"}), 404

        return jsonify({"success": True, "message": "Data berhasil dihapus"}), 200
    except Exception as e:
        return jsonify({"success": False, "message": f"Gagal hapus data: {str(e)}"}), 400


@air_bp.route("/air/<tanggal>/<jam>", methods=["DELETE"])
@jwt_required()
def hapus_jam_tertentu(tanggal, jam):
    db = request.mongo.db
    user_id = get_jwt_identity()

    try:
        result = db.riwayat_air.update_one(
            {"user_id": ObjectId(user_id), "tanggal": tanggal},
            {"$pull": {"riwayatJamMinum": jam}}
        )

        if result.modified_count == 0:
            return jsonify({"success": False, "message": "Jam tidak ditemukan atau tidak berubah"}), 404

        return jsonify({
            "success": True,
            "message": f"Jam {jam} berhasil dihapus dari tanggal {tanggal}"
        }), 200
    except Exception as e:
        return jsonify({"success": False, "message": f"Gagal hapus jam: {str(e)}"}), 400
