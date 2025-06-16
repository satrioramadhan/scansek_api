import requests
import os

SENDGRID_API_KEY = os.getenv("SENDGRID_API_KEY")


def send_otp_email(receiver_email, otp_code, purpose="verifikasi"):
    print(f"🔔 Kirim OTP ({purpose}) ke {receiver_email}: {otp_code}")

    subject = "Kode OTP Verifikasi ScanSek" if purpose == "verifikasi" else "Kode OTP Reset Password ScanSek"
    title = "Verifikasi Email Anda" if purpose == "verifikasi" else "Reset Password Anda"
    description = (
        "Halo 👋, berikut adalah kode verifikasi email Anda:"
        if purpose == "verifikasi"
        else "Halo 👋, berikut adalah kode untuk mereset password Anda:"
    )

    html_template = f"""
    <!DOCTYPE html>
    <html lang="id">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>{subject}</title>
    </head>
    <body style="font-family: Arial, sans-serif; background-color: #f2f2f2; padding: 20px;">
        <div style="max-width: 600px; margin: auto; background-color: #ffffff; padding: 30px; border-radius: 8px; box-shadow: 0 0 10px rgba(0,0,0,0.1);">
            <div style="text-align: center; margin-bottom: 20px;">
                <img src="http:164.92.109.4/static/logo.png" alt="ScanSek Logo" style="height: 60px;">
            </div>
            <h2 style="color: #4CAF50; text-align: center;">{title}</h2>
            <p style="text-align: center; font-size: 16px;">{description}</p>
            <h1 style="color: #4CAF50; font-size: 36px; text-align: center; letter-spacing: 4px;">{otp_code}</h1>
            <p style="text-align: center; font-size: 14px; color: #555;">Kode berlaku selama 5 menit. Jangan bagikan kepada siapa pun.</p>
            <hr style="margin-top: 30px;">
            <p style="font-size: 12px; color: #999; text-align: center;">&copy; 2025 ScanSek. Semua hak dilindungi.</p>
        </div>
    </body>
    </html>
    """

    headers = {
        "Authorization": f"Bearer {SENDGRID_API_KEY}",
        "Content-Type": "application/json"
    }

    data = {
        "personalizations": [{"to": [{"email": receiver_email}]}],
        "from": {"email": "scansek1@gmail.com", "name": "ScanSek"},
        "subject": subject,
        "content": [
            {"type": "text/plain", "value": f"Kode OTP kamu adalah: {otp_code}"},
            {"type": "text/html", "value": html_template}
        ]
    }

    try:
        response = requests.post("https://api.sendgrid.com/v3/mail/send", json=data, headers=headers)
        print("📬 SendGrid response:", response.status_code, response.text)
        return response.status_code == 202
    except Exception as e:
        print("❌ Gagal kirim via SendGrid:", e)
        return False
