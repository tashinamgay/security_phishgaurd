# backend/src/auth/twofa.py
# Two-Factor Authentication (2FA) using TOTP
# Member: Tashi
#
# SIMPLE EXPLANATION:
# TOTP = Time-based One-Time Password
# Every 30 seconds a new 6-digit code is generated
#
# HOW 2FA WORKS:
# Step 1: generate_secret()    - create random secret key for user
# Step 2: generate_qr_code()   - make QR code image from secret
# Step 3: User scans QR code with Google Authenticator app
# Step 4: App shows new 6-digit code every 30 seconds
# Step 5: verify_token()       - check if code entered is correct

import pyotp    # generates and verifies TOTP codes
import qrcode   # creates QR code images
import io       # handles image data in memory
import base64   # converts image to text for HTML


def generate_secret():
    """Create a random 32-character secret key for a user."""
    return pyotp.random_base32()


def generate_qr_code(secret, username):
    """
    Generate QR code as base64 string for HTML img tag.
    User scans this with Google Authenticator.
    """
    # Build standard TOTP URI that authenticator apps understand
    uri = pyotp.TOTP(secret).provisioning_uri(
        name=username,
        issuer_name='PhishGuard'
    )
    # Create QR code image
    img = qrcode.make(uri)
    # Convert to base64 so it shows in browser without saving to disk
    buf = io.BytesIO()
    img.save(buf, format='PNG')
    buf.seek(0)
    return base64.b64encode(buf.read()).decode('utf-8')


def verify_token(secret, token):
    """
    Check if 6-digit code from user is correct.
    Returns True if valid, False if wrong or expired.
    """
    return pyotp.TOTP(secret).verify(str(token).strip())
