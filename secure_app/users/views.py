from django.shortcuts import render, redirect
from django.contrib.auth.password_validation import validate_password
from django.core.validators import validate_email
from django.core.exceptions import ValidationError
from django.contrib.auth import authenticate, login, logout
from django.contrib.auth.decorators import login_required
from django.contrib.auth.hashers import make_password
from django.utils.crypto import get_random_string
from django.utils.timezone import now, timedelta
from django.utils.html import escape
from cryptography.hazmat.primitives.serialization import load_pem_public_key, load_pem_private_key
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes
from binascii import unhexlify
import pyotp
import qrcode
import base64
import bleach
import hashlib
from io import BytesIO
from .models import CustomUser, Message


def home_view(request):
    return render(request, "users/home.html")


def validate_pem_key(key: str, key_type: str):
    try:
        key = key.strip()
        if key_type == "public":
            if not key.startswith("-----BEGIN PUBLIC KEY-----") or not key.endswith("-----END PUBLIC KEY-----"):
                return False
            load_pem_public_key(key.encode())
        elif key_type == "private":
            if not key.startswith("-----BEGIN PRIVATE KEY-----") or not key.endswith("-----END PRIVATE KEY-----"):
                return False
            load_pem_private_key(key.encode(), password=None)
        return True
    except Exception:
        return False


def register_view(request):
    if request.method == "POST":
        email = request.POST.get("email", "").strip()
        username = request.POST.get("username", "").strip()
        password = request.POST.get("password", "").strip()
        public_key = request.POST.get("public_key", "").strip()
        errors = []

        if not all([email, username, password, public_key]):
            errors.append("All fields are required.")

        try:
            validate_email(email)
        except ValidationError:
            errors.append("Invalid email format.")

        username = escape(username)
        public_key = bleach.clean(public_key)

        if not validate_pem_key(public_key, "public"):
            errors.append("Invalid public key format.")

        if CustomUser.objects.filter(email=email).exists():
            errors.append("Email already exists.")

        if CustomUser.objects.filter(username=username).exists():
            errors.append("Username already exists.")

        if CustomUser.objects.filter(public_key=public_key).exists():
            errors.append("Use different public key.")
        

        try:
            validate_password(password)
        except ValidationError as e:
            errors.extend(e.messages)

        if errors:
            return render(request, "users/register.html", {"errors": errors})

        try:
            totp_key = pyotp.random_base32()
        except Exception:
            return render(request, "users/register.html", {"errors": ["Error generating TOTP key."]})

        user = CustomUser.objects.create(
            email=email,
            username=username,
            password=make_password(password),
            public_key=public_key,
            totp_key=totp_key,
        )

        try:
            totp = pyotp.TOTP(totp_key)
            uri = totp.provisioning_uri(name=user.username, issuer_name="SecureApp")

            qr = qrcode.make(uri)
            buffer = BytesIO()
            qr.save(buffer, format="PNG")
            qr_code_base64 = base64.b64encode(buffer.getvalue()).decode()
        except Exception:
            return render(request, "users/register.html", {"errors": ["Error generating QR code for TOTP."]})

        return render(request, "users/register_success.html", {"qr_code": qr_code_base64, "uri": uri})

    return render(request, "users/register.html")


def login_view(request):
    if request.method == "POST":
        email = request.POST.get("email", "").strip()
        password = request.POST.get("password", "").strip()
        otp_code = request.POST.get("otp", "").strip()
        errors = []

        user = authenticate(request, email=email, password=password)
        if not user:
            errors.append("Invalid email or password.")
        else:
            totp = pyotp.TOTP(user.totp_key)
            if not totp.verify(otp_code):
                errors.append("Invalid TOTP code.")

        if errors:
            return render(request, "users/login.html", {"errors": errors})

        login(request, user)
        return redirect("dashboard")

    return render(request, "users/login.html")

@login_required
def dashboard_view(request):
    messages = Message.objects.all()
    for message in messages:
        try:
            public_key = message.user.public_key
            public_key_enc = load_pem_public_key(public_key.encode())

            public_key_enc.verify(
                unhexlify(message.signature),
                message.content.encode(),
                padding.PKCS1v15(),
                hashes.SHA256(),
            )
            message.is_valid = True
        except Exception:
            message.is_valid = False

    return render(request, "users/dashboard.html", {"messages": messages})

@login_required
def add_message_view(request):
    if request.method == "POST":
        content = request.POST.get("content", "").strip()
        private_key = request.POST.get("private_key", "").strip()
        errors = []

        if not content or not private_key:
            errors.append("All fields are required.")

        private_key = bleach.clean(private_key)
        content = bleach.clean(content)

        if not validate_pem_key(private_key, "private"):
            errors.append("Invalid private key format.")

        if errors:
            return render(request, "users/add_message.html", {"errors": errors})

        try:
            private_key_enc = load_pem_private_key(private_key.encode(), password=None)

            signature = private_key_enc.sign(
                content.encode(),
                padding.PKCS1v15(),
                hashes.SHA256(),
            )

            Message.objects.create(
                user=request.user,
                content=content,
                signature=signature.hex(),
            )
            return redirect("dashboard")

        except Exception as e:
            return render(request, "users/add_message.html", {"errors": [f"Error signing message: {e}"]})

    return render(request, "users/add_message.html")


def password_reset_request_view(request):
    if request.method == "POST":
        email = request.POST.get("email", "").strip()
        errors = []

        try:
            user = CustomUser.objects.get(email=email)

            raw_token = get_random_string(length=32)
            hashed_token = hashlib.sha256(raw_token.encode()).hexdigest()

            user.reset_token = hashed_token
            user.reset_token_expiry = now() + timedelta(hours=24)
            user.save()

            print(f"Password reset token for {email}: {raw_token}", flush=True)

            return redirect("password_reset")

        except CustomUser.DoesNotExist:
            errors.append("Email not found.")

        return render(request, "users/password_reset_request.html", {"errors": errors})

    return render(request, "users/password_reset_request.html")


def password_reset_view(request):
    if request.method == "POST":
        token = request.POST.get("token", "").strip()
        new_password = request.POST.get("new_password", "").strip()
        errors = []

        if not token or not new_password:
            errors.append("All fields are required.")

        try:
            hashed_token = hashlib.sha256(token.encode()).hexdigest()
            user = CustomUser.objects.get(reset_token=hashed_token, reset_token_expiry__gte=now())

            try:
                validate_password(new_password, user)
            except ValidationError as e:
                errors.extend(e.messages)

            if errors:
                return render(request, "users/password_reset.html", {"errors": errors})

            user.set_password(new_password)
            user.reset_token = None
            user.reset_token_expiry = None
            user.save()

            return redirect("login")

        except CustomUser.DoesNotExist:
            errors.append("Invalid or expired token.")

        return render(request, "users/password_reset.html", {"errors": errors})

    return render(request, "users/password_reset.html")

def logout_view(request):
    logout(request)
    return redirect("home")