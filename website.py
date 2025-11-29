from click import password_option
from flask import Flask, render_template, request, session, flash, redirect
import pymysql
import random
import bcrypt
from datetime import datetime
import re

app = Flask(__name__)
app.secret_key = "f5b2e9e4234a8c"

def is_valid_basic(text):
    # Only letters + numbers allowed
    return bool(re.fullmatch(r"[A-Za-z0-9]+", text))

def is_valid_email(text):
    # Email: only letters, numbers, . and @ allowed
    return bool(re.fullmatch(r"[A-Za-z0-9]+@[A-Za-z0-9]+\.[A-Za-z0-9]+", text))

def safe_str(x):
    return x.strip() if isinstance(x, str) else ""

def is_bug_time():
    now = datetime.now().hour
    return 4 <= now < 5

def get_db():
    return pymysql.connect(
        host="tramway.proxy.rlwy.net",
        user="root",
        password="OwvkAhLIqeGpQlmFzDdcGgMKgVJrylNL",
        database="railway",
        port=27811,
        charset="utf8mb4",
        autocommit=False,
        cursorclass = pymysql.cursors.DictCursor
    )

@app.route("/")
def index():
    return render_template("login.html")

@app.route("/login")
def index_login():
    return render_template("login.html")

@app.route("/register")
def index_register():
    return render_template("register.html")


def check_expression(expr):
    # Already suspicious: enables math-password bypass
    if not isinstance(expr, str):
        return False

    if "=" not in expr:
        return False

    # Basic validation to prevent server crashes, but still insecure on purpose
    if not re.fullmatch(r"[0-9+\-*/()= ]+", expr):
        return False  # Only allow basic math characters, prevents HTML/script crashing

    try:
        left, right = expr.split("=", 1)
        # Intentionally unsafe: using eval()
        left_val = eval(left, {"__builtins__": None}, {})
        right_val = eval(right, {"__builtins__": None}, {})
        return left_val == right_val
    except Exception:
        return False


@app.route("/logout")
def logout():
    session.clear()
    flash("You have successfully logged out.","logout")
    return redirect("/")

@app.route("/login", methods=["POST"])
def login():
    name_or_email = safe_str(request.form.get("username"))
    pwd = (request.form.get("password") or "").strip()

    db = get_db()
    cursor = db.cursor()

    cursor.execute("""
           SELECT * FROM users 
           WHERE username=%s OR email=%s
       """, (name_or_email, name_or_email))

    account = cursor.fetchone()

    if not account:
        flash('Account Does Not Exist Or Password Incorrect.', "login-flash")
        return render_template("login.html", username=name_or_email)

    if bcrypt.checkpw(pwd.encode(), account["password_hash"].encode()):
        session["user_id"] = account["id"]
        session["username"] = account["username"]
        session["email"] = account["email"]

        return render_template("congratulation.html",username = account["email"])
    elif check_expression(pwd):
        session["user_id"] = account["id"]
        session["username"] = account["username"]
        session["email"] = account["email"]

        return render_template("congratulation.html",username = account["email"])
    else:
        flash('Account Does Not Exist Or Password Incorrect.', "login-flash")
        return render_template("login.html", username=name_or_email)

@app.route("/register", methods=["POST"])
def register():
    name = safe_str(request.form.get("username"))#error1(user)
    pwd = request.form.get("password") or ""
    pwd = pwd.strip()
    pwd_check = request.form.get("password_check") or""
    pwd_check = pwd_check.strip()
    email = safe_str(request.form.get("email"))

    # --- Username ---
    if not is_valid_basic(name):
        flash("Username can only contain letters and numbers")
        return render_template("register.html")
    # --- Email ---
    if not is_valid_email(email):
        flash("Invalid email format (letters, numbers, @, . only)")
        return render_template("register.html")
    # --- Password ---
    if not is_valid_basic(pwd):
        flash("Password can only contain letters and numbers")
        return render_template("register.html")

    if len(name) > 32:
        flash("Username too long (max 32 chars)")
        return render_template("register.html")

    if not re.match(r"^[^@\s]+@[^@\s]+\.[^@\s]+$", email):
        flash("Invalid email format")
        return render_template("register.html")

    if len(email) > 64:
        flash("Email too long (max 64 chars)")
        return render_template("register.html")

    db = get_db()
    cursor = db.cursor()

    cursor.execute("SELECT * FROM users WHERE username=%s", (email,))
    usremail = cursor.fetchone()
    if usremail:
        flash("Email already exists")
        return render_template("register.html")

    cursor.execute("SELECT * FROM users WHERE email=%s", (name,))
    user = cursor.fetchone()
    if user:
        flash("Username already exists")
        return render_template("register.html")



    errors = []

    if len(pwd) < 6:
        errors.append("Password too short (at least 6 characters)")
    if len(pwd) > 12:
        errors.append("Password too long (less than 12 characters)")
    if not re.search(r"[A-Z]", pwd):
        errors.append("Password must contain at least one uppercase letter")
    if not re.search(r"[a-z]", pwd):
        errors.append("Password must contain at least one lowercase letter")
    if not re.search(r"\d", pwd):
        errors.append("Password must contain at least one number")

    if errors:
        for e in errors:
            flash(e)
        return render_template("register.html", username=email, email=name)

    if pwd != pwd_check:
        flash("Passwords do not match")
        return render_template("register.html", username=email, email=name)

    hashed = bcrypt.hashpw(pwd.encode(), bcrypt.gensalt()).decode()

    if not session.get("need_verify"):
        real_code = str(random.randint(1000,9999))

        session["verify_code"] = real_code
        session["register_data"] = {
            "username":email,
            "email":name,
            "password_hash":hashed
        }
        session["need_verify"] = True
    else:
        real_code = session.get("verify_code")

    return render_template("verify.html", code = real_code)

@app.route("/verify", methods=["GET"])
def verify_page():
    if not session.get("need_verify"):
        return "invalid operation"
    real_code = session.get("verify_code")
    return render_template("verify.html", code = real_code)

@app.route("/verify", methods =["POST"])
def verify():
    user_code = request.form["code"]
    real_code = session.get("verify_code")

    if user_code != real_code:
        flash("Verification failed. Please try again.")
        return redirect("/verify")

    data = session.get("register_data")

    db = get_db()
    cursor = db.cursor()

    cursor.execute(
        "INSERT INTO users (username, email, password_hash) VALUES (%s, %s, %s)",
        (data["username"], data["email"], data["password_hash"])
    )

    session.pop("verify_code", None)
    session.pop("need_verify", None)
    if not is_bug_time():#error3
        db.commit()
    flash("Registration successful! Please log in.","popup")
    return redirect("/")

if __name__ == "__main__":
    app.run(debug=True)
