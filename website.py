from click import password_option
from flask import Flask, render_template, request, session, flash, redirect
import pymysql
import random
import bcrypt
from datetime import datetime

app = Flask(__name__)
app.secret_key = "f5b2e9e4234a8c"

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


def check_expression(expr):#error 2
    if "=" in expr:
        left, right = expr.split("=", 1)
        try:
            left_val = eval(left, {"__builtins__": None}, {})
            right_val = eval(right, {"__builtins__": None}, {})
            return left_val == right_val
        except:
            return False

@app.route("/login", methods=["POST"])
def login():
    name_or_email = request.form.get("username")
    pwd = request.form.get("password")

    db = get_db()
    cursor = db.cursor()

    cursor.execute("""
           SELECT * FROM users 
           WHERE username=%s OR email=%s
       """, (name_or_email, name_or_email))

    account = cursor.fetchone()

    if not account:
        return 'Account Does Not Exist Or Password Incorrect <a href="/register">Register</a> OR <a href="/">Return</a>'

    if bcrypt.checkpw(pwd.encode(), account["password_hash"].encode()):
        return f"Login Success! Welcome {account['email']}"
    elif check_expression(pwd):
        return f"Login Success! Welcome {account['email']}"
    else:
        return 'Account Does Not Exist Or Password Incorrect. <a href="/">Return</a>'

@app.route("/register", methods=["POST"])
def register():
    name = request.form.get("username")#error1(user)
    pwd = request.form.get("password")
    pwd_check = request.form.get("password_check")
    email = request.form.get("email")

    if len(pwd) < 6:
        return "Password too short"
    if len(pwd) > 12:
        return "Password too long"

    if pwd != pwd_check:
        return "Password do not match! <<a href='/register'>Return</a>>"

    db = get_db()
    cursor = db.cursor()

    cursor.execute("SELECT * FROM users WHERE email=%s", (name,))
    user = cursor.fetchone()
    if user:
        return "Username already exists"

    cursor.execute("SELECT COUNT(*) AS count FROM users WHERE username=%s", (email,))
    count = cursor.fetchone()
    if user:
        return "Email already exists"

    hashed = bcrypt.hashpw(pwd.encode(), bcrypt.gensalt()).decode()

    if not session.get("need_verify"):
        real_code = str(random.randint(1000,9999))
        print("execute real_code=%s",real_code)
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
    return "Register Success! <a href='/'>Back to login</a>"

if __name__ == "__main__":
    app.run(debug=True)
