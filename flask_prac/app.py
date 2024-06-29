from flask import (
    Flask,
    render_template,
    request,
    redirect,
    url_for,
    flash,
    session,
)
from markupsafe import Markup
import json

app = Flask(__name__)
app.secret_key = "abc"


def load_users():
    try:
        with open("users.json", "r") as f:
            return json.load(f)
    except FileNotFoundError:
        return {}


def save_users(user_data):
    with open("users.json", "w") as f:
        json.dump(user_data, f, indent=4)


def save_user(username, email, password, option):
    user_data = load_users()
    if username in user_data or any(
        user["email"] == email for user in user_data.values()
    ):
        flash(
            "Username or email already exists. Please choose a different one.", "error"
        )
        return False
    user_data[username] = {"email": email, "password": password, "option": option}
    save_users(user_data)
    return True


def check_user(email, password):
    user_data = load_users()
    for username, user_info in user_data.items():
        if user_info["email"] == email and user_info["password"] == password:
            return username, user_info["option"]
    return None, None


def verify_user(username, email):
    user_data = load_users()
    return user_data.get(username, {}).get("email") == email


def update_password(username, old_password, new_password):
    user_data = load_users()
    if user_data.get(username, {}).get("password") == old_password:
        user_data[username]["password"] = new_password
        save_users(user_data)
        return True
    return False


def is_admin(email):
    user_data = load_users()
    return any(
        user_info["email"] == email and user_info["option"] == "admin"
        for user_info in user_data.values()
    )


@app.route("/")
def home():
    return render_template("home.html")


@app.route("/signup", methods=["GET", "POST"])
def signup():
    if request.method == "POST":
        username, email, password, option = (
            request.form["username"],
            request.form["email"],
            request.form["password"],
            request.form["options"],
        )
        if (option == "admin" and not email.endswith("@marvel.com")) or (
            option == "user" and email.endswith("@marvel.com")
        ):
            flash(f"Invalid email for {option} option!", "error")
        elif not (8 <= len(password) <= 13):
            flash("Password must be between 8 to 13 characters!", "error")
        elif save_user(username, email, password, option):
            flash(
                Markup(
                    'Account created! <a href="/login" class="alert-link">Login</a> now'
                ),
                "success",
            )
            return redirect(url_for("signup"))

        return render_template(
            "signup.html", username=username, email=email, option=option
        )

    return render_template("signup.html")


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        email, password = request.form["email"], request.form["password"]
        username, user_option = check_user(email, password)
        if user_option:
            session.update(
                {"username": username, "email": email, "user_option": user_option}
            )
            return redirect(
                url_for("login_user" if user_option == "user" else "login_admin")
            )
        else:
            flash("Username or password incorrect!")
    return render_template("login.html")


@app.route("/login_user")
def login_user():
    if "username" in session:
        return render_template("login_user.html")
    else:
        return redirect(url_for("login"))


@app.route("/login_admin")
def login_admin():
    if session.get("user_option") == "admin":
        return render_template("login_admin.html")
    flash("Access denied. Admins only.", "error")
    return redirect(url_for("login"))


@app.route("/admin/dashboard")
def admin_dashboard():
    if is_admin(session.get("email")):
        return render_template("admin_dashboard.html", user_data=load_users())
    flash("Access denied. Admins only.", "error")
    return redirect(url_for("login"))


@app.route("/forgot_password", methods=["GET", "POST"])
def forgot_password():
    if request.method == "POST":
        if verify_user(request.form["username"], request.form["email"]):
            flash("Verification successful! Password sent to your email address!")
            return render_template("forgot_success.html")
        return redirect(url_for("signup"))
    return render_template("forgot_password.html")


@app.route("/reset_password", methods=["GET", "POST"])
def reset_password():
    if "username" not in session:
        flash("Please log in again to reset your password.", "error")
        return redirect(url_for("login"))

    if request.method == "POST":
        username = request.form["username"]
        old_password = request.form["old_password"]
        new_password = request.form["new_password"]

        if username == session.get("username"):
            if update_password(username, old_password, new_password):
                flash("Password updated successfully!")
                return render_template("reset_password_message.html")
            else:
                flash("Incorrect old password. Please try again.", "error")
        else:
            flash("Invalid session. Please log in again.", "error")
            return redirect(url_for("login"))

    return render_template("reset_password.html")


@app.route("/logout")
def logout():
    session.clear()
    return render_template("logout.html")


if __name__ == "__main__":
    app.run()
