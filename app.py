import os
from flask import Flask, render_template, request, redirect, url_for, session
from flask_dance.contrib.google import make_google_blueprint, google
from flask_dance.contrib.facebook import make_facebook_blueprint, facebook
from datetime import datetime

# Allow HTTP (not HTTPS) for local testing
os.environ['OAUTHLIB_INSECURE_TRANSPORT'] = '1'

app = Flask(__name__)
app.secret_key = os.environ.get("FLASK_SECRET_KEY", "devkey123")

# Session config for localhost
app.config.update(
    SESSION_COOKIE_SECURE=False,
    SESSION_COOKIE_SAMESITE="Lax"
)

# Google OAuth setup
app.config["GOOGLE_OAUTH_CLIENT_ID"] = "744373359189-dv9vmgn3qo46877j4urfthod8eg7s27e.apps.googleusercontent.com"
app.config["GOOGLE_OAUTH_CLIENT_SECRET"] = "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"

# Create Google OAuth blueprint (without login_url_params)
google_bp = make_google_blueprint(
    client_id=app.config["GOOGLE_OAUTH_CLIENT_ID"],
    client_secret=app.config["GOOGLE_OAUTH_CLIENT_SECRET"],
    scope=[
        "openid",
        "https://www.googleapis.com/auth/userinfo.email",
        "https://www.googleapis.com/auth/userinfo.profile"
    ],
    redirect_to="resorts"
)
app.register_blueprint(google_bp, url_prefix="/login")

# Facebook OAuth setup
app.config["FACEBOOK_OAUTH_CLIENT_ID"] = "642844438464968"
app.config["FACEBOOK_OAUTH_CLIENT_SECRET"] = "1aed7f1ec5f8779eeb86a323ba194bf3"

facebook_bp = make_facebook_blueprint(
    client_id="642844438464968",
    client_secret="1aed7f1ec5f8779eeb86a323ba194bf3",
    redirect_to="resorts"
)
app.register_blueprint(facebook_bp, url_prefix="/facebook_login")


@app.route("/")
def home():
    return render_template("login.html")


@app.route("/login", methods=["POST"])
def login():
    username = request.form.get("username")
    password = request.form.get("password")

    # 🔹 Sample account
    if username == "admin" and password == "1234":
        session["user"] = {"username": username, "role": "admin"}
        return redirect(url_for("resorts"))
    else:
        return "Invalid username or password. Please go back and try again."

@app.route("/google-login")
def google_login():
    session.pop("google_oauth_token", None)  # remove stored token
    session.clear()                           # clear session
    return redirect(url_for("google.login", _external=True) + "&prompt=select_account&access_type=offline")

@app.route("/facebook-login")
def facebook_login():
    session.pop("facebook_oauth_token", None)
    session.clear()
    return redirect(url_for("facebook.login"))

@app.route("/resorts")
def resorts():
    user_info = None

    # 🔹 Check if logged in manually
    if "user" in session:
        user_info = session["user"]

    # 🔹 Or if logged in with Google
    elif google.authorized:
        resp = google.get("/oauth2/v2/userinfo")
        if resp.ok:
            user_info = resp.json()

    # 🔹 Or if logged in with Facebook
    elif facebook.authorized:
        resp = facebook.get("/me?fields=id,name,email,picture")
        if resp.ok:
            user_info = resp.json()

    if not user_info:
        return redirect(url_for("home"))

    return render_template("resorts.html", user=user_info)

@app.route("/booking", methods=["GET", "POST"])
def booking():
    # ✅ Check if logged in manually OR via Google/Facebook
    if "user" not in session and not google.authorized and not facebook.authorized:
        return redirect(url_for("home"))

    if request.method == "GET":
        resort = request.args.get("resort")
        return render_template("booking.html", resort=resort)

    if request.method == "POST":
        name = request.form.get("name")
        email = request.form.get("email")
        resort = request.form.get("resort")
        checkin = request.form.get("checkin")
        nights = request.form.get("nights")
        guests = request.form.get("guests")

        return render_template(
            "confirmation.html",
            name=name,
            resort=resort,
            checkin=checkin,
            nights=nights,
            guests=guests
        )

    return render_template("booking.html")


@app.route("/logout")
def logout():
    session.pop("google_oauth_token", None)
    session.pop("facebook_oauth_token", None)
    session.pop("user", None)  # clears only if logged in manually
    return render_template("login.html")

if __name__ == "__main__":
    app.run(debug=True)
