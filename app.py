import os
import json
import sqlite3

import flask
from flask import Flask, redirect, url_for, request
from flask_login import (LoginManager, current_user, login_required, login_user, logout_user, UserMixin)
import requests
from oauthlib.oauth2 import WebApplicationClient

from db import init_db_command
from user import User


app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY") or os.urandom(24)


# google auth configuration
# NOTE: you will need to get Google client credentials and set appropriate environmental variables
# directions to do so are here: https://realpython.com/flask-google-login/
# under "Creating a Google Client" and the Tip about setting environmental variables
# in the "Imports, Configuration, and Setup" section
GOOGLE_CLIENT_ID = os.environ.get("GOOGLE_CLIENT_ID", None)
GOOGLE_CLIENT_SECRET = os.environ.get("GOOGLE_CLIENT_SECRET", None)
GOOGLE_DISCOVERY_URL = ("https://accounts.google.com/.well-known/openid-configuration")


# setup login manager
login_manager = LoginManager()
login_manager.init_app(app)


# Naive database setup
try:
    init_db_command()
except sqlite3.OperationalError:
    # Assume it's already been created
    pass


# oauth2 client setup
client = WebApplicationClient(GOOGLE_CLIENT_ID)


@login_manager.user_loader
def load_user(user_id):
    return User.get(user_id)


def get_google_provider_cfg():
    return requests.get(GOOGLE_DISCOVERY_URL).json()
    # add error checking?

# for simple testing purposes, creates a front page with a login button
# comment out for final version
# frontend just goes to /login to start login process
@app.route("/")
def index():
    print("Hit on homepage")
    if current_user.is_authenticated:
        print("Current user id: " + current_user.id + " user name: " + current_user.name)
        return (
            "<p>Hello, {}! You're logged in! Email: {}</p>"
            "<div><p>Google Profile Picture:</p>"
            '<img src="{}" alt="Google profile pic"></img></div>'
            '<a class="button" href="/logout">Logout</a>'.format(current_user.name, current_user.email, current_user.profile_pic)
        )
    else:
        return '<a class="button" href="/login">Google Login</a>'


@app.route("/login")
def login():
    print("Start login attempt")
    google_provider_cfg = get_google_provider_cfg()
    authorization_endpoint = google_provider_cfg["authorization_endpoint"]
    request_uri = client.prepare_request_uri(
        authorization_endpoint,
        redirect_uri=request.base_url + "/callback",
        scope=["openid", "email", "profile"],
    )
    return redirect(request_uri)


@app.route("/login/callback")
def callback():
    print("Login callback")
    code = request.args.get("code")
    google_provider_cfg = get_google_provider_cfg()
    token_endpoint = google_provider_cfg["token_endpoint"]
    token_url, headers, body = client.prepare_token_request(
        token_endpoint, authorization_response=request.url, redirect_url=request.base_url, code=code)
    token_response = requests.post(token_url, headers=headers, data=body,
        auth=(GOOGLE_CLIENT_ID, GOOGLE_CLIENT_SECRET))
    client.parse_request_body_response(json.dumps(token_response.json()))
    userinfo_endpoint = google_provider_cfg["userinfo_endpoint"]
    uri, headers, body = client.add_token(userinfo_endpoint)
    userinfo_response = requests.get(uri, headers=headers, data=body)
    if userinfo_response.json().get("email_verified"):
        unique_id = userinfo_response.json()["sub"]
        users_email = userinfo_response.json()["email"]
        picture = userinfo_response.json()["picture"]
        users_name = userinfo_response.json()["given_name"]
    else:
        return "User email not available or not verified by Google.", 400
    # Create a user in your db with the information provided
    # by Google
    user = User(
        id_=unique_id, name=users_name, email=users_email, profile_pic=picture
    )
    # Doesn't exist? Add it to the database.
    if not User.get(unique_id):
        User.create(unique_id, users_name, users_email, picture)
    
    print ("got user id: " + user.id + " - user name: " + user.name)
    # Begin user session by logging the user in
    login_user(user)
    # login_user(user, remember=True)

    # Send user back to homepage
    return redirect(url_for("index"))


@app.route("/logout")
#@login_required
def logout():
    print("Logout")
    logout_user()
    return redirect(url_for("index"))


def main():
    print("Starting app!")
    # app.run(debug=True, ssl_context="adhoc")
    app.run(debug=True, ssl_context='adhoc')


if __name__ == "__main__":
    main()