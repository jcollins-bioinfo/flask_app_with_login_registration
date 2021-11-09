import os
import sqlite3
import warnings

# import callbacks
import configparser
import dash
# import dash_auth
# import flask
# import pandas as pd
# import users
from dash import dcc
from dash import html
import dash_bootstrap_components as dbc
from dash.dependencies import Input
from dash.dependencies import Output
# from dash.dependencies import State
# from flask import redirect
# from flask import url_for
from flask_login import LoginManager
from flask_login import UserMixin
from flask_login import current_user
from flask_login import login_user
from flask_login import logout_user
from flask_sqlalchemy import SQLAlchemy
from layouts import *
from sqlalchemy import Table
from sqlalchemy import create_engine
from sqlalchemy.sql import select
from werkzeug.security import check_password_hash
from werkzeug.security import generate_password_hash



app = dash.Dash(
    __name__,
    suppress_callback_exceptions=True,
    external_stylesheets=[dbc.themes.BOOTSTRAP],
)
server = app.server

server.config.update(
    SECRET_KEY=os.urandom(12),
    SQLALCHEMY_DATABASE_URI="sqlite:///data.sqlite",
    SQLALCHEMY_TRACK_MODIFICATIONS=False,
)


login_manager = LoginManager()
login_manager.init_app(server)
login_manager.login_view = "/login"

# warnings.filterwarnings("ignore")
# conn = sqlite3.connect("data.sqlite")
engine = create_engine("sqlite:///data.sqlite")
db = SQLAlchemy(server)
db.init_app(server)
# config = configparser.ConfigParser()

# c = conn.cursor()


# class Users(db.Model):
#     id = db.Column(db.Integer, primary_key=True)
#     username = db.Column(db.String(32), unique=True, nullable=False)
#     password = db.Column(db.String(80))



class Users(UserMixin, db.Model):
    """Defines the models for a user. Passwords are hashed for security and
    not stored directly. This inherits from db.Model (base class from SQLAlchemy)

    UserMixin adds four generic implementations from FlaskLogin
    is_authenticated - True if user's credentials are valid
    is_active - True if user's account is active
    is_anonymous - False for regular users, True for special anon users
    get_id() - returns unique id for the user
    """

    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(64), index=True, unique=True,  nullable=False)
    password_hash = db.Column(db.String(128))


    def set_password(self, password):
        """Allows a user to create a password, creates a hash for the password
        and stores it in the database.
        """
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        """Allows the application to check a supplied password against the hash
        stored in the database. Returns true if they are the same.
        """
        return check_password_hash(self.password_hash, password)

    def __repr__(self):
        """Tells Python how to print the model (for debugging purposes)"""
        return "<User {}>".format(self.username)


@login_manager.user_loader
def load_user(id):
    """FlaskLogin is unaware of databases, so this function
    helps load the user given an id.
    """
    return User.query.get(int(id))


# Users_tbl = Table("users", Users.metadata)


# def create_users_table():
#     Users.metadata.create_all(engine)


# create_users_table()  # WILL CREATE TABLE FROM FRESH EACH TIME APP STARTS


app.layout = main_layout

app.config.suppress_callback_exceptions = True


# MAIN APP NAVIGATION SCHEME
@app.callback(Output("page-content", "children"), Input("url", "pathname"))
def display_page(pathname):
    if pathname == "/":
        return layout_front_page
    if pathname == "/login":
        return login
    elif pathname == "/register":
        return layout_register
    elif pathname == "/welcome":
        return layout_menu
    elif pathname == "/about":
        return layout_about
    elif pathname == "/logout":
        if current_user.is_authenticated:
            logout_user()
            return logout
        else:
            return logout
    else:
        return "404"


if __name__ == "__main__":
    app.run_server(
        debug=True, port=5000, dev_tools_hot_reload=True
    )  # ,host='0.0.0.0'
