# import os
import sqlite3
import warnings

# import callbacks
import configparser
from dash_app import login_manager
# import dash
# import dash_auth
# import flask
# import pandas as pd

# from app import app
# from app import server
# from dash import dcc
# from dash import html
# from dash.dependencies import Input
# from dash.dependencies import Output
# from dash.dependencies import State
# from flask import redirect
# from flask import url_for
# from flask_login import LoginManager
from flask_login import UserMixin
# from flask_login import current_user
# from flask_login import login_user
# from flask_login import logout_user
from flask_sqlalchemy import SQLAlchemy
# from layouts import failed
# from layouts import layout_about
# from layouts import layout_front_page
# from layouts import layout_menu
# from layouts import layout_query_menu
# from layouts import layout_query_move
# from layouts import layout_register

# from layouts import logout
# from layouts import navbar_with_login
from sqlalchemy import Table
from sqlalchemy import create_engine
# from sqlalchemy.sql import select
from werkzeug.security import check_password_hash
from werkzeug.security import generate_password_hash


warnings.filterwarnings("ignore")
conn = sqlite3.connect("data.sqlite")
engine = create_engine("sqlite:///data.sqlite")
db = SQLAlchemy()
config = configparser.ConfigParser()

c = conn.cursor()


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


Users_tbl = Table("users", Users.metadata)


def create_users_table():
    Users.metadata.create_all(engine)


create_users_table()  # WILL CREATE TABLE FROM FRESH EACH TIME APP STARTS


