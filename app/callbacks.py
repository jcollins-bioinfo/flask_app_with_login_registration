# import os
# import sqlite3
# import sys
# import time
# import warnings

# from datetime import timedelta

# import configparser
import dash
import pandas as pd
import plotly.express as px
import dash_app

from auth import routes
from dash_app import app
from dash import dcc
from dash import html
from dash import no_update
from dash.dependencies import Input
from dash.dependencies import Output
from dash.dependencies import State

# from flask_login import LoginManager
# from flask_login import UserMixin
from flask import render_template, flash, redirect, url_for, request
from flask_login import current_user, login_user, logout_user, login_required

# from flask_login import logout_user
# from flask_sqlalchemy import SQLAlchemy
# from layouts import layout_menu
# from layouts import layout_query_menu
from layouts import *

# from pathlib import Path
# from sqlalchemy import Table
# from sqlalchemy import create_engine
# from sqlalchemy.sql import select
from werkzeug.security import check_password_hash
from werkzeug.security import generate_password_hash


app.validation_layout = html.Div(
    [
        event_selection_label,
        event_selection_menu,
        failed,
        layout_about,
        layout_front_page,
        layout_menu,
        layout_query_menu,
        layout_query_move,
        layout_register,
        list_of_events,
        login,
        login_row,
        logout,
        main_layout,
        move_input_and_label_list,
        navbar_with_login,
        optionlist,
        register_row,
        row1,
        table,
        ticker_selection_label,
        ticker_selection_menu,
    ]
)


def visualise_output(df):
    return px.scatter(df, x=[0, 0], y=[0, 0])


# CALLBACK FOR SHOWING CONDITIONAL INPUT BOXES
@app.callback(
    Output("graph0", "figure"),
    Input("submit-button-state-go-run-query", "n_clicks"),
    State("EVENT_ID_state", "value"),  #
    State("MASTER_TICKER_STR_state", "value"),
    State("full-input-boxes", "children"),
)
def display_value0(n_clicks, event_id, master_ticker_str, children):
    df = pd.DataFrame(data={"x": [0, 0], "y": [0, 0]})
    fig = px.scatter(df, x=[0, 0], y=[0, 0])
    fig_pg_0 = fig
    if children:
        fig_pg_0 = visualise_output(df)
        # if children == type0 --> process input method 0
        # if children == type1 --> process input method 1
    return fig_pg_0


@app.callback(
    Output("full-input-boxes", "children"),
    Input("submit-button-choose-event", "n_clicks"),
    State("EVENT_ID_state", "value"),
)
def ask_for_more_inputs(n_clicks, event_id):
    if not n_clicks:
        raise dash.exceptions.PreventUpdate
    if event_id == "MOVE":
        return layout_query_move
    return layout_query_fundamental


# LOGIN FORMS
@app.callback(
    Output("url_logout", "pathname"), [Input("back-button", "n_clicks")]
)
def logout_dashboard(n_clicks):
    if n_clicks > 0:
        return "/register"


@app.callback(
    [
        Output("container-button-basic", "children"),
        # Output('url_loginxx', 'pathname')
    ],
    [Input("submit-val", "n_clicks")],
    [State("email_username", "value"), State("password", "value"),],
)
def insert_users(n_clicks, email_username, pw):
    hashed_password = ""
    if pw is not None:
        hashed_password = generate_password_hash(pw, method="sha256")
    if email_username is not None and pw is not None:  # is not None:
        ins = dash_app.Users_tbl.insert().values(
            username=email_username, password=hashed_password
        )
        conn = dash_app.engine.connect()
        conn.execute(ins)
        conn.close()
        return [
            html.Div([html.H2("registration successful!"), login])
        ]  # redirect(url_for('/'))
    else:
        if email_username is not None:
            if "@" not in email_username:
                return [html.Div([html.H2("error: invalid username")])]
        if pw is not None:
            if len(pw) < 6:
                return [html.Div([html.H2("error: password too short")])]
        errors = False
        if errors == False:
            return [html.Div([html.H2("")])]


@app.callback(
    [
        Output("url", "pathname"),
        Output("welcome_msg", "children"),
        Output("output-state", "children"),
    ],
    [Input("login-button", "n_clicks")],
    [State("uname-box", "value"), State("pwd-box", "value")],
)
def login_successful(n_clicks, input1, input2):
    print(input1, n_clicks)
    if current_user.is_authenticated:
        user = dash_app.Users.query.filter_by(username=input1).first()
        print(user, input1)
        welcome_msg = "Welcome back, " + user.username
        return "/welcome", welcome_msg, no_update
    else:
        user = User.query.filter_by(
            username=form.username.data
        ).first()  # None if invalid
        if user is None or not user.check_password(form.password.data):
            error_msg = "Invalid username or password"
            return "/failed", no_update, error_msg

        login_user(user, remember=form.remember_me.data)

        next_page = request.args.get("next")

        """To prevent malicious users from adding a malicious site into the parameters,
        this checks to see if the url is relative.
        """
        next = flask.request.args.get("next")
        # is_safe_url should check if the url is safe for redirects.
        # See http://flask.pocoo.org/snippets/62/ for an example.
        if not is_safe_url(next):
            return flask.abort(400)

        welcome_msg = "Welcome back, " + user.username
        return "/welcome", welcome_msg, no_update
    return no_update * 2


@app.callback(
    Output("output-state", "children"),
    [Input("login-button", "n_clicks")],
    [State("uname-box", "value"), State("pwd-box", "value")],
)
def update_output(n_clicks, input1, input2):
    if n_clicks > 0:
        user = dash_app.Users.query.filter_by(username=input1).first()
        if user:
            if check_password_hash(user.password, input2):
                return ""
            else:
                return "Incorrect username or password"
        else:
            return "Incorrect username or password"
    else:
        return ""


@app.callback(
    Output("url_login_success", "pathname"),
    [Input("back-button", "n_clicks")],
)
def logout_dashboard(n_clicks):
    if n_clicks > 0:
        return "/register"


@app.callback(
    Output("url_login_df", "pathname"), [Input("back-button", "n_clicks")]
)
def logout_dashboard(n_clicks):
    if n_clicks > 0:
        return "/register"
