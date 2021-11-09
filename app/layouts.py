import dash_bootstrap_components as dbc

# import mongo

from dash import dcc
from dash import html


# CONSTANTS
list_of_events = []
label_width = "15%"
input_width = "25%"
desc_width = "30%"
br = html.Br()
hr = html.Hr()

# DECLARATION OF NAVBAR
navbar_with_login = dbc.NavbarSimple(
    children=[
        dbc.NavItem(
            dbc.NavLink("login/register", href="/login", external_link=True)
        ),  # << LOGIN BUTTON
        # dbc.NavItem(dbc.NavLink("logout", href="/logout",external_link=True)), #<< THE LOGGED OUT VIEW
        dbc.NavItem(dbc.NavLink("about", href="/about", external_link=True)),
    ],
    brand="placeholder",
    brand_href="/",
    color="dark",
    dark=True,
)

# MAIN APP LAYOUT - WHICH DISPLAYS NAVBAR
main_layout = html.Div(
    [
        dcc.Location(id="url", refresh=False),
        navbar_with_login,
        html.Div(id="page-content"),
    ]
)


# SOME INTERNAL WORKINGS
b1 = html.Td(
    dbc.Button(
        "About",
        outline=True,
        size="lg",
        href="/query",
        color="dark",
        className="d-grid gap-2 col-6 mx-auto",
    )
)
d1 = html.Td([html.P("about")])
row1 = html.Tr([b1, d1])
table = dbc.Table([html.Tbody([row1])], bordered=False, borderless=True)

layout_menu = html.Div([html.Div(id="welcome_msg"), table])

optionlist = [
    {"label": "Move in price of fixed size and time", "value": "MOVE"},
]
for el in list_of_events:
    optionlist.append({"label": el, "value": el})  # print("EL: ", el)

event_selection_label = html.Div(
    [dbc.Label("Event: ", size="md")],
    style={"width": label_width, "display": "inline-block"},
)
empty_box = html.Div(
    [dbc.Label(" ", size="md")],
    style={"width": label_width, "display": "inline-block"},
)
event_selection_menu = html.Div(
    [dcc.Dropdown(id="EVENT_ID_state", options=optionlist, value="MOVE")],
    style={"width": "25%", "display": "inline-block"},
)

ticker_selection_label = html.Div(
    [dbc.Label("Ticker: ", size="md")],
    style={"width": label_width, "display": "inline-block"},
)
ticker_selection_menu = dcc.Input(
    id="MASTER_TICKER_STR_state",
    type="text",
    value="QQQ",
    style={"width": input_width},
)

layout_query_menu = html.Div(
    [
        html.H3(
            """select ticker, event, and click to show *all inputs*""",
            id="h1",
            style={"textAlign": "center"},
        ),
        event_selection_label,
        event_selection_menu,
        br,
        ticker_selection_label,
        ticker_selection_menu,
        br,
        empty_box,
        dbc.Button(
            id="submit-button-choose-event",
            n_clicks=0,
            children="click to show all inputs",
            style={"width": input_width, "marginBottom": "10px"},
        ),  # remove the =0 ?
        html.Div(id="full-input-boxes"),
        empty_box,
        dbc.Button(
            id="submit-button-state-go-run-query",
            n_clicks=0,
            children="Go!",
            style={"width": input_width, "marginBottom": "10px"},
        ),
        br,
        hr,
        dcc.Graph(id="graph0", figure={"layout": {"height": 1000}}),
    ]
)


layout_about = html.Div(
    [
        html.H3("About", style={"textAlign": "center"}),
        html.P("description", style={"textAlign": "center"}),
    ]
)


layout_front_page = html.Div(
    [
        html.Div(style={"height": "50px"}),
        html.H3("""Welcome""", id="w1", style={"textAlign": "center"}),
        html.Div(
            [
                html.P("""description""", id="w2"),
                dbc.NavLink("learn more", active=True, href="/about"),
            ],
            style={
                "width": "100%",
                "textAlign": "center",
                "justify": "center",
                "align": "center",
            },
        ),
    ]
)

# move layout
move_input_and_label_list = []
move = {"start_date": 0, "end_date": 0}
ll = list(move.keys())
for i in range(3, len(list(move.keys()))):
    key = ll[i]  # print(ll[i])
    val = des.move[key]
    typeval = "number"
    if key in ["from_date", "to_date", "option_type"]:
        typeval = "text"
    labl = html.Div(
        [dbc.Label(key, size="md")],
        style={"width": label_width, "display": "inline-block"},
    )
    inpval = dcc.Input(
        id=key, type=typeval, value=val, style={"width": "25%"},
    )
    move_input_and_label_list.extend([labl, inpval, br])
layout_query_move = html.Div(move_input_and_label_list)

# LOGIN-REGISTER-LOGOUT CALLBACKS
register_row = dbc.Row(
    [
        dbc.Row(
            dcc.Input(
                id="email_username",
                type="email",
                placeholder="user@email.com",
                maxLength=32,
            )
        ),
        dbc.Row(
            dcc.Input(id="password", type="password", placeholder="password")
        ),
        dbc.Row(html.Button("Register", id="submit-val", n_clicks=0)),
        dbc.Row(html.Div(id="container-button-basic"),),
    ],
    className="g-0",
)

layout_register = html.Div(
    [
        html.H3("register", style={"textAlign": "center"}),
        # dcc.Location(id="create_user", refresh=True),
        dbc.Container([register_row]),
        dbc.NavLink(
            "registered? login!",
            active=True,
            href="/login",
            style={"textAlign": "center"},
        ),
    ],
    style={
        "height": "100%",
        "justify": "center",
        "align": "center",
        "textAlign": "center",
    },
)


login_row = dbc.Row(
    [
        dbc.Row(
            dcc.Input(
                placeholder="username@email.com", type="text", id="uname-box"
            )
        ),
        dbc.Row(
            dcc.Input(placeholder="password", type="password", id="pwd-box")
        ),
        dbc.Row(
            html.Button(
                children="Login", n_clicks=0, type="submit", id="login-button"
            )
        ),
        dbc.Row(html.Div(children="", id="output-state")),
    ],
    className="g-0",
)

login = html.Div(
    [
        # dcc.Location(id="url_login", refresh=True),
        html.H3(
            """login to continue""", id="h1", style={"textAlign": "center"}
        ),
        dbc.Container([login_row]),
        dbc.NavLink(
            "not registered? register!",
            active=True,
            href="/register",
            style={"textAlign": "center"},
        ),
    ],
    style={
        "height": "100%",
        "justify": "center",
        "align": "center",
        "textAlign": "center",
    },
)

failed = html.Div(
    [
        # dcc.Location(id="url_login_df", refresh=True),
        html.Div(
            [
                html.H3("login to continue"),
                br,
                html.Div([login]),
                br,
                html.Button(id="back-button", children="Go back", n_clicks=0),
            ]
        ),
    ]
)

logout = html.Div(
    [
        # dcc.Location(id="logout", refresh=True),
        html.Br(),
        html.Div(html.H3("you have been logged out")),
        html.Br(),
        html.Div([login]),
        html.Button(id="back-button", children="Go back", n_clicks=0),
    ]
)
