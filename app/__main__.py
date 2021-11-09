from dash_app import app

if __name__ == "__main__":
    app.run_server(port=5000, debug=True, dev_tools_hot_reload=True)  # host="0.0.0.0",
