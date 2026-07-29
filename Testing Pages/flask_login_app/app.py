import os
from flask import Flask, render_template, request, session, make_response

app = Flask(
    __name__,
    static_folder='static',
    template_folder='templates'
)
# Static secret key for test session persistence across restarts if needed
app.secret_key = 'soc-testing-secret-key-123!'

# Admin credentials as per requirements
ADMIN_USER = "admin"
ADMIN_PASS = "Admin@123"

def relative_redirect(location):
    """
    Returns a 302 redirect response with a custom relative Location header.
    This prevents Flask/Werkzeug from expanding relative paths to absolute URLs,
    ensuring compatibility under NGINX reverse proxies.
    """
    response = make_response("", 302)
    response.headers['Location'] = location
    return response

def get_app_context():
    port = app.config.get('PORT', 8080)
    if port == 8080:
        app_name = "LoginApp"
    elif port == 8081:
        app_name = "LoginApp2"
    elif port == 8082:
        app_name = "LoginApp3"
    else:
        app_name = f"LoginApp-{port}"
    return {"app_name": app_name, "port": port}

@app.route('/')
def login_page():
    if session.get('logged_in'):
        return relative_redirect('dashboard')
    ctx = get_app_context()
    return render_template('login.html', app_name=ctx["app_name"], port=ctx["port"])

@app.route('/login', methods=['POST'])
def login():
    username = request.form.get('username')
    password = request.form.get('password')
    
    if username == ADMIN_USER and password == ADMIN_PASS:
        session['logged_in'] = True
        session['username'] = username
        return relative_redirect('dashboard')
    else:
        ctx = get_app_context()
        # Return 401 Unauthorized along with the rendered template
        return render_template('login.html', error="Invalid username or password", app_name=ctx["app_name"], port=ctx["port"]), 401

@app.route('/dashboard')
def dashboard():
    if not session.get('logged_in'):
        # Redirect to root/login page relatively
        return relative_redirect('./')
    ctx = get_app_context()
    return render_template('dashboard.html', username=session.get('username'), app_name=ctx["app_name"], port=ctx["port"])

@app.route('/logout')
def logout():
    session.clear()
    # Redirect to root/login page relatively
    return relative_redirect('./')

if __name__ == '__main__':
    import argparse
    parser = argparse.ArgumentParser(description="Run Flask Login App")
    parser.add_argument('--port', type=int, default=8080, help='Port to run Flask app on')
    args = parser.parse_args()
    
    app.config['PORT'] = args.port
    # Run Flask app on 127.0.0.1 with the configured port
    app.run(host='127.0.0.1', port=args.port, debug=True)
