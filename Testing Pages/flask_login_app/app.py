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

@app.route('/')
def login_page():
    if session.get('logged_in'):
        return relative_redirect('dashboard')
    return render_template('login.html')

@app.route('/login', methods=['POST'])
def login():
    username = request.form.get('username')
    password = request.form.get('password')
    
    if username == ADMIN_USER and password == ADMIN_PASS:
        session['logged_in'] = True
        session['username'] = username
        return relative_redirect('dashboard')
    else:
        # Return 401 Unauthorized along with the rendered template
        return render_template('login.html', error="Invalid username or password"), 401

@app.route('/dashboard')
def dashboard():
    if not session.get('logged_in'):
        # Redirect to root/login page relatively
        return relative_redirect('./')
    return render_template('dashboard.html', username=session.get('username'))

@app.route('/logout')
def logout():
    session.clear()
    # Redirect to root/login page relatively
    return relative_redirect('./')

if __name__ == '__main__':
    # Run Flask app on 127.0.0.1:8080 as requested
    app.run(host='127.0.0.1', port=8080, debug=True)
