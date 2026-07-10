# Flask Login Application (Testing Page)

This application is built to generate realistic authentication logs (successful logins, failed attempts, dashboard page hits, logouts) for testing the AI-Powered Security Operations Center (SOC) Platform. 

It is designed to run behind NGINX as a reverse proxy.

## Credentials

- **Username**: `admin`
- **Password**: `Admin@123`

## Installation

Install the required dependencies:

```bash
pip install -r requirements.txt
```

## Running the Application

Start the Flask development server on the configured port (`8080`):

```bash
python app.py
```

## URLs

- **Direct Flask URL**: [http://127.0.0.1:8080](http://127.0.0.1:8080)
- **NGINX Reverse Proxy URL**: [http://localhost/loginapp/](http://localhost/loginapp/)

---

## NGINX Configuration

To route requests through NGINX, insert the following block inside the main `server` block of `nginx.conf`:

```nginx
        location /loginapp/ {
            proxy_pass http://127.0.0.1:8080/;
            proxy_set_header Host $host;
            proxy_set_header X-Real-IP $remote_addr;
            proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
            proxy_redirect off;
        }
```

Then reload NGINX:

```bash
nginx -s reload
```
