import os
from flask import Flask, redirect, render_template, request, url_for, session
from werkzeug.security import check_password_hash
from werkzeug.middleware.proxy_fix import ProxyFix
from config import Config

from flask_wtf import CSRFProtect
from flask_wtf.csrf import generate_csrf

from routes.auth import auth_bp
from routes.inicio import inicio_bp
from routes.servicio import servicio_bp
from routes.proyecto import proyecto_bp
from routes.cliente import cliente_bp
from routes.debug_conclusiones import debug_bp

app = Flask(__name__)
app.config.from_object(Config)

# Middleware para reverse proxy (Apache) - solo en producción
if app.config['USE_PROXY_FIX']:
    app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1, x_port=1, x_prefix=1)

csrf = CSRFProtect(app)
app.jinja_env.globals['csrf_token'] = generate_csrf

app.register_blueprint(auth_bp)
app.register_blueprint(inicio_bp)
app.register_blueprint(servicio_bp)
app.register_blueprint(proyecto_bp)
app.register_blueprint(cliente_bp)
app.register_blueprint(debug_bp)

@app.route('/')
def index():
    if 'user_id' in session:
        return redirect(url_for('inicio.index'))
    else:
        return redirect(url_for('auth.login'))

@app.after_request
def disable_cache(response):
    response.headers['Cache-Control'] = 'no-store, no-cache, must-revalidate, private'
    response.headers['Pragma'] = 'no-cache'
    response.headers['Expires'] = '0'
    return response

if __name__ == '__main__':
    app.run(
        host=app.config['APP_HOST'],
        port=app.config['APP_PORT'],
        debug=app.config['APP_DEBUG']
    )