from flask import Flask, redirect, render_template,request,url_for,session
from werkzeug.security import check_password_hash
from config import Config

from flask_wtf import CSRFProtect
from flask_wtf.csrf import generate_csrf

from routes.auth import auth_bp
from routes.inicio import inicio_bp
from routes.proyecto import proyecto_bp

app = Flask(__name__)
app.config.from_object(Config)

csrf=CSRFProtect(app)
app.jinja_env.globals['csrf_token'] = generate_csrf

app.register_blueprint(auth_bp)
app.register_blueprint(inicio_bp)
app.register_blueprint(proyecto_bp)

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
