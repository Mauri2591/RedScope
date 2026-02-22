from flask import Blueprint, render_template, session, redirect, url_for
from functools import wraps
from routes.utils import abort
from models.proyecto import Proyecto

inicio_bp = Blueprint('inicio', __name__)

@inicio_bp.after_request
def no_cache_dashboard(response):
    response.headers['Cache-Control'] = 'no-store'
    return response


def login_required(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        if 'user_id' not in session:
            return redirect(url_for('auth.login'))
        return f(*args, **kwargs)
    return wrapper

@inicio_bp.route('/inicio')
@login_required
def index():
    estado = session.get('estado')
    proyectos=Proyecto.get_tipo_proyectos()
    servicio_cloud=Proyecto.get_tipos_servicio()
    if estado == 'ACTIVO':
        return render_template('inicio/index.html',proyectos=proyectos,tipos_servicio=servicio_cloud)
    else:
        abort(403)

