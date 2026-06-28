from flask import Blueprint, render_template, session, redirect, url_for
from functools import wraps
from models.proyecto import Proyecto
from models.servicio import Servicio
from routes.utils import abort

servicio_bp = Blueprint('servicio', __name__)

def login_required(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        if 'user_id' not in session:
            return redirect(url_for('auth.login'))
        return f(*args, **kwargs)
    return wrapper

@servicio_bp.route('/servicios')
@login_required
def index():
    estado = session.get('estado')
    proyectos = Proyecto.get_tipo_proyectos()
    servicio_cloud = Proyecto.get_tipos_servicio()
    if estado == 'ACTIVO':
        return render_template('servicio/index.html', proyectos=proyectos, tipos_servicio=servicio_cloud)
    else:
        abort(403)

from flask import request, jsonify

@servicio_bp.route('/servicio/alta', methods=['POST'])
@login_required
def alta_servicio():
    nombre = request.form.get('nombre')
    descripcion = request.form.get('descripcion') or None
    if not nombre:
        return jsonify({'success': False, 'mensaje': 'El nombre es obligatorio.'}), 400
    Servicio.alta(nombre, descripcion)
    return jsonify({'success': True}), 200

@servicio_bp.route('/servicio/<int:id>/inhabilitar', methods=['POST'])
@login_required
def inhabilitar_servicio(id):
    Servicio.inhabilitar(id)
    return jsonify({'success': True}), 200