from flask import Blueprint, render_template, session, redirect, url_for,request, jsonify
from functools import wraps
from routes.utils import abort
from models.proyecto import Proyecto
from models.cliente import Cliente

cliente_bp = Blueprint('cliente', __name__)

@cliente_bp.after_request
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


@cliente_bp.route('/clientes')
@login_required
def index():
    estado = session.get('estado')
    if estado == 'ACTIVO':
        clientes = Cliente.get_all()
        tipo_proyectos = Proyecto.get_tipo_proyectos()
        tipos_servicio = Proyecto.get_tipos_servicio()
        return render_template('cliente/index.html', 
            clientes=clientes,
            tipo_proyectos=tipo_proyectos,
            tipos_servicio=tipos_servicio)
    else:
        abort(403)
        
@cliente_bp.route('/cliente/alta', methods=['POST'])
@login_required
def alta():
    nombre = request.form.get('nombre')
    cuit = request.form.get('cuit') or None
    referencia = request.form.get('referencia') or None
    Cliente.alta(nombre, cuit, referencia)
    return jsonify({'nombre': nombre, 'cuit': cuit or '-', 'referencia': referencia or '-'})

@cliente_bp.route('/cliente/<int:id>/inhabilitar', methods=['POST'])
@login_required
def inhabilitar_cliente(id):
    Cliente.inhabilitar_cliente(id)
    return jsonify({'success' : True}), 200