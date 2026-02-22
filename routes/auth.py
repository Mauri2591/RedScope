from flask import Blueprint, render_template, request, redirect, url_for, session, jsonify, flash
from werkzeug.security import check_password_hash, generate_password_hash
from http import HTTPStatus
from models.usuario import Usuario
from routes.utils import login_required, require_scope
from botocore.exceptions import ClientError, EndpointConnectionError

auth_bp = Blueprint('auth', __name__)


@auth_bp.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form.get('email').strip()
        password = request.form.get('password').strip()
        if not email or not password:
            return render_template('auth/login.html', error='Datos vacios'), HTTPStatus.FORBIDDEN
        else:
            user = Usuario.get_email(email)
            if user and check_password_hash(user['password_hash'], password):
                session['user_id'] = user['id']
                session['email'] = user['email']
                session['rol'] = user['rol']
                session['sector'] = user['sector']
                session['sector_id'] = user['sector_id']
                session['estado'] = user['estado']
                return redirect(url_for('inicio.index'))
            else:
                return render_template(
                    'auth/login.html',
                    error='Datos inválidos'
                ), HTTPStatus.FORBIDDEN
    else:
        return render_template('auth/login.html')


@auth_bp.route('/usuario/update', methods=['POST'])
def update_usuario():

    if 'user_id' not in session:
        return redirect(url_for('auth.login'))

    user_id = session.get('user_id')
    email = request.form.get('email', '').strip()
    password = request.form.get('password', '').strip()

    if not email:
        flash("El email es obligatorio", "danger")
        return redirect(url_for('inicio.index'))

    Usuario.update_usuario(user_id, email, password)

    session['email'] = email

    flash("Perfil actualizado correctamente", "success")

    return redirect(url_for('inicio.index'))


@auth_bp.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('auth.login'))
