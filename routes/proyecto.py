from flask import Blueprint, render_template, session, redirect, url_for, request, jsonify, current_app
from functools import wraps
from routes.utils import abort
from models.proyecto import Proyecto
from models.cloud_ejecucion import CloudEjecucion
from cryptography.fernet import Fernet
import mysql.connector
import boto3
from botocore.exceptions import ClientError, EndpointConnectionError
import importlib
from db import get_db_connection  # asegurate de tenerlo arriba

from redis import Redis
from rq import Queue
from tasks.cloud.aws import discovery_roles_job

proyecto_bp = Blueprint('proyecto', __name__)


# ------------------------------------------------------------------
# NO CACHE
# ------------------------------------------------------------------
@proyecto_bp.after_request
def no_cache_dashboard(response):
    response.headers['Cache-Control'] = 'no-store'
    return response


# ------------------------------------------------------------------
# LOGIN REQUIRED
# ------------------------------------------------------------------
def login_required(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        if 'user_id' not in session:
            return redirect(url_for('auth.login'))
        return f(*args, **kwargs)
    return wrapper


# ------------------------------------------------------------------
# LISTADO PROYECTOS
# ------------------------------------------------------------------
@proyecto_bp.route('/proyectos')
@login_required
def index():
    sector_id = session.get('sector_id')
    proyectos = Proyecto.get_proyectos(sector_id)
    tipos_servicio = Proyecto.get_tipos_servicio()

    return render_template(
        'inicio/proyectos.html',
        proyectos=proyectos,
        tipos_servicio=tipos_servicio
    )


# ------------------------------------------------------------------
# CREAR PROYECTO
# ------------------------------------------------------------------
@proyecto_bp.route('/proyecto/crear', methods=['POST'])
@login_required
def crear_proyecto():

    sector_id = session.get('sector_id')
    usuario_creador_id = session.get('user_id')
    estado_id = 1

    titulo = request.form.get('titulo')
    cliente = request.form.get('cliente')
    tipo_proyecto = request.form.get('tipo_proyecto')
    tipo_servicio = request.form.get('tipo_servicio')
    autenticado = request.form.get('autenticado')

    if not titulo or not cliente:
        return jsonify({"success": False, "message": "Campos obligatorios"}), 400

    try:
        Proyecto.insert_proyecto(
            titulo=titulo,
            cliente=cliente,
            sector_id=sector_id,
            usuario_creador_id=usuario_creador_id,
            tipo_proyecto=tipo_proyecto,
            tipo_servicio=tipo_servicio,
            autenticado=autenticado,
            estado_id=estado_id
        )

        return jsonify({"success": True, "message": "Proyecto creado correctamente"})

    except Exception as e:
        return jsonify({"success": False, "message": str(e)}), 500


# ------------------------------------------------------------------
# DETALLE PROYECTO
# ------------------------------------------------------------------
@proyecto_bp.route('/proyecto/<int:proyecto_id>')
@login_required
def proyecto_detalle(proyecto_id):

    sector_id = session.get('sector_id')
    proyecto = Proyecto.get_by_id(proyecto_id, sector_id)

    if not proyecto:
        abort(404)

    return render_template(
        'proyecto/detalle.html',
        proyecto=proyecto
    )


# ------------------------------------------------------------------
# GUARDAR CONFIG CLOUD
# ------------------------------------------------------------------
@proyecto_bp.route('/proyecto/<int:proyecto_id>/cloud-config', methods=['POST'])
@login_required
def guardar_cloud_config(proyecto_id):

    sector_id = session.get('sector_id')
    proyecto = Proyecto.get_by_id(proyecto_id, sector_id)

    if not proyecto:
        return jsonify({
            "success": False,
            "message": "Proyecto no encontrado"
        }), 404

    if proyecto['tipo_proyecto'] != 'CLOUD':
        return jsonify({
            "success": False,
            "message": "No es proyecto Cloud"
        }), 400

    # 🔹 Campos del form
    auth_method = request.form.get('auth_method')
    access_key = request.form.get('access_key')
    secret_key = request.form.get('secret_key')
    arn_role = request.form.get('arn_role')
    external_id = request.form.get('external_id')
    region = request.form.get('region')

    if not auth_method or not region:
        return jsonify({
            "success": False,
            "message": "Método de autenticación y región son obligatorios"
        }), 400

    region = region.strip()
    aws_account_id = None
    secret_key_encrypted = None

    try:

        # ==========================================================
        # 🔐 MODO ROLE
        # ==========================================================
        if auth_method == "role":

            if not arn_role:
                return jsonify({
                    "success": False,
                    "message": "Role ARN es obligatorio"
                }), 400

            sts = boto3.client('sts')

            assume_params = {
                "RoleArn": arn_role.strip(),
                "RoleSessionName": "RedScopeValidationSession"
            }

            if external_id:
                assume_params["ExternalId"] = external_id.strip()

            assumed = sts.assume_role(**assume_params)
            creds = assumed["Credentials"]

            sts_temp = boto3.client(
                "sts",
                aws_access_key_id=creds["AccessKeyId"],
                aws_secret_access_key=creds["SecretAccessKey"],
                aws_session_token=creds["SessionToken"],
                region_name=region
            )

            identity = sts_temp.get_caller_identity()
            aws_account_id = identity.get("Account")

            # Limpiar claves si estaban enviadas
            access_key = None
            secret_key_encrypted = None

        # ==========================================================
        # 🔑 MODO ACCESS KEYS
        # ==========================================================
        elif auth_method == "keys":

            if not access_key or not secret_key:
                return jsonify({
                    "success": False,
                    "message": "Access Key y Secret Key son obligatorios"
                }), 400

            access_key = access_key.strip()

            sts = boto3.client(
                'sts',
                aws_access_key_id=access_key,
                aws_secret_access_key=secret_key,
                region_name=region
            )

            identity = sts.get_caller_identity()
            aws_account_id = identity.get("Account")

            # Cifrar secret_key
            fernet = Fernet(current_app.config['FERNET_KEY'])
            secret_key_encrypted = fernet.encrypt(secret_key.encode()).decode()

            arn_role = None
            external_id = None

        else:
            return jsonify({
                "success": False,
                "message": "Método de autenticación inválido"
            }), 400

    except EndpointConnectionError:
        return jsonify({
            "success": False,
            "message": "Región AWS inválida"
        }), 400

    except ClientError as e:
        return jsonify({
            "success": False,
            "message": f"Error AWS: {str(e)}"
        }), 400

    except Exception as e:
        print("AWS ERROR:", str(e))
        return jsonify({
            "success": False,
            "message": "Error validando credenciales AWS"
        }), 500

    # ==========================================================
    # 💾 Guardar en DB
    # ==========================================================
    try:

        Proyecto.guardar_cloud_config(
            proyecto_id=proyecto_id,
            auth_method=auth_method,
            access_key=access_key,
            secret_key=secret_key_encrypted,
            role_arn=arn_role,
            external_id=external_id,
            region=region,
            aws_account_id=aws_account_id
        )

        return jsonify({
            "success": True,
            "message": f"Configuración guardada correctamente (Account ID: {aws_account_id})"
        })

    except mysql.connector.Error as e:
        print("MYSQL ERROR:", e)
        return jsonify({
            "success": False,
            "message": str(e)
        }), 500

    except Exception as e:
        print("ERROR FINAL:", str(e))
        return jsonify({
            "success": False,
            "message": str(e)
        }), 500


@proyecto_bp.route('/proyecto/<int:proyecto_id>/cloud')
@login_required
def proyecto_cloud_workspace(proyecto_id):

    sector_id = session.get('sector_id')
    proyecto = Proyecto.get_by_id(proyecto_id, sector_id)

    if not proyecto:
        abort(404)

    if proyecto['tipo_proyecto'] != 'CLOUD':
        abort(403)

    servicios_aws = Proyecto.get_servicios_aws_by_id(
        proyecto['tipo_servicio_id']
    )

    return render_template(
        'proyecto/proyectos-cloud/index.html',
        proyecto=proyecto,
        servicios_aws=servicios_aws
    )


@proyecto_bp.route('/cloud/acciones/<int:servicio_id>')
@login_required
def obtener_acciones_cloud(servicio_id):

    acciones = Proyecto.get_servicios_aws_acciones(servicio_id)

    return jsonify({
        "success": True,
        "acciones": acciones
    })


@proyecto_bp.route('/cloud/run-roles', methods=['POST'])
@login_required
def run_roles():
    data = request.get_json(silent=True) or {}

    proyecto_id = data.get('proyecto_id')
    accion_id = data.get('accion_id')
    usuario_id = session.get('user_id')

    if not proyecto_id or not accion_id:
        return jsonify({
            "success": False,
            "message": "proyecto_id y accion_id son obligatorios"
        }), 400

    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute("""
        INSERT INTO cloud_ejecuciones
        (proyecto_id, accion_id, usuario_id, estado, fecha_creacion, estado_id)
        VALUES (%s,%s,%s,'QUEUED', NOW(), 1)
        ON DUPLICATE KEY UPDATE
            usuario_id = VALUES(usuario_id),
            estado = 'QUEUED',
            nivel_resultado = NULL,
            codigo_resultado = NULL,
            resultado = NULL,
            error = NULL,
            fecha_creacion = NOW(),
            fecha_fin = NULL,
            estado_id = 1
    """, (proyecto_id, accion_id, usuario_id))

    # Siempre obtenemos el ID correcto
    cursor.execute("""
        SELECT id FROM cloud_ejecuciones
        WHERE proyecto_id=%s AND accion_id=%s
    """, (proyecto_id, accion_id))

    ejecucion_id = cursor.fetchone()[0]

    conn.commit()
    cursor.close()
    conn.close()

    redis_conn = Redis(host='localhost', port=6379)
    q = Queue(connection=redis_conn)

    accion = Proyecto.get_accion_by_id(accion_id)
    if not accion:
        return jsonify({
            "success": False,
            "message": "Acción inválida"
        }), 400

    handler_path = accion['handler']
    module_path, function_name = handler_path.rsplit('.', 1)

    try:
        module = importlib.import_module(f"tasks.{module_path}")
        func = getattr(module, function_name)
    except Exception as e:
        return jsonify({
            "success": False,
            "message": f"Error cargando handler: {str(e)}"
        }), 500

    q.enqueue(func, ejecucion_id, proyecto_id)

    return jsonify({
        "success": True,
        "ejecucion_id": ejecucion_id
    })


@proyecto_bp.route('/cloud/resultados/<int:proyecto_id>')
@login_required
def obtener_resultados_cloud(proyecto_id):

    sector_id = session.get('sector_id')
    proyecto = Proyecto.get_by_id(proyecto_id, sector_id)

    if not proyecto:
        return jsonify({"success": False}), 404

    data = Proyecto.get_data_ejecucion_cloud(proyecto_id)

    return jsonify({
        "success": True,
        "data": data
    })


@proyecto_bp.route('/proyecto/<int:proyecto_id>/cloud/ejecucion/<int:ejecucion_id>', methods=['GET'])
@login_required
def obtener_detalle_ejecucion(proyecto_id, ejecucion_id):

    sector_id = session.get('sector_id')
    proyecto = Proyecto.get_by_id(proyecto_id, sector_id)

    if not proyecto:
        abort(404)

    data = Proyecto.get_data_ejecuciones_para_analisis(
        proyecto_id,
        ejecucion_id
    )

    if not data:
        return jsonify({"error": "No encontrado"}), 404

    # TRAIGO LOS INFDINGS
    findings = CloudEjecucion.extract_interesting(data["resultado"])
    data["interesting"] = findings

    return jsonify(data)
