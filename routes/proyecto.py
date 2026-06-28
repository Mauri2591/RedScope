from flask import (
    Blueprint,
    Response,
    render_template,
    session,
    redirect,
    url_for,
    request,
    jsonify,
    current_app,
    send_from_directory
)

from db import get_db_connection
from config import Config
from models.proyecto import Proyecto
from models.cloud_ejecucion import CloudEjecucion
from services.reportes import ReportService
from tasks.cloud.aws import discovery_roles_job

from functools import wraps
from datetime import datetime
import re
import importlib
import boto3
from botocore.exceptions import ClientError, EndpointConnectionError
from cryptography.fernet import Fernet
from redis import Redis
from rq import Queue
from routes.utils import abort
import json

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
        'servicio/proyectos.html',
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
    cliente_id = request.form.get('cliente_id') or None
    tipo_proyecto = request.form.get('tipo_proyecto_id')
    tipo_servicio = request.form.get('tipo_servicio_id')
    autenticado = request.form.get('autenticado')

    if not titulo:
        return jsonify({"success": False, "message": "Título obligatorio"}), 400

    try:
        Proyecto.insert_proyecto(
            titulo=titulo,
            cliente=cliente,
            cliente_id=cliente_id,
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

    auth_method = request.form.get('auth_method')
    access_key  = request.form.get('access_key')
    secret_key  = request.form.get('secret_key')
    arn_role    = request.form.get('arn_role')
    external_id = request.form.get('external_id')
    region      = request.form.get('region')

    if not auth_method or not region:
        return jsonify({
            "success": False,
            "message": "Método de autenticación y región son obligatorios"
        }), 400

    region = region.strip()
    aws_account_id     = None
    secret_key_encrypted = None

    try:

        # ==========================================================
        # MODO ROLE
        # ==========================================================
        if auth_method == "role":

            if not arn_role:
                return jsonify({
                    "success": False,
                    "message": "Role ARN es obligatorio"
                }), 400

            if not access_key or not secret_key:
                return jsonify({
                    "success": False,
                    "message": "Se requieren Access Key y Secret Key del pentester para asumir el rol"
                }), 400

            # Autenticamos primero con las keys del pentester
            sts = boto3.client(
                'sts',
                aws_access_key_id=access_key.strip(),
                aws_secret_access_key=secret_key.strip()
            )

            assume_params = {
                "RoleArn": arn_role.strip(),
                "RoleSessionName": "RedScopeValidationSession"
            }

            if external_id:
                assume_params["ExternalId"] = external_id.strip()

            assumed = sts.assume_role(**assume_params)
            creds   = assumed["Credentials"]

            # Verificamos identidad con las credenciales temporales
            sts_temp = boto3.client(
                "sts",
                aws_access_key_id=creds["AccessKeyId"],
                aws_secret_access_key=creds["SecretAccessKey"],
                aws_session_token=creds["SessionToken"],
                region_name=region
            )

            identity       = sts_temp.get_caller_identity()
            aws_account_id = identity.get("Account")

            # Ciframos la secret_key del pentester para guardarla
            fernet               = Fernet(current_app.config['FERNET_KEY'])
            secret_key_encrypted = fernet.encrypt(secret_key.encode()).decode()
            access_key           = access_key.strip()

        # ==========================================================
        # MODO ACCESS KEYS
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

            identity       = sts.get_caller_identity()
            aws_account_id = identity.get("Account")

            # Cifrar secret_key
            fernet               = Fernet(current_app.config['FERNET_KEY'])
            secret_key_encrypted = fernet.encrypt(secret_key.encode()).decode()

            arn_role    = None
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
    # Guardar en DB
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

    # ✅ Siempre inserta una nueva ejecución
    cursor.execute("""
        INSERT INTO cloud_ejecuciones
        (proyecto_id, accion_id, usuario_id, estado, fecha_creacion, estado_id)
        VALUES (%s,%s,%s,'QUEUED', NOW(), 1)
    """, (proyecto_id, accion_id, usuario_id))

    ejecucion_id = cursor.lastrowid

    conn.commit()
    cursor.close()
    conn.close()

    q = Queue(connection=Config.redis_conn)

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
    findings = CloudEjecucion.extract_interesting(data["resultado"], data.get("servicio"))
    data["interesting"] = findings

    return jsonify(data)

@proyecto_bp.route('/proyecto/<int:proyecto_id>/cloud/ejecucion/<int:ejecucion_id>/hallazgos')
@login_required
def gestionar_hallazgos(proyecto_id, ejecucion_id):
    sector_id = session.get('sector_id')
    proyecto = Proyecto.get_by_id(proyecto_id, sector_id)
    if not proyecto:
        abort(404)
    data = Proyecto.get_data_ejecuciones_para_analisis(proyecto_id, ejecucion_id)
    if not data:
        abort(404)

    findings = CloudEjecucion.extract_interesting(data["resultado"], data.get("servicio"))
    findings = Proyecto.enrich_findings_with_ids(findings, proyecto_id, ejecucion_id)

    check_ids_unicos = {f['check_id'] for f in findings}
    estado_reglas = Proyecto.get_estado_reglas(check_ids_unicos)
    for f in findings:
        info = estado_reglas.get(f['check_id'])
        if not info:
            f['regla_estado'] = 'sin_regla'
        elif info['origen'] in ('prowler', 'scoutsuite'):
            f['regla_estado'] = 'herramienta'
        elif info['validado_por'] is None:
            f['regla_estado'] = 'ia_sin_validar'
        else:
            f['regla_estado'] = 'validada'

    faltantes = check_ids_unicos - set(estado_reglas.keys())
    if faltantes:
        _encolar_generacion_ia(faltantes, findings)

    return render_template(
        'proyecto/proyectos-cloud/GestionHallazgos.html',
        proyecto=proyecto,
        ejecucion=data,
        findings=findings
    )
    
@proyecto_bp.route('/proyecto/cloud/estado-reglas', methods=['POST'])
@login_required
def estado_reglas_ajax():
    data = request.get_json()
    check_ids = data.get('check_ids', [])
    estado_reglas = Proyecto.get_estado_reglas(set(check_ids))

    resultado = {}
    for check_id in check_ids:
        info = estado_reglas.get(check_id)
        if not info:
            resultado[check_id] = 'sin_regla'
        elif info['creado_por_ia'] and info['validado_por'] is None:
            resultado[check_id] = 'ia_sin_validar'
        else:
            resultado[check_id] = 'validada'

    return jsonify(resultado)

def _encolar_generacion_ia(check_ids_faltantes, findings):
    """Encola generación de security_rules vía IA para check_ids nuevos, sin duplicar jobs."""
    from tasks.cloud.security_rules_ia import generar_security_rule

    findings_by_check = {}
    for f in findings:
        findings_by_check.setdefault(f['check_id'], f)

    q = Queue('ia', connection=Config.redis_conn)  # cola separada de la default (no compite con jobs de AWS)

    for check_id in check_ids_faltantes:
        lock_key = f"ia_lock:security_rule:{check_id}"
        # SET NX con expiración: si ya se encoló este check_id en los últimos 5 min, no insistir
        if not Config.redis_conn.set(lock_key, "1", nx=True, ex=300):
            continue

        f = findings_by_check.get(check_id)
        if not f:
            continue

        q.enqueue(
        generar_security_rule,
        f.get('provider', 'aws'),
        f.get('service'),
        check_id,
        f'check_id={check_id} service={f.get("service")}'
    )
    
@proyecto_bp.route('/proyecto/finding/<int:finding_id>/verificar', methods=['POST'])
@login_required
def verificar_finding(finding_id):
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("""
            UPDATE findings 
            SET verificado = 'SI'
            WHERE id = %s
        """, (finding_id,))
        conn.commit()
        return jsonify({"ok": True})
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)}), 500
    finally:
        cursor.close()
        conn.close()
        
@proyecto_bp.route('/proyecto/security-rule/<check_id>', methods=['GET'])
@login_required
def gestionar_findings(check_id):
    data = Proyecto.get_security_rules(check_id)
    severidades = Proyecto.get_severidades()
    combo_findings = Proyecto.get_combo_estados_findings()

    return jsonify({
        'success': True,
        'rule_exists': True if data else False,
        'data': data,
        'display_name': CloudEjecucion.get_display_name(check_id),
        'severidades': severidades,
        'combo_findings': combo_findings
    })
    
@proyecto_bp.route('/proyecto/finding/eliminar/<int:finding_id>', methods=['POST'])
@login_required
def eliminar_finding(finding_id):
    Proyecto.delete_finding(finding_id)
    return jsonify({"success": True})    

@proyecto_bp.route('/proyecto/security-rule', methods=['POST'])
@login_required
def insert_security_rule():
    data = request.get_json()
    usuario_id = session.get('user_id')
    rule_id = Proyecto.insert_security_rule(data, usuario_id)
    return jsonify({
        "success": True,
        "rule_id": rule_id
    })

    
@proyecto_bp.route('/proyecto/finding/detail/<int:finding_id>', methods=['GET'])
@login_required
def get_finding_by_id(finding_id):
    finding = Proyecto.get_finding_by_id(finding_id)
    if not finding:
        return jsonify({"success": False}), 404

    evidencias_img = Proyecto.get_finding_evidencias_img(finding_id)

    # Si todavía no se guardó manualmente, extraer la salida cruda de la herramienta
    if not finding.get('inventory_data'):
        resultado_raw = Proyecto.get_resultado_ejecucion(finding['cloud_ejecucion_id'])
        finding['inventory_data'] = _extraer_bloque_recurso(resultado_raw, finding['resource_id'])

    return jsonify({
        "success": True,
        "data": {
            "finding": finding,
            "evidencias_img": evidencias_img
        }
    })

    
@proyecto_bp.route('/proyecto/finding', methods=['POST'])
@login_required
def insert_finding():
    data = request.get_json()
    usuario_id = session.get("user_id")
    finding_id = Proyecto.insert_finding(data, usuario_id)

    # nuevas evidencias
    if data.get("evidencias"):
        Proyecto.insert_evidences(finding_id, data["evidencias"])

    # eliminadas
    if data.get("evidencias_eliminadas"):
        Proyecto.delete_evidences(data["evidencias_eliminadas"])

    return jsonify({
        "success": True,
        "finding_id": finding_id
    })
    

@proyecto_bp.route("/proyecto/finding/<int:finding_id>")
@login_required
def api_get_finding(finding_id):
    hallazgo = Proyecto.get_finding(finding_id)
    evidencias = Proyecto.get_finding_evidencias(finding_id)
    combo_findings = Proyecto.get_combo_estados_findings()

    return jsonify({
        "success": True,
        "hallazgo": hallazgo,
        "evidencias": [e["file_path"] for e in evidencias],
        "combo_findings": combo_findings
    })
    
@proyecto_bp.route('/proyecto/finding/<int:proyecto_id>/<string:check_id>', methods=['GET'])
@login_required
def get_finding_by_check(proyecto_id, check_id):
    resource_id        = request.args.get('resource_id')
    cloud_ejecucion_id = request.args.get('ejecucion_id')

    finding = Proyecto.get_finding(
        check_id=check_id,
        proyecto_id=proyecto_id,
        resource_id=resource_id,
        cloud_ejecucion_id=cloud_ejecucion_id
    )

    if not finding:
        return jsonify({"success": False, "message": "No encontrado"}), 404

    finding_id     = finding['id']
    evidencias_img = Proyecto.get_finding_evidencias_img(finding_id)

    return jsonify({
        "success": True,
        "data": {
            "finding": finding,
            "evidencias_img": evidencias_img
        }
    })
    
@proyecto_bp.route("/uploads/findings/<path:filename>")
@login_required
def serve_evidencias(filename):
    import os
    from flask import send_from_directory
    path = os.path.join(Config.BASE_DIR, "uploads", "findings")
    return send_from_directory(path, filename)


# *****************************  Reportes  ***************************
#-------------------------------- xlsx ------------------------------#
@proyecto_bp.route('/proyecto/<int:proyecto_id>/export/xlsx')
@login_required
def exportar_xlsx(proyecto_id):
    sector_id = session.get('sector_id')
    proyecto = Proyecto.get_by_id(proyecto_id, sector_id)

    if not proyecto:
        abort(404)

    data = Proyecto.get_data_reporte(proyecto_id)
    severidades = Proyecto.get_severidades()  

    output = ReportService.generar_xlsx(data, severidades)
    filename = ReportService.generar_nombre_archivo(data, proyecto_id)

    return Response(
        output.getvalue(),
        mimetype="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
        headers={
            "Content-Disposition": f"attachment; filename={filename}",
            "Cache-Control": "no-cache"
        }
    )
#-------------------------------- xlsx ------------------------------#

#-------------------------------- CSV (Vulma) ------------------------------#
@proyecto_bp.route('/proyecto/<int:proyecto_id>/export/csv')
@login_required
def exportar_csv(proyecto_id):
    sector_id = session.get('sector_id')
    proyecto = Proyecto.get_by_id(proyecto_id, sector_id)

    if not proyecto:
        abort(404)

    data = Proyecto.get_data_reporte(proyecto_id)

    output = ReportService.generar_csv_vulma(data)
    filename = ReportService.generar_nombre_archivo(data, proyecto_id).replace(".xlsx", ".csv")

    return Response(
        output.getvalue(),
        mimetype="text/csv",
        headers={
            "Content-Disposition": f"attachment; filename={filename}",
            "Cache-Control": "no-cache"
        }
    )
#---------------------------------------------------------------------------#
#-------------------------------- Docx ------------------------------#

@proyecto_bp.route('/proyecto/<int:proyecto_id>/export/docx/<tipo_informe>')
@login_required
def exportar_docx(proyecto_id, tipo_informe):

    if tipo_informe not in ('tecnico', 'ejecutivo'):
        abort(404)

    sector_id = session.get('sector_id')
    proyecto  = Proyecto.get_by_id(proyecto_id, sector_id)

    if not proyecto:
        abort(404)

    tipo_servicio = proyecto.get('tipo_servicio', 'aws').lower()

    data               = Proyecto.get_data_reporte(proyecto_id)
    tema               = Proyecto.get_reporte_tema()
    estructura         = Proyecto.get_reporte_estructura(proveedor=tipo_servicio)
    severidades        = Proyecto.get_severidades()
    contenido_secciones = Proyecto.get_contenido_secciones(tipo_servicio)

    output = ReportService.generar_docx(
        data, proyecto, tema, estructura, severidades,
        contenido_secciones,
        base_dir=Config.BASE_DIR,
        tipo_informe=tipo_informe
    )
    filename = ReportService.generar_nombre_archivo(data, proyecto_id, extension="docx", tipo_informe=tipo_informe)

    return Response(
        output.getvalue(),
        mimetype="application/vnd.openxmlformats-officedocument.wordprocessingml.document",
        headers={
            "Content-Disposition": f"attachment; filename={filename}",
            "Cache-Control": "no-cache"
        }
    )

@proyecto_bp.route('/cloud/acciones/all/<int:proyecto_id>')
@login_required
def obtener_todas_acciones(proyecto_id):
    sector_id = session.get('sector_id')
    proyecto = Proyecto.get_by_id(proyecto_id, sector_id)
    if not proyecto:
        return jsonify({"success": False}), 404
    
    acciones = Proyecto.get_todas_las_acciones(proyecto['tipo_servicio_id'])
    return jsonify({
        "success": True,
        "acciones": acciones
    })
    
def _extraer_bloque_recurso(resultado_raw, resource_id):
    """Busca dentro del JSON de la ejecución el bloque correspondiente a un resource_id puntual."""
    if not resultado_raw:
        return ""

    try:
        resultado = json.loads(resultado_raw) if isinstance(resultado_raw, str) else resultado_raw
    except (TypeError, ValueError):
        return ""

    for recurso in resultado.get("resources", []):
        if recurso.get("resource_id") == resource_id:
            return json.dumps(recurso, indent=2, ensure_ascii=False)

    return ""

@proyecto_bp.route('/proyecto/<int:proyecto_id>/cloud/import-findings/lista', methods=['GET'])
@login_required
def get_imported_findings(proyecto_id):
    resultado = Proyecto.get_imported_findings_by_proyecto(proyecto_id)
    return jsonify(resultado)

#---------------------------------------------------------------------------#
#-------------------------------- Importar archivos de findings de herramientas ------------#
IMPORT_CONFIG = {
    'prowler': {
        'extensiones': ['.json'],
        'parser': 'parse_prowler'
    },
    'scoutsuite': {
        'extensiones': ['.json'],
        'parser': 'parse_scoutsuite'
    }
}

@proyecto_bp.route('/proyecto/<int:proyecto_id>/cloud/import-findings', methods=['POST'])
@login_required
def import_findings(proyecto_id):
    herramienta = request.form.get('herramienta')
    archivo = request.files.get('archivo')

    if not herramienta or herramienta not in IMPORT_CONFIG:
        return jsonify({"success": False, "message": "Herramienta no soportada."}), 400

    if not archivo:
        return jsonify({"success": False, "message": "No se envió ningún archivo."}), 400

    config = IMPORT_CONFIG[herramienta]
    ext = '.' + archivo.filename.rsplit('.', 1)[-1].lower()
    if ext not in config['extensiones']:
        return jsonify({"success": False, "message": f"Para {herramienta} se esperaba: {', '.join(config['extensiones'])}."}), 400

    try:
        data = json.loads(archivo.read())
    except Exception:
        return jsonify({"success": False, "message": "El archivo no es un JSON válido."}), 400

    resultado = Proyecto.import_findings(proyecto_id, herramienta, data, session.get('user_id'))

    return jsonify({"success": True, "imported": resultado})

@proyecto_bp.route('/proyecto/<int:proyecto_id>/cloud/importados/<string:herramienta>/hallazgos')
@login_required
def gestionar_hallazgos_importados(proyecto_id, herramienta):
    sector_id = session.get('sector_id')
    proyecto = Proyecto.get_by_id(proyecto_id, sector_id)
    if not proyecto:
        abort(404)

    findings = Proyecto.get_findings_importados(proyecto_id, herramienta)

    check_ids_unicos = {f['check_id'] for f in findings}
    estado_reglas = Proyecto.get_estado_reglas(check_ids_unicos)
    for f in findings:
        info = estado_reglas.get(f['check_id'])
        if not info:
            f['regla_estado'] = 'sin_regla'
        elif info.get('origen') == 'prowler' or info.get('origen') not in (None, 'manual', 'ia'):
            f['regla_estado'] = 'herramienta'
        elif info['validado_por'] is None:
            f['regla_estado'] = 'ia_sin_validar'
        else:
            f['regla_estado'] = 'validada'

    return render_template(
        'proyecto/proyectos-cloud/GestionHallazgos.html',
        proyecto=proyecto,
        ejecucion=None,
        findings=findings
    )
    
@proyecto_bp.route('/proyecto/findings/verificar-masivo', methods=['POST'])
@login_required
def verificar_findings_masivo():
    data = request.get_json()
    ids = data.get('finding_ids', [])
    Proyecto.verificar_findings_masivo(ids)
    return jsonify({"success": True})

@proyecto_bp.route('/proyecto/findings/eliminar-masivo', methods=['POST'])
@login_required
def eliminar_findings_masivo():
    data = request.get_json()
    ids = data.get('finding_ids', [])
    Proyecto.eliminar_findings_masivo(ids)
    return jsonify({"success": True})

@proyecto_bp.route('/proyecto/<int:proyecto_id>/cloud/mitre-tecnicas', methods=['GET'])
@login_required
def get_mitre_tecnicas(proyecto_id):
    import json as _json
    findings = Proyecto.get_findings_con_inventory(proyecto_id)
    tecnicas = {}
    for f in findings:
        inv = f.get('inventory_data')
        if not inv:
            continue
        try:
            data = _json.loads(inv) if isinstance(inv, str) else inv
            for t_id in data.get('compliance', {}).get('MITRE-ATTACK', []):
                tecnicas[t_id] = tecnicas.get(t_id, 0) + 1
        except Exception:
            continue
    return jsonify(tecnicas)

@proyecto_bp.route('/proyecto/<int:proyecto_id>/cloud/mitre-findings/<string:tecnica>', methods=['GET'])
@login_required
def get_findings_by_mitre(proyecto_id, tecnica):
    import json as _json
    findings = Proyecto.get_findings_con_inventory(proyecto_id)
    resultado = []
    for f in findings:
        inv = f.get('inventory_data')
        if not inv:
            continue
        try:
            data = _json.loads(inv) if isinstance(inv, str) else inv
            if tecnica in data.get('compliance', {}).get('MITRE-ATTACK', []):
                resultado.append({
                    'finding_id': f.get('id'),
                    'check_id': f.get('check_id'),
                    'resource_id': f.get('resource_id'),
                    'service': f.get('service'),
                    'severidad': f.get('severidad_id')
                })
        except Exception:
            continue
    return jsonify(resultado)