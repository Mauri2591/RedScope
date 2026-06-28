# tasks/cloud/security_rules_ia.py
import logging
from services.ia import IA
from models.proyecto import Proyecto

log = logging.getLogger(__name__)

SEVERIDAD_MAP = {
    "INFORMATIONAL": 1,
    "INFORMATIVO": 1,
    "LOW": 2,
    "BAJO": 2,
    "MEDIUM": 3,
    "MEDIO": 3,
    "HIGH": 4,
    "ALTO": 4,
    "CRITICAL": 5,
    "CRITICO": 5,
}

def _mapear_severidad(valor):
    if not valor:
        return SEVERIDAD_MAP["MEDIUM"]
    return SEVERIDAD_MAP.get(valor.strip().upper(), SEVERIDAD_MAP["MEDIUM"])


def generar_security_rule(provider, service, check_id, contexto=""):
    """
    Genera y persiste una security_rule vía IA cuando auto_insert_findings
    detecta un check_id sin regla cargada.
    """
    ia = IA()

    prompt = f"""Sos un analista de seguridad cloud especializado en {provider.upper()}.
Generá la documentación de una regla de auditoría para un check de seguridad.

check_id: {check_id}
servicio: {service}
contexto del finding: {contexto or "no disponible"}

Respondé SOLO con un JSON válido, sin texto adicional, sin backticks, con estos campos.
El campo "title" debe estar en inglés, estilo CVE/CWE (ej: "S3 Bucket Versioning Disabled").
El campo "reference" debe apuntar a documentación oficial en inglés (no versiones traducidas).
Todos los demás campos de texto deben estar en español (Argentina/Rioplatense), sin excepción.
Sé conciso: respetá el límite de palabras indicado en cada campo, sin cortar palabras a la mitad.
IMPORTANTE: No menciones nombres de recursos, buckets, IDs, ARNs ni valores específicos del entorno escaneado. La regla debe ser genérica y aplicable a cualquier recurso del mismo tipo.

{{
  "title": "...",
  "description": "máximo 40 palabras",
  "risk_level": "BAJO|MEDIO|ALTO|CRITICO",
  "condition_logic": "máximo 35 palabras",
  "remediation": "máximo 40 palabras",
  "reference": "URL de documentación oficial de {provider.upper()}"
}}"""

    data = ia.generar_json(prompt, max_tokens=2000)
    if data is None:
        log.warning(f"No se pudo generar security_rule vía IA para check_id={check_id}")
        return None

    payload = {
        "provider": provider,
        "service": service,
        "check_id": check_id,
        "title": data.get("title", check_id),
        "description": data.get("description", ""),
        "severidad_id": _mapear_severidad(data.get("risk_level")),
        "condition_logic": data.get("condition_logic", ""),
        "remediation": data.get("remediation", ""),
        "reference": data.get("reference", ""),
    }

    rule_id = Proyecto.insert_security_rule_ia(payload)
    log.info(f"security_rule generada por IA: check_id={check_id}, rule_id={rule_id}")
    return rule_id