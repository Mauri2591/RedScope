"""
Prowler Report Parser
Procesa reportes de Prowler Web (JSON-OCSF) y extrae/organiza datos correctamente
"""
import json
import re
from typing import Dict, List, Tuple


class ProwlerDataExtractor:
    """Extrae y estructura datos de reportes Prowler"""

    @staticmethod
    def group_compliance_by_family(compliance_dict: Dict[str, str]) -> Dict[str, Dict[str, str]]:
        """
        Agrupa compliance por familia de estándares

        Entrada:
        {
            "CIS-1.4": "1.16",
            "NIST-800-53-Revision-5": "ac_3",
            "ISO27001-2022": "A.5.18",
            "GDPR": "article_25",
            ...
        }

        Salida (agrupado):
        {
            "CIS Benchmarks": {
                "CIS-1.4": "1.16",
                "CIS-1.5": "1.16",
                ...
            },
            "NIST Standards": {
                "NIST-800-171": "3_1_1, 3_1_2",
                "NIST-800-53-Revision-5": "ac_3, ac_6",
                ...
            },
            "Regulatory": {
                "GDPR": "article_25",
                "HIPAA": "164_308_a_1_ii_b",
                ...
            },
            ...
        }
        """
        if not isinstance(compliance_dict, dict):
            return {}

        families = {
            "CIS Benchmarks": [],
            "NIST Standards": [],
            "AWS Frameworks": [],
            "ISO & Regulatory": [],
            "Industry Standards": [],
            "Otros": []
        }

        for standard, controls in compliance_dict.items():
            # Clasificar por familia basado en el nombre del estándar
            if standard.startswith("CIS"):
                families["CIS Benchmarks"].append((standard, controls))
            elif "NIST" in standard or "nist" in standard.lower():
                families["NIST Standards"].append((standard, controls))
            elif "AWS" in standard or "Well-Architected" in standard or "Foundational" in standard:
                families["AWS Frameworks"].append((standard, controls))
            elif any(x in standard for x in ["ISO", "GDPR", "HIPAA", "PCI", "SOC2"]):
                families["ISO & Regulatory"].append((standard, controls))
            elif any(x in standard for x in ["CCC", "KISA", "ENS", "RBI", "CISA", "FFIEC", "FedRAMP", "GxP", "SecNumCloud"]):
                families["Industry Standards"].append((standard, controls))
            else:
                families["Otros"].append((standard, controls))

        # Convertir a dict ordenado (solo familias con contenido)
        result = {}
        for family, items in families.items():
            if items:
                result[family] = dict(items)

        return result

    @staticmethod
    def parse_compliance_string(compliance_data) -> Dict[str, str]:
        """
        Parsea compliance que viene como string o dict

        Entrada (como string):
        "ASD-Essential-Eight-Nov 2023: E8-4.4
        AWS-AI-Security-Framework-1.0: AISF-IAM-02
        ..."

        Salida (como dict):
        {
            "ASD-Essential-Eight-Nov 2023": "E8-4.4",
            "AWS-AI-Security-Framework-1.0": "AISF-IAM-02"
        }
        """
        if isinstance(compliance_data, dict):
            return compliance_data  # Ya está parseado

        if not isinstance(compliance_data, str) or not compliance_data.strip():
            return {}

        compliance_dict = {}

        # Parsear líneas del compliance
        for line in compliance_data.strip().split('\n'):
            line = line.strip()
            if not line:
                continue

            # Buscar el patrón: STANDARD: CONTROL
            if ':' in line:
                parts = line.split(':', 1)
                if len(parts) == 2:
                    standard = parts[0].strip()
                    control = parts[1].strip()

                    if standard and control:
                        compliance_dict[standard] = control

        return compliance_dict

    @staticmethod
    def extract_links_from_field(text: str) -> List[Dict[str, str]]:
        """
        Busca URLs en texto (ej: "Leer más...") y extrae los links
        Formato esperado: "[texto link](url)" o "texto: url"
        """
        links = []
        if not text:
            return links

        # Patrón: [texto](url)
        pattern_md = r'\[([^\]]+)\]\(([^)]+)\)'
        for match in re.finditer(pattern_md, text):
            links.append({
                "title": match.group(1),
                "url": match.group(2)
            })

        # Patrón: "Leer más..." (si está en un contexto de URL, extraer de contexto)
        # Esto es más complejo y dependerá de tu formato específico

        return links

    @staticmethod
    def parse_prowler_item(item: Dict) -> Dict:
        """
        Transforma un item de Prowler en estructura limpia

        INPUT (from Prowler OCSF):
        {
            "status_code": "FAIL",
            "metadata": {"event_code": "check_id"},
            "cloud": {"provider": "aws", "region": "us-east-1", "account": {"uid": "111..."}},
            "resources": [{"uid": "resource_arn", "group": {"name": "service"}}],
            "severity": "medium",
            "finding_info": {"title": "...", "desc": "..."},
            "remediation": {"desc": "...", "references": ["url"]},
            "unmapped": {"compliance": {...}}
        }

        OUTPUT (estructura mejorada):
        {
            "status_code": "FAIL",
            "account_id": "111...",
            "resource_id": "arn:aws:...",
            "region": "us-east-1",
            "service": "s3",
            "check_id": "check_id",
            "severity": "medium",
            "title": "Check Title",
            "description": "Description",
            "remediation": "How to fix",
            "remediation_url": "https://...",
            "compliance": {...},
            "links": [{"title": "Reference", "url": "https://..."}],
            "raw_data": {...}  # TODO: para debugging
        }
        """

        # Extraer status
        status_code = item.get('status_code', 'UNKNOWN').upper()

        # Buscar account_id en múltiples ubicaciones (fallback)
        account_id = ''

        # Intento 1: unmapped.cloud.account.uid (ubicación correcta en Prowler OCSF)
        unmapped = item.get('unmapped', {})
        unmapped_cloud = unmapped.get('cloud', {})
        account_id = unmapped_cloud.get('account', {}).get('uid', '')

        # Intento 2: cloud.account.uid (alternativa)
        if not account_id:
            cloud = item.get('cloud', {})
            account_id = cloud.get('account', {}).get('uid', '')

        # Intento 3: account como string directo
        if not account_id:
            account = cloud.get('account') if cloud else None
            if isinstance(account, str):
                account_id = account

        # Intento 4: en metadata
        if not account_id:
            metadata = item.get('metadata', {})
            account_id = metadata.get('account_id', '')

        # Cloud info
        cloud = item.get('cloud', {})
        region = cloud.get('region', '') or unmapped_cloud.get('region', '')
        provider = cloud.get('provider', '') or unmapped_cloud.get('provider', 'aws')
        provider = provider.lower()

        # Recurso
        resources = item.get('resources', [])
        resource_id = resources[0].get('uid', '') if resources else ''
        service = resources[0].get('group', {}).get('name', '') if resources else ''

        # Fallback: extraer account_id del ARN del recurso si no se encontró antes
        if not account_id and resource_id and resource_id.startswith('arn:aws:'):
            # Formato: arn:aws:service:region:account-id:resource
            arn_parts = resource_id.split(':')
            if len(arn_parts) >= 5:
                account_id = arn_parts[4]

        # Check info
        metadata = item.get('metadata', {})
        check_id = metadata.get('event_code', '')

        # Severity
        severity = item.get('severity', 'medium').lower()

        # Finding info
        finding_info = item.get('finding_info', {})

        # Título: buscar en compliance.checks primero (nombre del check)
        title = check_id
        compliance_checks = item.get('compliance', {}).get('checks', [])
        if compliance_checks and isinstance(compliance_checks, list):
            title = compliance_checks[0].get('name', title)

        # Si no encontró en compliance, usar finding_info
        if not title or title == check_id:
            title = finding_info.get('title', check_id)

        # Descripción: de finding_info
        description = finding_info.get('desc', '')

        # Remediation (del nuevo template Prowler Web completo)
        remediation = item.get('remediation', {})
        remediation_desc = remediation.get('desc', '')
        remediation_urls = remediation.get('references', [])
        remediation_url = remediation_urls[0] if remediation_urls else ''

        # Risk Details (del nuevo template Prowler Web completo)
        risk_details = item.get('risk_details', '')

        # Compliance - extraer de unmapped.compliance (nuevo template Prowler Web)
        # En el nuevo template, compliance está en unmapped.compliance
        compliance_raw = unmapped.get('compliance', {})
        condicion_logica = ''

        # Si compliance es un dict con frameworks (nuevo template)
        if isinstance(compliance_raw, dict) and compliance_raw:
            # En el nuevo template, compliance es un dict con frameworks como keys
            # Ejemplo: {"CIS-1.4": ["1.20"], "NIST-CSF-2.0": ["po_3", "po_4"], ...}
            compliance = compliance_raw  # Guardar completo

            # Extraer primer control para condición lógica (si existe)
            first_key = next(iter(compliance_raw.keys())) if compliance_raw else None
            if first_key:
                first_controls = compliance_raw[first_key]
                if isinstance(first_controls, list) and first_controls:
                    condicion_logica = f"{first_key}: {', '.join(first_controls)}"
        else:
            # Fallback: si no hay compliance en unmapped, intentar en raíz
            compliance_root = item.get('compliance', {})
            if isinstance(compliance_root, dict):
                compliance = {
                    'standards': compliance_root.get('standards', []),
                    'requirements': compliance_root.get('requirements', []),
                    'control': compliance_root.get('control', ''),
                }
                condicion_logica = compliance_root.get('control', '')
            else:
                compliance = ProwlerDataExtractor.parse_compliance_string(compliance_raw)

        # DEBUG: loguear si hay compliance
        # if compliance:
        #     print(f" Compliance extraído para {check_id}: {len(compliance)} estándares")

        # Links: referencia del campo remediation + otros
        links = []
        if remediation_url:
            links.append({"title": "Remediation", "url": remediation_url})

        # Buscar más links en otros campos si existen
        for field in [description, remediation_desc]:
            extracted = ProwlerDataExtractor.extract_links_from_field(field)
            links.extend(extracted)

        # Estructura limpia
        parsed = {
            "status_code": status_code,
            "account_id": account_id,
            "resource_id": resource_id,
            "region": region,
            "service": service,
            "check_id": check_id,
            "severity": severity,
            "provider": provider,
            "title": title,
            "description": description,
            "remediation": remediation_desc,
            "remediation_url": remediation_url,
            "risk_details": risk_details,  # Nuevo: detalle del riesgo
            "compliance": compliance,
            "condition_logic": condicion_logica,  # Coincide con el campo SQL
            "links": links,
            "raw_data": item  # Guardar original para debuging
        }

        return parsed

    @staticmethod
    def generate_inventory_json(parsed_item: Dict) -> str:
        """
        Genera el JSON para guardar en inventory_data (SOLO salida de la herramienta)

        SOLO: status_code y account_id (resultado del escaneo)
        Lo demás va en referencias_data
        """
        inventory = {
            "status_code": parsed_item["status_code"],
            "account_id": parsed_item["account_id"]
        }
        return json.dumps(inventory, ensure_ascii=False, indent=2)

    @staticmethod
    def generate_referencias_json(parsed_item: Dict) -> str:
        """
        Genera el JSON para guardar en referencias_data (compliance + remediation + risk + links)

        {
            "compliance": {...},
            "remediation": "...",
            "remediation_url": "...",
            "risk_details": "...",
            "referencias": [
                {"titulo": "Remediation", "url": "https://..."},
                {"titulo": "Reference", "url": "https://..."}
            ]
        }
        """
        referencias = {
            "compliance": parsed_item.get("compliance", {}),
            "remediation": parsed_item.get("remediation", ""),
            "remediation_url": parsed_item.get("remediation_url", ""),
            "risk_details": parsed_item.get("risk_details", ""),
            "referencias": parsed_item.get("links", [])
        }
        return json.dumps(referencias, ensure_ascii=False, indent=2)

    @staticmethod
    def format_for_report(parsed_item: Dict) -> Dict:
        """
        Formatea los datos para mostrar en reportes
        Separa claramente:
        - Salida de herramienta: status_code + account_id
        - Referencias: compliance + links
        """
        return {
            "salida_herramienta": {
                "status_code": parsed_item["status_code"],
                "account_id": parsed_item["account_id"]
            },
            "referencias": {
                "compliance": parsed_item["compliance"],
                "documentacion": parsed_item["links"]
            }
        }


class ProwlerHTMLParser:
    """Parsea reportes HTML de Prowler (si necesitas procesarlos)"""

    @staticmethod
    def extract_compliance_from_html(html_text: str) -> Dict[str, List[str]]:
        """
        Extrae compliance del HTML del reporte Prowler
        Busca patrones como: •CIS-1.4: 1.3 •CIS-1.5: 1.
        """
        compliance = {}

        # Patrón: •STANDARD: control1, control2
        pattern = r'•([A-Za-z0-9\-\.]+):\s*([^\s•]+(?:\s+[^\s•]+)*)'

        for match in re.finditer(pattern, html_text):
            standard = match.group(1).strip()
            controls_str = match.group(2).strip()

            # Parsear controles separados por coma o espacio
            controls = [c.strip() for c in re.split(r'[,\s]+', controls_str) if c.strip()]

            if standard not in compliance:
                compliance[standard] = []
            compliance[standard].extend(controls)

        return compliance

    @staticmethod
    def extract_links_from_html(html_text: str, context: str = "") -> List[Dict]:
        """
        Extrae enlaces "Leer más..." del HTML de Prowler
        Busca patrones como: "texto <strong>Leer más...</strong>" con URL
        """
        links = []

        # Este patrón dependerá de tu HTML específico
        # Ajusta según tu estructura real

        return links
