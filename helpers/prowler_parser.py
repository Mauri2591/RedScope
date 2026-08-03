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

        # Cloud info
        cloud = item.get('cloud', {})
        account_id = cloud.get('account', {}).get('uid', '')
        region = cloud.get('region', '')
        provider = cloud.get('provider', 'aws').lower()

        # Recurso
        resources = item.get('resources', [])
        resource_id = resources[0].get('uid', '') if resources else ''
        service = resources[0].get('group', {}).get('name', '') if resources else ''

        # Check info
        metadata = item.get('metadata', {})
        check_id = metadata.get('event_code', '')

        # Severity
        severity = item.get('severity', 'medium').lower()

        # Finding info
        finding_info = item.get('finding_info', {})
        title = finding_info.get('title', check_id)
        description = finding_info.get('desc', '')

        # Remediation
        remediation = item.get('remediation', {})
        remediation_desc = remediation.get('desc', '')
        remediation_urls = remediation.get('references', [])
        remediation_url = remediation_urls[0] if remediation_urls else ''

        # Compliance - extraer del campo unmapped.compliance
        unmapped = item.get('unmapped', {})
        compliance_raw = unmapped.get('compliance', {})

        # Parsear compliance (puede venir como string o dict)
        compliance = ProwlerDataExtractor.parse_compliance_string(compliance_raw)

        # DEBUG: loguear si hay compliance
        # if compliance:
        #     print(f"✅ Compliance extraído para {check_id}: {len(compliance)} estándares")

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
            "compliance": compliance,
            "links": links,
            "raw_data": item  # Guardar original para debuging
        }

        return parsed

    @staticmethod
    def generate_inventory_json(parsed_item: Dict) -> str:
        """
        Genera el JSON para guardar en inventory_data (salida de la herramienta)

        SOLO status_code y account_id
        """
        inventory = {
            "status_code": parsed_item["status_code"],
            "account_id": parsed_item["account_id"]
        }
        return json.dumps(inventory, ensure_ascii=False, indent=2)

    @staticmethod
    def generate_referencias_json(parsed_item: Dict) -> str:
        """
        Genera el JSON para guardar en referencias_data (compliance + links)

        {
            "compliance": {...},
            "referencias": [
                {"titulo": "Remediation", "url": "https://..."},
                {"titulo": "Reference", "url": "https://..."}
            ]
        }
        """
        referencias = {
            "compliance": parsed_item["compliance"],
            "referencias": parsed_item["links"]  # Renombrado a referencias
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
