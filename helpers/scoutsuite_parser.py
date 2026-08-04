"""
ScoutSuite Report Parser
Procesa reportes de ScoutSuite y extrae/organiza datos correctamente
"""
import json
import re
from typing import Dict, List, Tuple


class ScoutSuiteDataExtractor:
    """Extrae y estructura datos de reportes ScoutSuite"""

    @staticmethod
    def extract_region_from_path(path: str) -> str:
        """
        Extrae región de una ruta ScoutSuite
        Ej: "ec2.regions.us-east-1.vpcs.vpc-123.security_groups.sg-456"
        Retorna: "us-east-1"
        """
        match = re.search(r'\.regions\.([^\.]+)\.', path)
        return match.group(1) if match else ''

    @staticmethod
    def extract_resource_id_from_path(path: str) -> str:
        """
        Extrae el resource ID de una ruta ScoutSuite
        Ej: "ec2.regions.us-east-1.vpcs.vpc-123.security_groups.sg-456.rules.ingress..."
        Retorna: "sg-456" (último identificador de recurso)

        Estrategia: buscar IDs específicos de AWS primero
        """
        # Patrón 1: IDs específicos de AWS (sg-, vpc-, i-, ami-, snap-, etc)
        # Busca el ÚLTIMO ID de AWS en el path
        match = re.findall(r'((?:sg|vpc|i|ami|snap|key|bucket|role|user|group|instance|db|cls|rs|fs|ebs|acl|igw|ngw|tgw|vpce|subnet|rtb|trail|stream)-[a-z0-9]+)', path)
        if match:
            return match[-1]  # Retorna el último ID encontrado

        # Patrón 2: Nombres de buckets S3 (sin guión, después de "buckets.")
        match = re.search(r'\.buckets\.([^\.]+)', path)
        if match:
            return match.group(1)

        # Patrón 3: Para CloudTrail y otros sin recursos específicos, retornar el service + region
        # Ej: "cloudtrail.regions.us-east-1" → "cloudtrail-us-east-1"
        parts = path.split('.')
        if len(parts) >= 3:
            service = parts[0]
            # Buscar la región en el path
            region_match = re.search(r'\.regions\.([^\.]+)\.', path)
            if region_match:
                region = region_match.group(1)
                return f"{service}-{region}"

        # Fallback: retornar el servicio si no hay nada más
        if parts:
            return parts[0]

        return ""

    @staticmethod
    def extract_service_from_path(path: str) -> str:
        """
        Extrae servicio de una ruta ScoutSuite
        Ej: "ec2.regions.us-east-1..." → "ec2"
        """
        parts = path.split('.')
        return parts[0].lower() if parts else ''

    @staticmethod
    def parse_scoutsuite_finding(finding_id: str, finding_data: Dict, account_id: str) -> List[Dict]:
        """
        Transforma un finding de ScoutSuite en múltiples items de RedScope
        (uno por cada resource afectado)

        INPUT (from ScoutSuite):
        {
            "ec2-default-security-group-with-rules": {
                "checked_items": 38,
                "flagged_items": 34,
                "description": "Non-empty Rulesets for Default Security Groups",
                "level": "warning",
                "items": [
                    "ec2.regions.us-east-1.vpcs.vpc-123.security_groups.sg-456.rules.ingress",
                    ...
                ],
                "compliance": [{name, reference, version}],
                "remediation": "...",
                "references": [...]
            }
        }

        OUTPUT: lista de dicts (uno por item/recurso):
        [
            {
                "status_code": "FAIL",  (porque está en items, significa que falló)
                "account_id": "601227218666",
                "resource_id": "sg-456",
                "region": "us-east-1",
                "service": "ec2",
                "check_id": "ec2-default-security-group-with-rules",
                "severity": "warning",
                "title": "Non-empty Rulesets for Default Security Groups",
                "description": "...",
                "remediation": "...",
                "remediation_url": "",
                "compliance": {...},
                "condition_logic": "",
                "links": [...],
                "raw_data": {...}
            },
            ...
        ]
        """
        parsed_items = []

        # Mapeo de levels de ScoutSuite a severidad
        level_map = {
            'danger': 'critical',
            'warning': 'medium',
            'info': 'low'
        }

        # Datos comunes para todos los items
        description = finding_data.get('description', '')
        remediation_text = finding_data.get('remediation', '')
        level = finding_data.get('level', 'warning').lower()
        severity = level_map.get(level, 'medium')
        service = finding_data.get('service', '').lower()

        # Compliance (puede ser None en ScoutSuite)
        compliance_list = finding_data.get('compliance') or []
        compliance = {}
        if compliance_list and isinstance(compliance_list, list):
            for comp in compliance_list:
                key = f"{comp.get('name', '')}"
                value = comp.get('reference', '')
                if key and value:
                    compliance[key] = value

        # References/Links (puede ser None en ScoutSuite)
        references = finding_data.get('references') or []
        links = []
        if references and isinstance(references, list):
            for ref_url in references:
                if ref_url:
                    links.append({"title": "Reference", "url": ref_url})

        # Procesar cada item (recurso afectado)
        items = finding_data.get('items', [])
        print(f"[SCOUTSUITE_PARSER] Finding {finding_id}: {len(items)} items")

        for item_path in items:
            # Extraer datos del path
            region = ScoutSuiteDataExtractor.extract_region_from_path(item_path)
            resource_id_base = ScoutSuiteDataExtractor.extract_resource_id_from_path(item_path)
            item_service = ScoutSuiteDataExtractor.extract_service_from_path(item_path)

            # Si no hay región, skipear
            if not region:
                continue

            # Construir resource_id escalable: service-account-region
            # Ej: cloudtrail-601227218666-ap-northeast-1
            resource_id = f"{item_service}-{account_id}-{region}"
            if resource_id_base and not resource_id_base.startswith(item_service):
                # Si hay un ID específico (sg-123), incluirlo: sg-123-account-region
                resource_id = f"{resource_id_base}-{account_id}-{region}"

            # Construir item parseado
            parsed = {
                "status_code": "FAIL",  # Si está en items, es un fallo
                "account_id": account_id,
                "resource_id": resource_id,
                "region": region,
                "service": item_service or service,
                "check_id": finding_id,
                "severity": severity,
                "provider": "aws",
                "title": description,
                "description": description,
                "remediation": remediation_text,
                "remediation_url": references[0] if references else '',
                "risk_details": "",
                "compliance": compliance,
                "condition_logic": "",
                "links": links,
                "raw_data": {
                    "finding_id": finding_id,
                    "item_path": item_path,
                    "original_finding": finding_data
                }
            }

            parsed_items.append(parsed)

        return parsed_items

    @staticmethod
    def generate_inventory_json(parsed_item: Dict) -> str:
        """
        Genera JSON para inventory_data
        ScoutSuite: status_code, account_id, resource_id, item_path
        """
        inventory = {
            "status_code": parsed_item["status_code"],
            "account_id": parsed_item["account_id"],
            "resource_id": parsed_item.get("resource_id", ""),
            "item_path": parsed_item.get("raw_data", {}).get("item_path", "")
        }
        return json.dumps(inventory, ensure_ascii=False, indent=2)

    @staticmethod
    def generate_referencias_json(parsed_item: Dict) -> str:
        """
        Genera JSON para referencias_data (compliance + remediation + links)
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
        Formatea datos para reportes
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
