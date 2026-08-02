# preprocesar_mitre.py
import json

with open('enterprise-attack.json', encoding='utf-8') as f:
    data = json.load(f)

tecnicas = {}
for obj in data['objects']:
    if obj['type'] == 'attack-pattern':
        for ref in obj.get('external_references', []):
            if ref.get('source_name') == 'mitre-attack' and ref.get('external_id', '').startswith('T'):
                tecnicas[ref['external_id']] = {
                    'nombre': obj['name'],
                    'descripcion': obj.get('description', '')[:300],
                    'url': ref.get('url', '')
                }

with open('mitre_tecnicas.json', 'w', encoding='utf-8') as f:
    json.dump(tecnicas, f, ensure_ascii=False, indent=2)

print(f"Técnicas exportadas: {len(tecnicas)}")