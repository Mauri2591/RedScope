# Estructura Mejorada de Datos Prowler

## Problema Original

El reporte HTML de Prowler mostraba todos los datos mezclados:
- Status y compliance juntos en la tabla
- Links y recomendaciones sin separación clara
- Difícil de procesar y mostrar en reportes profesionales

## Solución Implementada

Se separaron los datos en campos claramente diferenciados:

### 1. **Salida de la Herramienta** (Tool Output)
```
status_code: FAIL
account_id: 111046292918
```

Solo lo esencial del estado de Prowler.

### 2. **Cumplimiento** (Compliance)
```
| Estándar      | Controles                          |
|----------------|-------|-----------|
| NIS2           | 3.2.3.e, 11.1.1, 11.2.1            |
| CIS-1.4        | 1.20                               |
| ISO27001-2022  | A.8.3                              |
```

Claramente separado, en tabla para lectura fácil.

### 3. **Enlaces** (Links)
```
Enlaces:
• Remediation: https://...
• Reference: https://...
```

Cada link claramente identificado.

---

## Estructura en la Base de Datos

Ahora se usa **DOS campos separados**:

### Campo 1: `inventory_data` (Salida de la Herramienta)
```json
{
  "status_code": "FAIL",
  "account_id": "111046292918"
}
```
**Solo:** status_code del escaneo + ID de cuenta

### Campo 2: `referencias_data` (Referencias y Cumplimiento)
```json
{
  "compliance": {
    "NIS2": ["3.2.3.e", "11.1.1"],
    "CIS-1.4": ["1.20"],
    "ISO27001-2022": ["A.8.3"]
  },
  "referencias": [
    {
      "title": "Remediation",
      "url": "https://docs.aws.amazon.com/..."
    },
    {
      "title": "Reference",
      "url": "https://cis.org/..."
    }
  ]
}
```
**Contiene:** compliance frameworks + links de documentación

**Ventajas:**
- ✅ Separación clara de responsabilidades
- ✅ Mejor performance (campos separados)
- ✅ Facilita búsquedas por cumplimiento normativo
- ✅ Queries más rápidas y específicas
- ✅ Compatible con índices en BD

---

## Uso en el Código

### Parser Helper (`helpers/prowler_parser.py`)

```python
from helpers.prowler_parser import ProwlerDataExtractor

# 1. Parsear un item de Prowler
parsed = ProwlerDataExtractor.parse_prowler_item(prowler_item)
# Retorna estructura limpia con todos los campos

# 2. Generar JSON para guardar en DB
inventory_json = ProwlerDataExtractor.generate_inventory_json(parsed)
# Retorna string JSON listo para insertar

# 3. Formatear para mostrar en reportes
formatted = ProwlerDataExtractor.format_for_report(parsed)
# Retorna dict con tool_output, compliance, links separados
```

### Importación Automática (`_import_prowler_web`)

Ya actualizado para:
1. Usar el nuevo parser automáticamente
2. Generar la estructura mejorada
3. Guardar en `inventory_data` correctamente

### Renderizado en Reportes (`reportes_aws.py`)

Ahora el bloque de evidencia muestra:
1. **Salida de la herramienta** (fondo oscuro, mono-espacio)
2. **Cumplimiento** (tabla clara con estándares y controles)
3. **Enlaces** (bullets con títulos descriptivos)

---

## Ejemplo Completo

### Input (Prowler JSON-OCSF):
```json
{
  "status_code": "FAIL",
  "metadata": {"event_code": "s3_bucket_default_encryption"},
  "cloud": {
    "provider": "aws",
    "region": "us-east-1",
    "account": {"uid": "111046292918"}
  },
  "resources": [{
    "uid": "arn:aws:s3:::my-bucket",
    "group": {"name": "s3"}
  }],
  "severity": "medium",
  "finding_info": {
    "title": "S3 bucket default encryption",
    "desc": "Check that S3 bucket has default encryption enabled"
  },
  "remediation": {
    "desc": "Enable default encryption on the S3 bucket",
    "references": ["https://docs.aws.amazon.com/AmazonS3/latest/dev/bucket-encryption.html"]
  },
  "unmapped": {
    "compliance": {
      "CIS-1.4": ["2.1.5"],
      "ISO27001-2022": ["A.10.1"]
    }
  }
}
```

### Output (inventory_data en DB):
```json
{
  "status_code": "FAIL",
  "account_id": "111046292918",
  "compliance": {
    "CIS-1.4": ["2.1.5"],
    "ISO27001-2022": ["A.10.1"]
  },
  "links": [
    {
      "title": "Remediation",
      "url": "https://docs.aws.amazon.com/AmazonS3/latest/dev/bucket-encryption.html"
    }
  ]
}
```

### Renderizado en Reporte:
```
SALIDA DE LA HERRAMIENTA:
┌──────────────────────────────┐
│ status_code: FAIL            │
│ account_id: 111046292918     │
└──────────────────────────────┘

CUMPLIMIENTO:
┌────────────────┬────────────┐
│ CIS-1.4        │ 2.1.5      │
├────────────────┼────────────┤
│ ISO27001-2022  │ A.10.1     │
└────────────────┴────────────┘

ENLACES:
• Remediation: https://docs.aws.amazon.com/AmazonS3/latest/dev/bucket-encryption.html
```

---

## Migración de Datos Antiguos

Si ya tienes findings con la estructura antigua, ejecuta:

```bash
python scripts/migrate_prowler_data.py --proyecto_id 27
```

Esto actualizará todos los `inventory_data` a la nueva estructura.

---

## API REST (Futuro)

```python
GET /api/findings/{finding_id}/inventory
# Retorna:
{
  "tool_output": {...},
  "compliance": {...},
  "links": [...]
}
```

Facilita integración con dashboards y otros sistemas.

---

## FAQ

**P: ¿Los datos antiguos se pierden?**
R: No. El campo `raw_data` dentro de `parsed` guarda el original para debugging.

**P: ¿Puedo agregar más links?**
R: Sí. Modifica `ProwlerDataExtractor.extract_links_from_field()` para parsear más patrones.

**P: ¿Cómo muestro esto en mi frontend?**
R: El JSON en `inventory_data` ya está separado. Solo parsea `compliance` y `links` por separado en tu JS/HTML.

---

## Próximos Pasos

1. ✅ Parser de Prowler Web (JSON-OCSF)
2. ⬜ Parser de Prowler CLI (CSV/JSON plano)
3. ⬜ Parser de Prowler HTML (si importas desde HTML)
4. ⬜ API REST para acceder a datos estructurados
5. ⬜ Dashboard interactivo mostrando compliance
