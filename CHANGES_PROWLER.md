# Cambios en Procesamiento de Prowler - Agosto 2026

## 📋 Resumen

Se mejoró la estructura de datos de Prowler para **separar claramente**:
- ✅ Status de la herramienta (status_code, account_id)
- ✅ Cumplimiento (compliance frameworks)
- ✅ Enlaces (links de referencia)

**Resultado**: Reportes más legibles y datos mejor organizados.

---

## 📁 Archivos Modificados

### 1. **helpers/prowler_parser.py** (NUEVO)
Helper completo para procesar Prowler:
- `ProwlerDataExtractor.parse_prowler_item()` - Normaliza datos
- `ProwlerDataExtractor.generate_inventory_json()` - Estructura limpia para DB
- `ProwlerDataExtractor.format_for_report()` - Formato para reportes

### 2. **models/proyecto.py** (ACTUALIZADO)
Método `_import_prowler_web()`:
- Ahora usa `ProwlerDataExtractor` automáticamente
- Genera `inventory_data` con status_code + account_id
- Genera `referencias_data` con compliance + links
- Inserta en ambos campos automáticamente

### 3. **services/reportes_aws.py** (ACTUALIZADO)
Bloque de evidencia:
- Lee `inventory_data` → Muestra "Salida de la herramienta"
- Lee `referencias_data` → Muestra "Referencias" con:
  - Tabla clara de "Cumplimiento" por estándar
  - Sección "Referencias" con links descriptivos

### 4. **docs/PROWLER_STRUCTURE.md** (NUEVO)
Documentación detallada de:
- Estructura anterior vs nueva
- Ejemplos de JSON
- Cómo usar en código
- FAQ

### 5. **scripts/migrate_prowler_data.py** (NUEVO)
Script para migrar datos antiguos:
```bash
python scripts/migrate_prowler_data.py --proyecto_id 27
python scripts/migrate_prowler_data.py --all
```

### 6. **tests/prowler_example.json** (NUEVO)
Archivo de ejemplo con 3 findings de prueba.

---

## 🔄 Estructura de Datos

### Campo `inventory_data` (Salida de Herramienta)
```json
{
  "status_code": "FAIL",
  "account_id": "111046292918"
}
// Solo lo que Prowler reporta como OUTPUT
```

### Campo `referencias_data` (Referencias y Cumplimiento)
```json
{
  "compliance": {
    "CIS-1.4": ["1.20"],
    "ISO27001-2022": ["A.8.3"],
    "NIS2": ["3.2.3.e", "11.1.1"]
  },
  "referencias": [
    {"title": "Remediation", "url": "https://docs.aws.amazon.com/..."},
    {"title": "Reference", "url": "https://cis.org/..."}
  ]
}
// Compliance + Links separados
```

✅ **Ventaja:** Dos campos independientes = mejor performance y queries específicas

---

## 🚀 Cómo Usar

### Para Nuevas Importaciones (Automático)
```python
# Ya funciona automáticamente con _import_prowler_web
Proyecto.import_findings(proyecto_id, 'prowler_web', data, usuario_id)
# El parser se aplica automáticamente
```

### Para Datos Existentes (Migración)
```bash
cd RedScoe
python scripts/migrate_prowler_data.py --proyecto_id 27

# O migrar todo:
python scripts/migrate_prowler_data.py --all
```

### En Código (Si necesitas)
```python
from helpers.prowler_parser import ProwlerDataExtractor

# 1. Parsear
parsed = ProwlerDataExtractor.parse_prowler_item(prowler_item)

# 2. Generar JSON para guardar
json_str = ProwlerDataExtractor.generate_inventory_json(parsed)

# 3. Formatear para mostrar
formatted = ProwlerDataExtractor.format_for_report(parsed)
```

---

## 📊 Resultado en Reportes Word

Cuando se genera un reporte, ahora muestra:

```
═══════════════════════════════════════════════════════

    SALIDA DE LA HERRAMIENTA:
    ┌─────────────────────────────────────┐
    │ status_code: FAIL                   │
    │ account_id: 111046292918            │
    └─────────────────────────────────────┘

    CUMPLIMIENTO:
    ┌──────────────────┬─────────────────┐
    │ CIS-1.4          │ 1.20            │
    │ ISO27001-2022    │ A.8.3           │
    │ NIS2             │ 3.2.3.e, 11.1.1 │
    └──────────────────┴─────────────────┘

    ENLACES:
    • Remediation: https://docs.aws.amazon.com/...
    • Reference: https://cis.org/...

═══════════════════════════════════════════════════════
```

---

## ✅ Verificación

Después de los cambios, verifica que:

1. **Nuevos imports funcionan:**
   ```bash
   # Importa un JSON de Prowler
   # Verifica que se guarden con estructura mejorada
   SELECT inventory_data FROM findings WHERE herramienta='prowler_web' LIMIT 1;
   # Debe tener "links" field
   ```

2. **Reportes se generan correctamente:**
   ```bash
   # Genera un reporte
   # Verifica que se vean 3 secciones:
   # - Salida de herramienta
   # - Cumplimiento
   # - Enlaces
   ```

3. **(Opcional) Migra datos antiguos:**
   ```bash
   python scripts/migrate_prowler_data.py --proyecto_id 27
   ```

---

## 🐛 Troubleshooting

**Error: "ImportError: No module named helpers.prowler_parser"**
- Verifica que `helpers/prowler_parser.py` exista
- Asegúrate de estar en el directorio raíz de RedScoe

**Error: "KeyError" al procesar Prowler**
- Verifica que el JSON de Prowler siga formato OCSF
- Revisa `tests/prowler_example.json` para referencia

**Los links no aparecen en reporte**
- Verifica que `inventory_data` tenga el campo `"links": [...]`
- Ejecuta migración: `python scripts/migrate_prowler_data.py --all`

---

## 📝 Notas de Desarrollo

### Estructura Extensible
El parser es fácil de extender:
- Agregar nuevos patrones de links en `extract_links_from_field()`
- Soportar nuevos formatos de Prowler (CLI, HTML)
- Integrar más herramientas de escaneo

### Backward Compatibility
- Los datos antiguos siguen siendo válidos
- El sistema detecta automáticamente el formato
- La migración es opcional

### Futuro
- [ ] Parser para Prowler CLI (CSV/JSON plano)
- [ ] Parser para reportes HTML de Prowler
- [ ] API REST para acceder a datos estructurados
- [ ] Dashboard de cumplimiento normativo

---

## 📞 Contacto

Si tienes preguntas sobre los cambios, revisa:
1. `docs/PROWLER_STRUCTURE.md` - Documentación técnica
2. `helpers/prowler_parser.py` - Código con comentarios
3. `tests/prowler_example.json` - Ejemplos de entrada/salida

---

**Versión:** 1.0
**Fecha:** Agosto 2026
**Autor:** Sistema RedScope
