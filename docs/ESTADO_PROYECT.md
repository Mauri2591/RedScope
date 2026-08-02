# RedScope - Estado del Proyecto (Agosto 2026)

## ✅ Completado

### 1. Separación de Datos Prowler
- **Problema:** Todos los datos de Prowler (status, compliance, links) mezclados en un campo
- **Solución:** Dos campos separados en BD:
  - `inventory_data` → Status, account, resource (datos de la herramienta)
  - `referencias_data` → Compliance frameworks + links (datos de referencia)
- **Archivo:** `helpers/prowler_parser.py` - Parser modular que extrae y transforma

### 2. Rendering de Compliance en Reportes
- **Problema:** Compliance mostrado como string sin formato o fuera de la tabla
- **Solución:** Renderizado como tabla con:
  - Columna izquierda: "Cumplimiento"
  - Columna derecha: Lista de bullets con frameworks y controles
  - Ejemplo:
    ```
    Cumplimiento | • AWS-Well-Architected-Framework: SEC05-BP03
                 | • C5-2025: COS-03.01B
                 | • ISO27001-2022: A.8.20, A.8.21, A.8.22
    ```
- **Archivo:** `services/reportes_aws.py` - Métodos `_agrupar_findings_por_check()` y `_bloque_detalle_hallazgos()`

### 3. Modelo Modular de Traducción
- **Problema:** ¿Usar LibreTranslate (gratis) o DeepL (pago)?
- **Solución:** Arquitectura factory pattern que permite cambiar traductores sin refactoring
- **Archivo:** `services/traductor.py`
- **Características:**
  - LibreTranslate (local o API pública)
  - DeepL (para futuro)
  - Google Translate (para futuro)
  - Modo mock para desarrollo/testing

### 4. Instalación de Dependencias
- ✅ LibreTranslate instalado y funcional
- ✅ requests disponible
- ✅ Módulo traductor listo para usar

## 📋 TODO - Próximas Fases

### Fase 1: Integración Básica de Traducción
Dónde integrar el traductor en el flujo de reportes:

1. **En `_import_prowler_web()` (models/proyecto.py)**
   - Traducir título y descripción al importar
   - Guardar en BD

2. **En `_agrupar_findings_por_check()` (services/reportes_aws.py)**
   - Traducir campos durante agregación
   - O hacerlo post-importación

3. **Campos a traducir:**
   - `titulo` (check name)
   - `descripcion` (risk description)
   - `remediacion` (remediation steps)

### Fase 2: Setup de Servidor Local
Para activar traducciones reales (ahora está en mock):

```bash
# Opción 1: Docker
docker run -d -p 5000:5000 --name libretranslate libretranslate/libretranslate:latest

# Opción 2: Python local
libretranslate --port 5000
```

Ver detalles en `docs/SETUP_LIBRETRANSLATE.md`

### Fase 3: Testing y Validación
- Generar reporte con Prowler import
- Verificar que compliance se renderiza bien
- Verificar que traducciones aparecen (si servidor instalado)

## 📁 Archivos Creados/Modificados

| Archivo | Tipo | Descripción |
|---------|------|------------|
| `services/traductor.py` | ✨ NUEVO | Módulo modular de traducción |
| `examples/uso_traductor.py` | ✨ NUEVO | Ejemplos de uso |
| `docs/TRADUCTOR_MODULAR.md` | ✨ NUEVO | Documentación arquitectura |
| `docs/SETUP_LIBRETRANSLATE.md` | ✨ NUEVO | Setup servidor local |
| `helpers/prowler_parser.py` | ✏️ EXISTENTE | Parser Prowler (de sesión anterior) |
| `services/reportes_aws.py` | ✏️ EXISTENTE | Rendering compliance (de sesión anterior) |
| `models/proyecto.py` | ✏️ EXISTENTE | Import/DB (de sesión anterior) |

## 🎯 Arquitectura de Traducción

```
Usuario solicita reporte
    ↓
Prowler data se importa
    ├─ inventory_data (tool output)
    └─ referencias_data (compliance)
    ↓
Durante report generation:
    ├─ Traducir título/desc/remediación
    └─ Renderizar compliance como tabla
    ↓
Generar Word report
```

## 🔧 Uso Rápido

### Traducir un texto
```python
from services.traductor import obtener_traductor

traductor = obtener_traductor("libretranslate")
texto_es = traductor.traducir("Hello world")
```

### Cambiar a DeepL (futuro)
```python
# Una sola línea cambia
traductor = obtener_traductor("deepl", api_key="sk-xxx")
```

## 📊 Diagrama de Flujo

```
Prowler JSON Input
    ↓
[ProwlerDataExtractor]
    ├→ Parse check_id, provider, service, resource
    ├→ Extract compliance frameworks
    └→ Extract links
    ↓
Split en dos campos
    ├→ inventory_data {status_code, account_id}
    └→ referencias_data {compliance: {framework: [controls]}}
    ↓
[DB insert]
    ├→ findings.inventory_data
    └→ findings.referencias_data
    ↓
[Reporte generation]
    ├→ get_data_reporte() → fetch ambos campos
    ├→ _agrupar_findings_por_check() → agregar por check_id
    ├→ _bloque_detalle_hallazgos() → renderizar tabla
    │   └→ Compliance como row con bullets
    └→ Traducir campos si traductor activo
    ↓
[Word report output]
```

## 💾 Base de Datos

```sql
-- findings table (campos relevantes)
ALTER TABLE findings ADD COLUMN referencias_data LONGTEXT;

-- Estructura esperada en referencias_data:
{
  "compliance": {
    "AWS-Well-Architected-Framework": ["SEC05-BP03"],
    "ISO27001-2022": ["A.8.20", "A.8.21", "A.8.22"]
  },
  "referencias": [
    {
      "titulo": "AWS Best Practices",
      "url": "https://..."
    }
  ]
}
```

## 🚀 Próximas Acciones Sugeridas

1. **Instalar servidor LibreTranslate** (Docker o local)
2. **Integrar traductor en `_import_prowler_web()`**
3. **Generar reporte de prueba**
4. **Validar que compliance + traducciones funcionen**
5. **Documentar casos de uso específicos**

---
**Última actualización:** 2026-08-02
**Estado:** Arquitectura lista, testing/integración pendiente
