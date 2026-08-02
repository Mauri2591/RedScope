# Traductor Modular - Arquitectura

## Problema

LibreTranslate es gratis pero puede que en el futuro quieras cambiar a:
- **DeepL** (mejor calidad pero pago)
- **Google Translate API** (integración con Google Cloud)

Sin una arquitectura modular, cambiar traductores significaría refactorizar código en múltiples archivos.

## Solución

`services/traductor.py` implementa el patrón **Factory + Strategy**:

### Estructura

```
TraductorBase (interfaz)
├── TraductorLibreTranslate (gratis, sin API key)
├── TraductorDeepL (premium, requiere API key)
└── TraductorGoogle (premium, requiere credenciales)

obtener_traductor(proveedor) → instancia de TraductorBase
```

## Uso Actual (LibreTranslate)

### Instalación

```bash
pip install libretranslate --break-system-packages
```

### Código

```python
from services.traductor import obtener_traductor

# Obtener instancia
traductor = obtener_traductor("libretranslate")

# Traducir
texto_traducido = traductor.traducir("Hello world")
# → "Hola mundo"

# Parámetros opcionales
texto_traducido = traductor.traducir(
    "Hello",
    idioma_origen="en",
    idioma_destino="es"
)
```

## Migración Futura (Sin Cambios en Código)

### Si compran DeepL

**Paso 1:** Obtener API key en https://www.deepl.com/pro

**Paso 2:** Cambiar UNA línea en donde se usa el traductor:

```python
# ANTES
traductor = obtener_traductor("libretranslate")

# DESPUÉS
traductor = obtener_traductor("deepl", api_key="sk-tu-api-key")
```

**Paso 3:** ¡Listo! El resto del código no cambia.

### Instalación de DeepL

```bash
pip install deepl --break-system-packages
```

## Dónde Integrar

### En `services/reportes_aws.py`

Traducir títulos y descripciones de hallazgos:

```python
from services.traductor import obtener_traductor

def _traducir_hallazgo(titulo_en, descripcion_en, remediacion_en):
    """Traduce los campos de un hallazgo de Prowler"""
    traductor = obtener_traductor("libretranslate")
    
    return {
        "titulo": traductor.traducir(titulo_en),
        "descripcion": traductor.traducir(descripcion_en),
        "remediacion": traductor.traducir(remediacion_en)
    }
```

### En `models/proyecto.py`

Al importar Prowler, traducir campos:

```python
from services.traductor import obtener_traductor

# En _import_prowler_web()
traductor = obtener_traductor("libretranslate")
titulo_es = traductor.traducir(parsed["titulo"])
descripcion_es = traductor.traducir(parsed["descripcion"])
```

## Ventajas

✅ **Cambio fácil** - 1 línea para cambiar de proveedor  
✅ **Sin refactoring** - El resto del código no se toca  
✅ **Testeable** - Puedes mockear el traductor en tests  
✅ **Extensible** - Agregar nuevos proveedores es simple  

## Ejemplo Completo

Ver `examples/uso_traductor.py` para casos de uso y ejemplos.

## Códigos de Idioma

LibreTranslate usa códigos ISO 639-1:

- `"es"` → Español
- `"en"` → Inglés
- `"fr"` → Francés
- `"de"` → Alemán
- `"pt"` → Portugués
- `"it"` → Italiano

[Lista completa](https://en.wikipedia.org/wiki/List_of_ISO_639-1_codes)
