# Setup: LibreTranslate Local

## Estado Actual

El módulo traductor está **funcional** en modo mock (sin traducción real) para desarrollo.

Para activar traducciones reales, necesitas ejecutar LibreTranslate como servidor local.

## Opción 1: Docker (Recomendado)

### Instalación

```bash
docker pull libretranslate/libretranslate:latest
```

### Ejecutar

```bash
docker run -d \
  -p 5000:5000 \
  --name libretranslate \
  libretranslate/libretranslate:latest
```

### Verificar

```bash
curl http://localhost:5000/
# Respuesta: {"status":"OK"}
```

## Opción 2: Python Local

### Instalación

Ya está hecho (LibreTranslate se instaló con pip).

### Ejecutar

```bash
libretranslate --port 5000
```

Esto iniciará el servidor en `http://localhost:5000`

⚠️ **Nota:** La primera ejecución descargará los modelos de idioma (puede tomar 5-10 minutos y varios GB de espacio).

## Validar en RedScope

Una vez que LibreTranslate esté corriendo:

```python
from services.traductor import obtener_traductor

traductor = obtener_traductor("libretranslate", modo="local")
resultado = traductor.traducir("Hello world")
print(resultado)  # "Hola mundo"
```

## Integración en Reportes

### Uso Simple

```python
from services.traductor import obtener_traductor

traductor = obtener_traductor("libretranslate")
titulo_es = traductor.traducir(hallazgo["titulo"])
descripcion_es = traductor.traducir(hallazgo["descripcion"])
```

### Traducir Lote (Más Eficiente)

```python
traductor = obtener_traductor("libretranslate")

hallazgos = [...datos de Prowler...]
for hallazgo in hallazgos:
    hallazgo["titulo_es"] = traductor.traducir(hallazgo["titulo"])
    hallazgo["descripcion_es"] = traductor.traducir(hallazgo["descripcion"])
    hallazgo["remediacion_es"] = traductor.traducir(hallazgo["remediacion"])
```

## Troubleshooting

### "Servidor no encontrado en localhost:5000"

**Solución:** Asegúrate que LibreTranslate está ejecutándose:

```bash
# Ver si el puerto 5000 está en uso
lsof -i :5000

# Si usa Docker, ver logs
docker logs libretranslate

# Si usa Python, ejecutar en terminal:
libretranslate --port 5000
```

### Traducción retorna texto sin cambios

**Causas:**
1. Servidor no está corriendo → Inicia LibreTranslate
2. Modo mock activado → Cambia a modo "local"
3. Idiomas no descargados → Espera a que termine descarga inicial

### Lento al traducir (Primera ejecución)

**Normal:** LibreTranslate descarga modelos de idiomas la primera vez.
- Tamaño: ~2GB
- Tiempo: 5-10 minutos

Después es rápido (millisegundos por frase).

## Costos

| Opción | Costo | Velocidad | Límites |
|--------|-------|-----------|---------|
| **LibreTranslate Local** | $0 | Medio | Ninguno |
| **DeepL API** | Pago | Rápido | Por uso |
| **Google Translate** | Pago | Rápido | Por uso |

## Para Cambiar a DeepL en el Futuro

Solo necesitas:

```python
# Cambiar esta línea
traductor = obtener_traductor("libretranslate")

# Por esta
traductor = obtener_traductor("deepl", api_key="tu-api-key")
```

El resto del código no cambia. ✨
