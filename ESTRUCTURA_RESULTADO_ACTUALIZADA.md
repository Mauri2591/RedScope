# Estructura de Resultados - Detección de Herramientas IA

## Cambios Principales

Se ha restructurado completamente PASO 7 (Compilar resultados finales) para crear una **separación cristal-clara** entre:

1. **REVALIDACIÓN**: Confirmar que el hallazgo existe
2. **VULNERABILIDADES**: Explotar si es vulnerable

---

## Estructura JSON Actualizada

```json
{
  "timestamp": "2024-XX-XX",
  "tipo": "deteccion_ia_tools",
  "detalle_por_ia": {
    "OpenAI": {
      "nombre_ia": "OpenAI",
      "ocurrencias": 5,
      "targets_afectados": 2,
      "targets": ["www.example.com", "api.example.com"],
      "urls_encontradas": ["https://www.example.com/api", "https://www.example.com/chat"],
      "severidad_id": 2,
      "severidad_nombre": "MEDIUM",
      "descripcion": "Se detectó OpenAI en 2 target(s)",
      
      "_workflow": {
        "paso_1": "Ejecutar comandos en sección 'revalidar' para CONFIRMAR hallazgo",
        "paso_2": "Si revalidación exitosa, usar comandos en sección 'vulnerabilidades' para EXPLOTAR (si aplica)",
        "paso_3": "Aplicar mitigaciones sugeridas"
      },
      
      "revalidar": [
        {
          "url": "https://www.example.com/api",
          "patron": "sk-[a-zA-Z0-9]{20,}",
          "fragmento_encontrado": "sk-proj_abcd1234...",
          "linea_aproximada": 156,
          "comando_curl_directo": "curl -s 'https://www.example.com/api' | grep -i 'sk-'",
          "comando_con_guardado": "curl -s 'https://www.example.com/api' -o /tmp/revalidar.html && grep -i 'sk-' /tmp/revalidar.html",
          "comando_con_cabeceros": "curl -s -H 'User-Agent: Mozilla/5.0' 'https://www.example.com/api' | grep -i 'sk-'",
          "validar_manual": "Navega a: https://www.example.com/api → Ctrl+F → Busca: 'sk-proj_abcd1234...'",
          "tipo": "curl|grep - Confirma que el patrón existe en la respuesta HTTP"
        }
      ],
      
      "vulnerabilidades": [
        {
          "cve": "CVE-2023-49070",
          "nombre": "OpenAI API Key Exposure in Log Files",
          "severidad": 7.5,
          "descripcion": "API keys and sensitive data exposed in debug logs and error messages",
          "ano": 2023,
          "afecta": "OpenAI API clients <= v0.27",
          "poc": "grep -r 'sk-' logs/ | head -20",
          "mitigacion": "Actualizar a versión >= v0.28, usar environment variables, nunca loguear tokens",
          "referencias": ["https://nvd.nist.gov/vuln/detail/CVE-2023-49070"],
          "fuente": "BD local",
          "tipo": "Explotación - Intenta explotar la vulnerabilidad"
        }
      ]
    }
  }
}
```

---

## Diferencia: REVALIDACIÓN vs VULNERABILIDADES

### 🔍 REVALIDACIÓN (Confirmar hallazgo)
**Propósito**: Que el pentester verifique que el hallazgo realmente existe

**Comandos**:
```bash
# 1. Rápido: curl + grep directo
curl -s 'https://www.example.com/api' | grep -i 'sk-'

# 2. Con guardado: curl a archivo + grep
curl -s 'https://www.example.com/api' -o /tmp/revalidar.html && grep -i 'sk-' /tmp/revalidar.html

# 3. Con cabeceros: simula navegador real
curl -s -H 'User-Agent: Mozilla/5.0' 'https://www.example.com/api' | grep -i 'sk-'

# 4. Manual: abre en navegador y busca
Navega a: https://www.example.com/api → Ctrl+F → Busca: 'sk-proj_abcd1234...'
```

**¿Qué hace?**: 
- ✅ Confirma que el patrón existe en la respuesta HTTP
- ✅ Reproduce exactamente cómo la herramienta detectó el hallazgo
- ✅ Usa la URL EXACTA donde se encontró
- ✅ Busca el PATRÓN EXACTO y el FRAGMENTO encontrado

---

### ⚠️ VULNERABILIDADES/POC (Explotar si vulnerable)
**Propósito**: Si se confirma que usa esa IA, ver si tiene vulnerabilidades conocidas y cómo explotarlas

**Ejemplo POC**:
```bash
# CVE-2023-49070: OpenAI API Key Exposure
grep -r 'sk-' logs/ | head -20

# CVE-2024-0001: Claude API Token Leakage
curl -X POST 'https://api.anthropic.com/v1/messages' \
  -H 'Authorization: Bearer INVALID_TOKEN' \
  -d '{}' 2>&1 | grep -i 'sk-ant'
```

**¿Qué hace?**:
- ⚠️ Intenta explotar una vulnerabilidad CVE conocida
- ⚠️ NO confirma que el hallazgo existe (eso es REVALIDACIÓN)
- ⚠️ SOLO si se confirma que usa esa IA
- ⚠️ Puede dañar/afectar el sistema

---

## Flujo de Trabajo Pentester (IMPORTANTE)

```
┌─────────────────────────────────────────────────────┐
│ 1. REVALIDAR: Confirma que el hallazgo existe      │
│                                                      │
│ curl -s 'https://example.com/api' | grep -i 'sk-' │
│                                                      │
│ ✅ Sale match? → HALLAZGO CONFIRMADO                │
│ ❌ No sale? → Falso positivo                         │
└─────────────────────────────────────────────────────┘
                        ↓
            (SI CONFIRMADO, CONTINUAR)
                        ↓
┌─────────────────────────────────────────────────────┐
│ 2. VULNERABILIDADES: Intenta explotar               │
│                                                      │
│ grep -r 'sk-' logs/                                 │
│ curl -X POST 'https://api.openai.com/...'           │
│                                                      │
│ ⚠️ SOLO si paso 1 fue exitoso                        │
│ ⚠️ POC es exploración, no confirmación               │
└─────────────────────────────────────────────────────┘
                        ↓
┌─────────────────────────────────────────────────────┐
│ 3. MITIGAR: Aplicar recomendaciones de seguridad   │
│                                                      │
│ - Actualizar versión                                │
│ - Cambiar API keys                                  │
│ - Implementar secrets management                    │
└─────────────────────────────────────────────────────┘
```

---

## Cambios Específicos en handlers.py

### ANTES (línea 5611)
```python
'validar': validaciones if validaciones else _generar_comandos_validacion(ia, info['urls']),
'vulnerabilidades': vulnerabilidades
```

### AHORA (línea 5623+)
```python
'_workflow': {
    'paso_1': 'Ejecutar comandos en sección "revalidar" para CONFIRMAR hallazgo',
    'paso_2': 'Si revalidación exitosa, usar comandos en sección "vulnerabilidades" para EXPLOTAR (si aplica)',
    'paso_3': 'Aplicar mitigaciones sugeridas'
},
'revalidar': revalidar,           # ← CONFIRMAR: Hallazgo existe
'vulnerabilidades': vulnerabilidades  # ← EXPLOTAR: Si es explotable
```

---

## Nuevos Campos en "revalidar"

| Campo | Descripción | Ejemplo |
|-------|-------------|---------|
| `url` | URL exacta donde se detectó | `https://www.example.com/api` |
| `patron` | Patrón regex exacto | `sk-[a-zA-Z0-9]{20,}` |
| `fragmento_encontrado` | HTML/texto encontrado | `sk-proj_abcd1234...` |
| `linea_aproximada` | Línea en respuesta HTML | `156` |
| `comando_curl_directo` | Curl rápido + grep | `curl -s '...' \| grep -i '...'` |
| `comando_con_guardado` | Curl guarda archivo + grep | `curl -s '...' -o /tmp/... && grep` |
| `comando_con_cabeceros` | Curl con User-Agent | `curl -s -H 'User-Agent: Mozilla/5.0' '...'` |
| `validar_manual` | Instrucciones manuales en navegador | `Navega a: ... → Ctrl+F → Busca: ...` |
| `tipo` | Descrición del tipo de validación | `curl\|grep - Confirma que el patrón existe...` |

---

## Nuevos Campos en "vulnerabilidades"

| Campo | Descripción | Ejemplo |
|-------|-------------|---------|
| `cve` | ID CVE oficial | `CVE-2023-49070` |
| `nombre` | Descripción de vulnerabilidad | `OpenAI API Key Exposure in Log Files` |
| `severidad` | Score CVSS | `7.5` |
| `descripcion` | Descripción completa | `API keys exposed in debug logs...` |
| `ano` | Año descubierto | `2023` |
| `afecta` | Versiones afectadas | `OpenAI API clients <= v0.27` |
| `poc` | Proof of Concept completo | `grep -r 'sk-' logs/` |
| `mitigacion` | Cómo mitigarlo | `Actualizar a >= v0.28...` |
| `referencias` | Links a más información | `["https://nvd.nist.gov/..."]` |
| `fuente` | De dónde vino | `BD local` o `NVD` |
| `tipo` | Descrición tipo | `Explotación - Intenta explotar la vulnerabilidad` |

---

## Ejecución

La herramienta seguirá ejecutándose igual, pero ahora con resultados claramente separados:

**PASO 7 Compilando resultados finales:**
```
[7/7] Compilando resultados finales...
  ├─ OpenAI
  │  ├─ Ocurrencias: 5
  │  ├─ Targets: 2
  │  ├─ Severidad: MEDIUM
  │  ├─ Métodos de REVALIDACIÓN: 3      ← Nuevamente
  │  └─ CVEs/POCs de EXPLOTACIÓN: 2    ← Nuevamente
```

---

## Notas Técnicas

1. **`_workflow`**: Guía clara de qué hacer primero/después
2. **`revalidar`**: Reemplaza a `validar` (más explícito)
3. **`vulnerabilidades[].poc`**: Contiene POC COMPLETO (no limitado)
4. **Fallback**: Si no hay `detalles_validacion`, genera comandos genéricos
5. **Ruta CVE**: `C:\xampp\htdocs\RedScoe\data\nvd\cves_nvd.json`
6. **Importación**: `from tasks.osint.nvd.preprocesar_nvd import CVESearcher`

---

## Próximos Pasos (Opcional)

1. ✅ Copiar `handlers.py` actualizado a `C:\xampp\htdocs\RedScoe\tasks\osint\`
2. ✅ Verificar que `data\nvd\cves_nvd.json` existe con datos
3. ✅ Ejecutar handler y ver nuevo formato JSON
4. (Opcional) Crear UI para mostrar revalidación vs vulnerabilidades de forma visual
