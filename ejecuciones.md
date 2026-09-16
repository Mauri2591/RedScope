truncate table cloud_ejecuciones
truncate table findings
truncate table findings_evidence
truncate table security_rules


# ================================ REDSCOPE OPERATIONS ================================

## 🏗️ ARQUITECTURA
# - APP (Flask/Gunicorn) en puerto 5001 → procesa requests HTTP
# - WORKERS (RQ) → procesan jobs en paralelo desde Redis DB1
#   - AWS Worker → queue "aws" (1 worker)
#   - OSINT Workers → queue "osint" (1-8 workers)
#   - IA Worker → queue "ia" (1 worker)

# ================================ WORKERS ================================

## 📊 VER STATUS - AWS
# Comando rápido (resumen):
redscope-aws-status

# Comando detallado (diagnóstico profundo):
redscope_aws_detailed

## 📊 VER STATUS - OSINT
# Comando rápido (resumen):
redscope-osint-status

# Comando detallado (diagnóstico profundo):
redscope_osint_detailed

## 🔄 REINICIAR - AWS CON VERIFICACIÓN (RECOMENDADO)
# Verifica si hay jobs en progreso, pide confirmación
# Úsalo cuando: cambias código de tasks.cloud.aws.*
redscope-reload-aws

## 🔄 REINICIAR - OSINT CON VERIFICACIÓN (RECOMENDADO)
# Verifica si hay jobs en progreso, pide confirmación
# Úsalo cuando: cambias código de tasks.osint.*
redscope-reload-osint

## 🔄 REINICIAR - IA (SIN VERIFICACIÓN)
# Reinicia directo sin verificar (pocas opciones de conflicto)
# Úsalo cuando: cambias código de tasks.ia.*
redscope-reload-ia

# ================================ APP (FLASK) ================================

## 📊 VER LOGS
# Errores de aplicación en vivo:
redscope-logs-app

# Accesos HTTP en vivo:
redscope-logs-access

## 🔄 REINICIAR - APP
# Reinicia Flask/Gunicorn
# Úsalo cuando: cambias routes, config.py, o importas nuevas librerías
redscope-reload-app

# ================================ OPERACIONES GLOBALES ================================

## 🔍 VERIFICAR ANTES DE REINICIAR
# Lista TODOS los jobs que están corriendo en cada queue
# Úsalo para: evitar cancelar jobs sin querer
redscope_check_jobs

## 🔄 REINICIO SEGURO TOTAL (RECOMENDADO)
# Verifica jobs en TODOS los workers, pide confirmación, reinicia TODO
# Úsalo cuando: cambias múltiples componentes (code + config + tasks)
# Proceso: 1) Lista jobs activos, 2) Pide confirmación, 3) Reinicia APP + WORKERS
redscope-safe-restart

## 🔄 REINICIO TOTAL FORZADO (SIN VERIFICACIÓN)
# Reinicia APP + todos los WORKERS al mismo tiempo
# ⚠️ Cancela TODOS los jobs en progreso
# Úsalo cuando: necesitas reset total y sabes qué haces
redscope-reload-all