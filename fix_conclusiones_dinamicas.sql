-- Script para fijar conclusiones como dinámicas en la BD

-- Primero, verificar el estado actual
SELECT 'ANTES:' as status;
SELECT id, clave, subtitulo, es_dinamico, tipo FROM reporte_estructura_cloud WHERE clave = 'conclusiones' AND proveedor = 'aws';

-- Actualizar conclusiones para que sea dinámica
UPDATE reporte_estructura_cloud
SET es_dinamico = 1
WHERE clave = 'conclusiones' AND proveedor = 'aws';

-- Verificar después del cambio
SELECT 'DESPUÉS:' as status;
SELECT id, clave, subtitulo, es_dinamico, tipo FROM reporte_estructura_cloud WHERE clave = 'conclusiones' AND proveedor = 'aws';

-- Ver todas las secciones para AWS
SELECT '\nTODAS LAS SECCIONES AWS:' as status;
SELECT clave, es_dinamico FROM reporte_estructura_cloud WHERE proveedor = 'aws' ORDER BY orden;
