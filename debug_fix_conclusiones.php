<?php
// Script de debug para verificar y fijar conclusiones dinámicas
// Acceso: http://localhost/RedScoe/debug_fix_conclusiones.php

// Incluir configuración de BD
require_once('config/config.php');

try {
    $mysqli = new mysqli(DB_HOST, DB_USER, DB_PASSWORD, DB_NAME);

    if ($mysqli->connect_error) {
        die("❌ Error de conexión: " . $mysqli->connect_error);
    }

    echo "<h2>🔍 DEBUG: Conclusiones Dinámicas</h2>";
    echo "<pre style='background: #f0f0f0; padding: 10px; border-radius: 5px;'>";

    // 1. Verificar estado actual
    echo "\n1️⃣ ESTADO ACTUAL EN BD:\n";
    echo "=====================================\n";

    $sql = "SELECT id, clave, subtitulo, es_dinamico, tipo FROM reporte_estructura_cloud WHERE clave = 'conclusiones' AND proveedor = 'aws'";
    $result = $mysqli->query($sql);

    if ($result && $result->num_rows > 0) {
        $row = $result->fetch_assoc();
        echo "✅ Conclusiones encontrada:\n";
        echo "  - ID: " . $row['id'] . "\n";
        echo "  - Clave: " . $row['clave'] . "\n";
        echo "  - Tipo: " . $row['tipo'] . "\n";
        echo "  - Es Dinámico: " . ($row['es_dinamico'] == 1 ? '✅ SI (1)' : '❌ NO (0)') . "\n";

        if ($row['es_dinamico'] == 0) {
            echo "\n⚠️ PROBLEMA DETECTADO: es_dinamico = 0\n";
            echo "Aplicando fix...\n\n";

            // 2. Actualizar
            $update_sql = "UPDATE reporte_estructura_cloud SET es_dinamico = 1 WHERE clave = 'conclusiones' AND proveedor = 'aws'";
            if ($mysqli->query($update_sql)) {
                echo "✅ ACTUALIZADO: es_dinamico ahora = 1\n";
            } else {
                echo "❌ Error al actualizar: " . $mysqli->error . "\n";
            }
        }
    } else {
        echo "❌ PROBLEMA: Conclusiones NO encontrada en reporte_estructura_cloud\n";
    }

    // 3. Listar todas las secciones
    echo "\n\n2️⃣ TODAS LAS SECCIONES AWS:\n";
    echo "=====================================\n";

    $sql_all = "SELECT orden, clave, tipo, es_dinamico FROM reporte_estructura_cloud WHERE proveedor = 'aws' ORDER BY orden";
    $result_all = $mysqli->query($sql_all);

    if ($result_all && $result_all->num_rows > 0) {
        echo "Orden | Clave                      | Tipo          | Dinámico\n";
        echo "------+----------------------------+---------------+---------\n";
        while ($row = $result_all->fetch_assoc()) {
            printf("%-5d | %-26s | %-13s | %s\n",
                   $row['orden'],
                   substr($row['clave'], 0, 26),
                   substr($row['tipo'], 0, 13),
                   $row['es_dinamico'] == 1 ? '✅' : '❌');
        }
    }

    // 4. Contar hallazgos
    echo "\n\n3️⃣ PROYECTOS CON HALLAZGOS:\n";
    echo "=====================================\n";

    $sql_projects = "SELECT p.id, p.titulo, COUNT(f.id) as total FROM proyectos p LEFT JOIN findings f ON p.id = f.proyecto_id GROUP BY p.id HAVING COUNT(f.id) > 0 ORDER BY total DESC LIMIT 5";
    $result_projects = $mysqli->query($sql_projects);

    if ($result_projects && $result_projects->num_rows > 0) {
        echo "Proyecto | Título                | Hallazgos\n";
        echo "---------+-----------------------+----------\n";
        while ($row = $result_projects->fetch_assoc()) {
            printf("%-8d | %-21s | %d\n", $row['id'], substr($row['titulo'], 0, 21), $row['total']);
        }
    } else {
        echo "⚠️ No hay proyectos con hallazgos\n";
    }

    echo "\n</pre>";

    $mysqli->close();

} catch (Exception $e) {
    echo "<h2>❌ Error: " . $e->getMessage() . "</h2>";
}
?>
