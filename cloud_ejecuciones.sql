-- phpMyAdmin SQL Dump
-- version 5.2.1
-- https://www.phpmyadmin.net/
--
-- Servidor: 127.0.0.1
-- Tiempo de generación: 14-03-2026 a las 18:28:05
-- Versión del servidor: 10.4.32-MariaDB
-- Versión de PHP: 8.2.12

SET SQL_MODE = "NO_AUTO_VALUE_ON_ZERO";
START TRANSACTION;
SET time_zone = "+00:00";


/*!40101 SET @OLD_CHARACTER_SET_CLIENT=@@CHARACTER_SET_CLIENT */;
/*!40101 SET @OLD_CHARACTER_SET_RESULTS=@@CHARACTER_SET_RESULTS */;
/*!40101 SET @OLD_COLLATION_CONNECTION=@@COLLATION_CONNECTION */;
/*!40101 SET NAMES utf8mb4 */;

--
-- Base de datos: `red_scope`
--

-- --------------------------------------------------------

--
-- Estructura de tabla para la tabla `cloud_ejecuciones`
--

CREATE TABLE `cloud_ejecuciones` (
  `id` int(11) NOT NULL,
  `proyecto_id` int(11) NOT NULL,
  `accion_id` int(11) NOT NULL,
  `usuario_id` int(11) NOT NULL,
  `estado` enum('QUEUED','RUNNING','COMPLETED','FAILED') DEFAULT 'QUEUED',
  `nivel_resultado` enum('OK','INFO','WARNING','CRITICAL') DEFAULT NULL,
  `codigo_resultado` varchar(100) DEFAULT NULL,
  `resultado` longtext DEFAULT NULL,
  `error` text DEFAULT NULL,
  `fecha_creacion` datetime DEFAULT current_timestamp(),
  `fecha_fin` datetime DEFAULT NULL,
  `estado_id` int(11) NOT NULL DEFAULT 1
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

--
-- Volcado de datos para la tabla `cloud_ejecuciones`
--

INSERT INTO `cloud_ejecuciones` (`id`, `proyecto_id`, `accion_id`, `usuario_id`, `estado`, `nivel_resultado`, `codigo_resultado`, `resultado`, `error`, `fecha_creacion`, `fecha_fin`, `estado_id`) VALUES
(51, 20, 15, 1, 'COMPLETED', NULL, NULL, '{\n  \"provider\": \"AWS\",\n  \"service\": \"Lambda\",\n  \"account_id\": \"080518909696\",\n  \"region\": \"us-east-1\",\n  \"inventory_type\": \"FUNCTION_CONFIGURATION_DISCOVERY\",\n  \"total_functions_checked\": 0,\n  \"total_resources\": 0,\n  \"resources\": []\n}', NULL, '2026-03-14 13:37:12', '2026-03-14 13:37:14', 1),
(52, 20, 10, 1, 'COMPLETED', NULL, NULL, '{\n  \"provider\": \"AWS\",\n  \"service\": \"APIGateway\",\n  \"account_id\": \"080518909696\",\n  \"region\": \"us-east-1\",\n  \"inventory_type\": \"FULL_CONFIGURATION_ANALYSIS\",\n  \"total_apis_checked\": 0,\n  \"total_resources\": 0,\n  \"resources\": []\n}', NULL, '2026-03-14 13:37:26', '2026-03-14 13:37:29', 1);

--
-- Índices para tablas volcadas
--

--
-- Indices de la tabla `cloud_ejecuciones`
--
ALTER TABLE `cloud_ejecuciones`
  ADD PRIMARY KEY (`id`),
  ADD UNIQUE KEY `uk_proyecto_accion` (`proyecto_id`,`accion_id`),
  ADD KEY `fk_cloud_ejec_accion` (`accion_id`),
  ADD KEY `fk_cloud_ejec_usuario` (`usuario_id`),
  ADD KEY `fk_cloud_ejecuciones_estados` (`estado_id`);

--
-- AUTO_INCREMENT de las tablas volcadas
--

--
-- AUTO_INCREMENT de la tabla `cloud_ejecuciones`
--
ALTER TABLE `cloud_ejecuciones`
  MODIFY `id` int(11) NOT NULL AUTO_INCREMENT, AUTO_INCREMENT=53;

--
-- Restricciones para tablas volcadas
--

--
-- Filtros para la tabla `cloud_ejecuciones`
--
ALTER TABLE `cloud_ejecuciones`
  ADD CONSTRAINT `fk_cloud_ejec_accion` FOREIGN KEY (`accion_id`) REFERENCES `servicios_aws_acciones` (`id`) ON UPDATE CASCADE,
  ADD CONSTRAINT `fk_cloud_ejec_proyecto` FOREIGN KEY (`proyecto_id`) REFERENCES `proyectos` (`id`) ON UPDATE CASCADE,
  ADD CONSTRAINT `fk_cloud_ejec_usuario` FOREIGN KEY (`usuario_id`) REFERENCES `usuarios` (`id`) ON UPDATE CASCADE,
  ADD CONSTRAINT `fk_cloud_ejecuciones_estados` FOREIGN KEY (`estado_id`) REFERENCES `estados` (`id`);
COMMIT;

/*!40101 SET CHARACTER_SET_CLIENT=@OLD_CHARACTER_SET_CLIENT */;
/*!40101 SET CHARACTER_SET_RESULTS=@OLD_CHARACTER_SET_RESULTS */;
/*!40101 SET COLLATION_CONNECTION=@OLD_COLLATION_CONNECTION */;
