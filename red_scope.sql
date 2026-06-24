-- phpMyAdmin SQL Dump
-- version 5.2.1
-- https://www.phpmyadmin.net/
--
-- Servidor: 127.0.0.1
-- Tiempo de generación: 24-06-2026 a las 21:31:06
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

-- --------------------------------------------------------

--
-- Estructura de tabla para la tabla `cloud_ejecucion_findings`
--

CREATE TABLE `cloud_ejecucion_findings` (
  `id` int(11) NOT NULL,
  `cloud_ejecucion_id` int(11) NOT NULL,
  `resource_id` varchar(255) NOT NULL,
  `check_id` varchar(150) NOT NULL,
  `severity` varchar(20) DEFAULT NULL,
  `created_at` timestamp NOT NULL DEFAULT current_timestamp()
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

-- --------------------------------------------------------

--
-- Estructura de tabla para la tabla `estados`
--

CREATE TABLE `estados` (
  `id` int(11) NOT NULL,
  `nombre` varchar(100) NOT NULL,
  `color` varchar(25) NOT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

--
-- Volcado de datos para la tabla `estados`
--

INSERT INTO `estados` (`id`, `nombre`, `color`) VALUES
(1, 'ACTIVO', '#28a745'),
(2, 'INACTIVO', '#6c757d'),
(3, 'SUSPENDIDO', '#dc3545 '),
(4, 'PENDIENTE', '#ffc107'),
(5, 'EN CURSO', '#007bff'),
(6, 'CHECKEADO', '#6f42c1'),
(7, 'SIN CHECKEAR', '#fd7e14');

-- --------------------------------------------------------

--
-- Estructura de tabla para la tabla `estados_findings`
--

CREATE TABLE `estados_findings` (
  `id` int(11) NOT NULL,
  `nombre` varchar(50) NOT NULL,
  `color` varchar(20) DEFAULT 'info',
  `orden` int(11) DEFAULT 0,
  `estado_id` int(11) DEFAULT 1
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

--
-- Volcado de datos para la tabla `estados_findings`
--

INSERT INTO `estados_findings` (`id`, `nombre`, `color`, `orden`, `estado_id`) VALUES
(1, 'ABIERTO', 'info', 1, 1),
(2, 'ADMITIDO', 'warning', 2, 1),
(3, 'RESUELTO', 'success', 3, 1),
(4, 'FALSO POSITIVO', 'secondary', 4, 1);

-- --------------------------------------------------------

--
-- Estructura de tabla para la tabla `findings`
--

CREATE TABLE `findings` (
  `id` int(11) NOT NULL,
  `proyecto_id` int(11) NOT NULL,
  `usuario_id` int(11) DEFAULT NULL,
  `cloud_ejecucion_id` int(11) NOT NULL,
  `security_rules_id` int(11) DEFAULT NULL,
  `check_id` varchar(255) DEFAULT NULL,
  `provider` varchar(20) NOT NULL,
  `service` varchar(50) NOT NULL,
  `resource_id` varchar(255) NOT NULL,
  `severidad_id` int(11) NOT NULL,
  `estados_findings_id` int(11) DEFAULT NULL,
  `finding_comment` text DEFAULT NULL,
  `verificado` char(2) DEFAULT 'NO',
  `inventory_data` longtext CHARACTER SET utf8mb4 COLLATE utf8mb4_bin DEFAULT NULL,
  `detectado` datetime DEFAULT current_timestamp(),
  `actualizacion` datetime DEFAULT current_timestamp() ON UPDATE current_timestamp(),
  `estado_id` int(11) NOT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

-- --------------------------------------------------------

--
-- Estructura de tabla para la tabla `findings_evidence`
--

CREATE TABLE `findings_evidence` (
  `id` int(11) NOT NULL,
  `finding_id` int(11) NOT NULL,
  `file_path` text DEFAULT NULL,
  `creacion` datetime DEFAULT current_timestamp(),
  `estado_id` int(11) DEFAULT 1
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

-- --------------------------------------------------------

--
-- Estructura de tabla para la tabla `proyectos`
--

CREATE TABLE `proyectos` (
  `id` int(11) NOT NULL,
  `titulo` varchar(255) NOT NULL,
  `cliente` varchar(255) NOT NULL,
  `sector_id` int(11) DEFAULT NULL,
  `usuario_creador_id` int(11) NOT NULL,
  `tipo_proyecto_id` int(11) NOT NULL,
  `tipo_servicio_id` int(11) DEFAULT NULL,
  `autenticado` char(2) DEFAULT NULL,
  `creacion` datetime DEFAULT current_timestamp(),
  `actualizacion` datetime DEFAULT current_timestamp() ON UPDATE current_timestamp(),
  `estado_id` int(11) NOT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

--
-- Volcado de datos para la tabla `proyectos`
--

INSERT INTO `proyectos` (`id`, `titulo`, `cliente`, `sector_id`, `usuario_creador_id`, `tipo_proyecto_id`, `tipo_servicio_id`, `autenticado`, `creacion`, `actualizacion`, `estado_id`) VALUES
(18, 'Prueba EH', 'Telecom', 1, 1, 3, 1, 'SI', '2026-02-18 11:10:57', '2026-02-18 11:10:57', 1),
(20, 'Cloud Security B2B', 'Telecom', 1, 1, 3, 1, 'SI', '2026-02-18 14:40:46', '2026-02-18 14:40:46', 1),
(25, 'Prueba Assume Role', 'Empresa Prueba Assume Role', 1, 1, 3, 1, 'SI', '2026-03-18 18:33:06', '2026-03-18 18:33:06', 1),
(26, 'Cloud Security B2B - Parte 2', 'Telecom', 1, 1, 3, 1, 'SI', '2026-03-31 16:46:33', '2026-03-31 16:46:33', 1),
(27, 'prueba', 'prueba', 1, 1, 3, 1, 'SI', '2026-04-15 16:50:03', '2026-04-15 16:50:03', 1),
(28, 'prrueba 10', 'prueba 10', 1, 1, 3, 1, 'SI', '2026-04-23 12:12:17', '2026-04-23 12:12:17', 1),
(29, 'PRUEBA CLAUDE', 'PRUEBA CLAUDE', 1, 1, 3, 1, 'SI', '2026-05-05 16:45:41', '2026-05-05 16:45:41', 1);

-- --------------------------------------------------------

--
-- Estructura de tabla para la tabla `proyecto_cloud_config`
--

CREATE TABLE `proyecto_cloud_config` (
  `id` int(11) NOT NULL,
  `proyecto_id` int(11) NOT NULL,
  `access_key` varchar(255) DEFAULT NULL,
  `secret_key` text DEFAULT NULL,
  `aws_account_id` varchar(20) NOT NULL,
  `creacion` datetime DEFAULT current_timestamp(),
  `region` varchar(100) NOT NULL,
  `estado_id` int(11) NOT NULL DEFAULT 1,
  `auth_method` enum('role','keys') NOT NULL DEFAULT 'keys',
  `role_arn` varchar(255) DEFAULT NULL,
  `external_id` varchar(255) DEFAULT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

--
-- Volcado de datos para la tabla `proyecto_cloud_config`
--

INSERT INTO `proyecto_cloud_config` (`id`, `proyecto_id`, `access_key`, `secret_key`, `aws_account_id`, `creacion`, `region`, `estado_id`, `auth_method`, `role_arn`, `external_id`) VALUES
(10, 18, 'AKIAYX67PJ3VDX5T4GKM', 'gAAAAABplckUqdnL9JN0qC5aCJS5KTihseGEly3aM2_z0bAhj2b33DHqIBGCfNEUS5PAmrvxd6irSPQiQzjBswrF_5sBtQMlyVIdubpzgB_UhPIbtLFSMh3ikuV3cg3OHv2VCUxfmI6e', '601227218666', '2026-02-18 11:13:40', 'us-east-1', 1, 'keys', NULL, NULL),
(11, 20, 'AKIARFP2NB4ACZHH7WTC', 'gAAAAABplfpdB0W9-MBRENdxkMIi00FBSsGWfMnn_23SuhTN5sOPRK0kmK7eLn1mqlZCSLd5OtCYGF43TOlXu9xQtmOQ0yqy_iaRvIGSzIJTWKeWD8F0RIgpwTvDsZddRkS9c8_PrTTA', '080518909696', '2026-02-18 14:43:57', 'us-east-1', 1, 'keys', NULL, NULL),
(12, 26, 'AKIARFP2NB4ACZHH7WTC', 'gAAAAABpzCVpqriSlIyIpzTNoLHT91NkGg3gq72ZVenMfws9EdyU1Ux_31_vO5Dttsis8Y2CanB5TdyeLd_R0F0cIC3ZlA9QBWmgYNmyMkTwaMcpmgmB-ppqB6G9IUV-jSxg8nqD9U16', '080518909696', '2026-03-31 16:50:01', 'us-east-1', 1, 'keys', NULL, NULL),
(13, 27, 'AKIAYX67PJ3VDX5T4GKM', 'gAAAAABp3_hA81nDfvYZc78rCqHppxU_GXouQDRmzcmR1OEs2oRemsTWsd0Rq3RKhBD18SQ7xCiYG48EL7ZAA2FD-zYF6LjDdlQ7iO4bKKYrC2CvZzDZZM7NPi6Pg7T0ETQ5KJpGiwRD', '601227218666', '2026-04-15 17:42:40', 'us-east-1', 1, 'role', 'arn:aws:iam::601227218666:role/RedScope-PentestRole', 'redscope-lab-2024');

-- --------------------------------------------------------

--
-- Estructura de tabla para la tabla `puertos_comunes`
--

CREATE TABLE `puertos_comunes` (
  `id` int(11) NOT NULL,
  `nombre` varchar(100) NOT NULL,
  `puertos_json` longtext CHARACTER SET utf8mb4 COLLATE utf8mb4_bin NOT NULL CHECK (json_valid(`puertos_json`)),
  `estado_id` int(11) NOT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

--
-- Volcado de datos para la tabla `puertos_comunes`
--

INSERT INTO `puertos_comunes` (`id`, `nombre`, `puertos_json`, `estado_id`) VALUES
(1, 'TOP_100_COMMON_TCP', '{\n  \"20\":\"ftp-data\",\n  \"21\":\"ftp\",\n  \"22\":\"ssh\",\n  \"23\":\"telnet\",\n  \"25\":\"smtp\",\n  \"53\":\"dns\",\n  \"67\":\"dhcp\",\n  \"68\":\"dhcp\",\n  \"69\":\"tftp\",\n  \"80\":\"http\",\n  \"88\":\"kerberos\",\n  \"110\":\"pop3\",\n  \"119\":\"nntp\",\n  \"123\":\"ntp\",\n  \"135\":\"msrpc\",\n  \"137\":\"netbios-ns\",\n  \"138\":\"netbios-dgm\",\n  \"139\":\"netbios-ssn\",\n  \"143\":\"imap\",\n  \"161\":\"snmp\",\n  \"162\":\"snmptrap\",\n  \"179\":\"bgp\",\n  \"389\":\"ldap\",\n  \"443\":\"https\",\n  \"445\":\"smb\",\n  \"465\":\"smtps\",\n  \"500\":\"isakmp\",\n  \"512\":\"exec\",\n  \"513\":\"login\",\n  \"514\":\"shell\",\n  \"515\":\"printer\",\n  \"587\":\"smtp-submission\",\n  \"636\":\"ldaps\",\n  \"989\":\"ftps-data\",\n  \"990\":\"ftps\",\n  \"993\":\"imaps\",\n  \"995\":\"pop3s\",\n  \"1025\":\"nfs\",\n  \"1080\":\"socks\",\n  \"1433\":\"mssql\",\n  \"1434\":\"mssql-monitor\",\n  \"1521\":\"oracle\",\n  \"2049\":\"nfs\",\n  \"2082\":\"cpanel\",\n  \"2083\":\"cpanel-ssl\",\n  \"2086\":\"whm\",\n  \"2087\":\"whm-ssl\",\n  \"2095\":\"webmail\",\n  \"2096\":\"webmail-ssl\",\n  \"2181\":\"zookeeper\",\n  \"2375\":\"docker\",\n  \"2376\":\"docker-tls\",\n  \"2483\":\"oracle-tcps\",\n  \"2484\":\"oracle-ssl\",\n  \"3000\":\"dev-app\",\n  \"3001\":\"dev-app\",\n  \"3306\":\"mysql\",\n  \"3389\":\"rdp\",\n  \"3690\":\"svn\",\n  \"4000\":\"dev-app\",\n  \"4040\":\"spark-ui\",\n  \"4444\":\"metasploit\",\n  \"4567\":\"sinatra\",\n  \"4848\":\"glassfish\",\n  \"5000\":\"flask\",\n  \"5001\":\"dev-app\",\n  \"5432\":\"postgresql\",\n  \"5601\":\"kibana\",\n  \"5672\":\"rabbitmq\",\n  \"5900\":\"vnc\",\n  \"5985\":\"winrm\",\n  \"5986\":\"winrm-ssl\",\n  \"6000\":\"x11\",\n  \"6379\":\"redis\",\n  \"6443\":\"kubernetes-api\",\n  \"6667\":\"irc\",\n  \"7001\":\"weblogic\",\n  \"7002\":\"weblogic-ssl\",\n  \"7077\":\"spark\",\n  \"7199\":\"cassandra\",\n  \"8000\":\"http-alt\",\n  \"8008\":\"http-alt\",\n  \"8080\":\"http-alt\",\n  \"8081\":\"http-alt\",\n  \"8088\":\"hadoop\",\n  \"8161\":\"activemq\",\n  \"8200\":\"vault\",\n  \"8443\":\"https-alt\",\n  \"8500\":\"consul\",\n  \"8888\":\"jupyter\",\n  \"9000\":\"sonarqube\",\n  \"9042\":\"cassandra\",\n  \"9090\":\"prometheus\",\n  \"9092\":\"kafka\",\n  \"9200\":\"elasticsearch\",\n  \"9418\":\"git\",\n  \"10000\":\"webmin\",\n  \"11211\":\"memcached\",\n  \"27017\":\"mongodb\",\n  \"50070\":\"hadoop-namenode\"\n}', 1),
(2, 'VPC_SENSITIVE_INGRESS_PORTS', '{\r\n        \"22\":\"ssh\",\r\n        \"23\":\"telnet\",\r\n        \"135\":\"msrpc\",\r\n        \"139\":\"netbios-ssn\",\r\n        \"445\":\"smb\",\r\n        \"1433\":\"mssql\",\r\n        \"1521\":\"oracle\",\r\n        \"2375\":\"docker\",\r\n        \"2379\":\"etcd\",\r\n        \"3306\":\"mysql\",\r\n        \"3389\":\"rdp\",\r\n        \"5432\":\"postgresql\",\r\n        \"5900\":\"vnc\",\r\n        \"5984\":\"couchdb\",\r\n        \"6379\":\"redis\",\r\n        \"8443\":\"https-alt\",\r\n        \"9200\":\"elasticsearch\",\r\n        \"9300\":\"elasticsearch-cluster\",\r\n        \"11211\":\"memcached\",\r\n        \"27017\":\"mongodb\"\r\n    }', 1);

-- --------------------------------------------------------

--
-- Estructura de tabla para la tabla `reporte_contenido_secciones`
--

CREATE TABLE `reporte_contenido_secciones` (
  `id` int(11) NOT NULL,
  `tipo_servicio` varchar(50) NOT NULL,
  `objetivos` text DEFAULT NULL,
  `alcance` text DEFAULT NULL,
  `conclusiones` text DEFAULT NULL,
  `recomendaciones` text DEFAULT NULL,
  `actividades` text DEFAULT NULL,
  `anexo_metodologia` text DEFAULT NULL,
  `anexo_herramientas` text DEFAULT NULL,
  `anexo_clasificacion` text DEFAULT NULL,
  `estado_id` tinyint(4) DEFAULT 1
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

--
-- Volcado de datos para la tabla `reporte_contenido_secciones`
--

INSERT INTO `reporte_contenido_secciones` (`id`, `tipo_servicio`, `objetivos`, `alcance`, `conclusiones`, `recomendaciones`, `actividades`, `anexo_metodologia`, `anexo_herramientas`, `anexo_clasificacion`, `estado_id`) VALUES
(1, 'aws', 'Evaluar el nivel de seguridad de los servicios y configuraciones cloud de la organización sobre Amazon Web Services (AWS), identificando configuraciones incorrectas, hallazgos y brechas de seguridad que puedan ser aprovechadas por actores maliciosos internos o externos.\n\nLos objetivos específicos del presente trabajo son:\n\n- Identificar configuraciones incorrectas en los principales servicios AWS evaluados (S3, EC2, IAM, Lambda, API Gateway, VPC), determinando el impacto potencial de cada hallazgo sobre la confidencialidad, integridad y disponibilidad de los activos.\n\n- Detectar permisos excesivos o mal configurados en políticas IAM, roles y usuarios, que puedan derivar en escalación de privilegios o acceso no autorizado a recursos críticos.\n\n- Verificar la exposición pública de recursos sensibles como buckets S3, instancias EC2, funciones Lambda, endpoints de API Gateway y configuraciones de red en VPC (Security Groups, subnets, NACLs), evaluando el riesgo asociado a cada superficie de ataque expuesta.\n\n- Comprobar el cumplimiento de buenas prácticas de seguridad según CIS AWS Foundations Benchmark y AWS Well-Architected Framework Security Pillar.\n\n- Proveer recomendaciones técnicas priorizadas por nivel de riesgo que permitan a la organización remediar los hallazgos identificados y fortalecer su postura de seguridad en la nube.', 'El presente trabajo de seguridad ofensiva abarca la evaluación de los servicios y configuraciones cloud del cliente sobre Amazon Web Services (AWS). El análisis se realizó de forma no intrusiva mediante técnicas de revisión de configuración y análisis de permisos, sin afectar la disponibilidad ni la integridad de los servicios productivos.\n\nLos servicios evaluados incluyen:\n\n- Amazon S3: revisión de políticas de bucket, ACLs, configuración de acceso público y cifrado.\n\n- Amazon EC2: análisis de grupos de seguridad, exposición de puertos, configuración de instancias y metadatos.\n\n- AWS IAM: evaluación de usuarios, roles, políticas y permisos, detección de privilegios excesivos y credenciales comprometidas.\n\n- AWS Lambda: revisión de funciones, permisos de ejecución, variables de entorno y exposición de endpoints.\n\n- Amazon API Gateway: análisis de endpoints expuestos, autenticación, autorización y configuración de seguridad.\n\n- Amazon VPC: revisión de Security Groups, exposición de subnets, Network ACLs, Flow Logs y configuración de VPC Peering.\n\n\nEl alcance del presente trabajo se circunscribe exclusivamente a la(s) cuenta(s) de AWS explícitamente autorizadas por el cliente, identificadas mediante su Account ID correspondiente. El acceso a cada cuenta fue habilitado a través de un IAM Role dedicado (Role ARN + External ID) con permisos de solo lectura, evitando cualquier mecanismo de delegación automática a nivel de AWS Organizations que pudiera extender el alcance a cuentas no contempladas en el presente acuerdo.\n\nQuedan fuera del alcance los sistemas on-premise del cliente, aplicaciones de terceros integradas a la plataforma, la evaluación de vulnerabilidades a nivel de sistema operativo o red interna de las instancias, y cualquier servicio AWS no listado explícitamente.', 'Como resultado del trabajo realizado, se identificaron hallazgos de seguridad distribuidos en distintos niveles de criticidad sobre los servicios y configuraciones AWS evaluados. Los hallazgos detectados evidencian patrones comunes en entornos cloud, entre los que se destacan la asignación de permisos excesivos en políticas IAM, la exposición pública de recursos de almacenamiento, la ausencia de controles de cifrado en servicios críticos y la presencia de reglas de red permisivas que amplían innecesariamente la superficie de exposición a Internet.\r\n\r\nLa superficie de ataque identificada representa un riesgo real para la confidencialidad e integridad de los datos gestionados por la organización en la nube. Se recomienda abordar con prioridad los hallazgos clasificados como Críticos y Altos, implementando los controles detallados en la sección de recomendaciones del presente informe.\r\n\r\nLa organización demuestra una base de configuración cloud estructurada, con oportunidades de mejora concretas y alcanzables mediante la aplicación de controles estándar de la industria.', 'En base a los hallazgos identificados durante la evaluación, se recomienda a la organización implementar las siguientes medidas de seguridad de forma prioritaria:\r\n\r\nGestión de Identidades y Accesos (IAM): aplicar el principio de mínimo privilegio en todas las políticas IAM, eliminando permisos wildcard (*) y revisando periódicamente los roles y usuarios activos. Habilitar MFA obligatorio para todos los usuarios con acceso a la consola AWS.\r\n\r\nAlmacenamiento (S3): bloquear el acceso público en todos los buckets que no requieran exposición externa, habilitar el cifrado en reposo con SSE-S3 o SSE-KMS y activar el versionado y logging de accesos en buckets críticos.\r\n\r\nCómputo (EC2): revisar y restringir los grupos de seguridad, eliminando reglas que permitan acceso desde 0.0.0.0/0 a puertos sensibles. Deshabilitar el servicio de metadatos IMDSv1 y migrar a IMDSv2 en todas las instancias.\r\n\r\nRedes (VPC): segmentar adecuadamente las subnets públicas y privadas, deshabilitando la asignación automática de IP pública en subnets que no la requieran. Habilitar VPC Flow Logs en todas las VPCs para garantizar visibilidad sobre el tráfico de red. Revisar las Network ACLs eliminando reglas permisivas de tipo \"allow all\", y restringir las rutas de VPC Peering al CIDR mínimo necesario en lugar de exponer el rango completo. Evaluar el retiro o hardening de la VPC default en cada región.\r\n\r\nFunciones Serverless (Lambda): eliminar variables de entorno con credenciales en texto plano, restringir los permisos de ejecución de cada función al mínimo necesario y auditar los triggers expuestos públicamente.\r\n\r\nAPI Gateway: implementar autenticación en todos los endpoints expuestos, habilitar throttling y WAF para proteger las APIs de abuso y accesos no autorizados.\r\n\r\nMonitoreo y Detección: habilitar AWS CloudTrail en todas las regiones, configurar AWS Config para detectar cambios de configuración y activar Amazon GuardDuty para detección continua de amenazas.', 'Durante el desarrollo del trabajo se llevaron a cabo las siguientes actividades:\n\nRelevamiento inicial: recopilación de información sobre la arquitectura AWS del cliente, servicios utilizados y modelo de responsabilidad compartida aplicable al entorno evaluado.\n\nConfiguración del entorno de análisis: configuración de credenciales de acceso de solo lectura mediante IAM Role con External ID, validación del alcance y verificación de conectividad con los servicios AWS objetivo.\n\nAnálisis automatizado: ejecución de herramientas especializadas de auditoría cloud sobre los servicios en alcance, recopilación de hallazgos y clasificación preliminar por severidad.\n\nAnálisis manual: revisión y validación manual de los hallazgos detectados, eliminación de falsos positivos y profundización en configuraciones de alto riesgo identificadas durante el análisis automatizado.\n\nDocumentación y clasificación: clasificación de hallazgos por severidad (Crítico, Alto, Medio, Bajo, Informativo), documentación técnica de cada hallazgo con descripción, condición lógica, remediación y referencias.\n\nElaboración del informe: redacción del presente informe técnico con los resultados obtenidos, conclusiones y recomendaciones priorizadas para la organización.', 'La evaluación fue realizada siguiendo una metodología estructurada de auditoría de seguridad en entornos cloud, basada en los siguientes marcos de referencia internacionales:\n\nCIS Amazon Web Services Foundations Benchmark: conjunto de controles de seguridad recomendados para entornos AWS, organizado por servicio y nivel de criticidad. Utilizado como referencia principal para la evaluación de configuraciones.\n\nAWS Well-Architected Framework — Security Pillar: pilar de seguridad del marco de buenas prácticas de AWS, que cubre áreas como gestión de identidades, protección de datos, detección de amenazas y respuesta a incidentes.\n\nOWASP Cloud Security: guía de seguridad para entornos cloud que complementa el análisis con perspectivas orientadas a aplicaciones y APIs expuestas.\n\nEl proceso de evaluación se desarrolló en las siguientes fases: reconocimiento y relevamiento, análisis de configuración automatizado, validación manual, clasificación de hallazgos y elaboración del informe. En todo momento se trabajó con credenciales de solo lectura, garantizando la no intrusividad del proceso sobre los entornos productivos del cliente.\n\nEl acceso a la infraestructura del cliente se realizó mediante el modelo de Cross-Account Role con External ID, mecanismo estándar de la industria para auditorías de terceros sobre entornos AWS (utilizado por plataformas como AWS Security Hub, Prowler y soluciones CSPM comerciales). Este modelo garantiza acceso auditable vía AWS CloudTrail, revocable de forma inmediata por el cliente sin necesidad de rotar credenciales compartidas, y mitiga el riesgo de \"confused deputy\" mediante el uso del External ID. El alcance de acceso quedó limitado estrictamente a las cuentas individuales autorizadas, sin visibilidad sobre otras cuentas de la organización del cliente.', 'Para el desarrollo del presente trabajo se utilizaron las siguientes herramientas y tecnologías:\n\nHerramientas Internas: Plataforma desarrollada sobre Boto3 para la ejecución automatizada de checks de seguridad sobre los principales servicios AWS (S3, EC2, IAM, Lambda, API Gateway). Permite el análisis de configuraciones, detección de hallazgos y generación de reportes de forma centralizada.\n\nAWS CLI: interfaz de línea de comandos oficial de Amazon Web Services, utilizada para consultas manuales de configuración y validación de hallazgos directamente sobre los entornos evaluados.\n\nBoto3: SDK oficial de AWS para Python, utilizado como motor de consulta en los módulos de análisis para interactuar programáticamente con los servicios en alcance.\n\nProwler: herramienta open source de auditoría de seguridad AWS utilizada como referencia complementaria para validación de controles CIS AWS Foundations Benchmark y verificación de hallazgos.\n\nScoutSuite: herramienta multi-cloud de auditoría de seguridad utilizada para análisis complementario de la superficie de ataque en el entorno AWS evaluado.\n\nPacu: framework open source de explotación y post-explotación en entornos AWS, utilizado para validación de hallazgos relacionados con escalación de privilegios y configuraciones IAM incorrectas.', 'Los hallazgos identificados durante la evaluación son clasificados según el siguiente esquema de severidad, basado en el impacto potencial sobre la confidencialidad, integridad y disponibilidad de los activos evaluados:\n\nCRÍTICO: Hallazgo o configuración incorrecta que permite acceso no autorizado a datos sensibles, ejecución remota de código o compromiso total del entorno cloud. Requiere remediación inmediata.\n\nALTO: Hallazgo que representa un riesgo significativo para la seguridad del entorno, con potencial de escalación de privilegios, exposición de datos o movimiento lateral. Remediación prioritaria en el corto plazo.\n\nMEDIO: Configuración incorrecta o debilidad que, combinada con otros factores, podría derivar en un incidente de seguridad. Remediación recomendada en el mediano plazo.\n\nBAJO: Hallazgo de impacto reducido que representa una desviación de buenas prácticas o un riesgo marginal en el contexto actual. Remediación recomendada como mejora continua.', 1);

-- --------------------------------------------------------

--
-- Estructura de tabla para la tabla `reporte_estructura_cloud`
--

CREATE TABLE `reporte_estructura_cloud` (
  `id` int(11) NOT NULL,
  `clave` varchar(50) NOT NULL COMMENT 'identificador interno: objetivos, alcance, etc.',
  `subtitulo` varchar(255) NOT NULL COMMENT 'texto visible en TOC: Objetivos, Alcance, etc.',
  `tipo` enum('portada','toc','seccion','anexo') NOT NULL DEFAULT 'seccion',
  `proveedor` enum('aws','azure','gcp','huawei') NOT NULL DEFAULT 'aws',
  `pagina_ref` int(11) DEFAULT NULL COMMENT 'numero de pagina referencial para el TOC',
  `orden` int(11) NOT NULL DEFAULT 0,
  `es_dinamico` tinyint(1) NOT NULL DEFAULT 0 COMMENT '1 = se llena con datos de findings',
  `estado_id` int(11) NOT NULL DEFAULT 1
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

--
-- Volcado de datos para la tabla `reporte_estructura_cloud`
--

INSERT INTO `reporte_estructura_cloud` (`id`, `clave`, `subtitulo`, `tipo`, `proveedor`, `pagina_ref`, `orden`, `es_dinamico`, `estado_id`) VALUES
(1, 'portada', 'Portada', 'portada', 'aws', NULL, 0, 0, 1),
(2, 'tabla_contenidos', 'Tabla de Contenidos', 'toc', 'aws', NULL, 1, 0, 1),
(3, 'objetivos', 'Objetivos', 'seccion', 'aws', 3, 2, 0, 1),
(4, 'alcance', 'Alcance', 'seccion', 'aws', 3, 3, 0, 1),
(5, 'resumen_hallazgos', 'Resumen de Hallazgos', 'seccion', 'aws', 4, 4, 1, 1),
(6, 'hallazgos', 'Hallazgos', 'seccion', 'aws', 6, 5, 1, 1),
(7, 'detalle_hallazgos', 'Detalle de Hallazgos', 'seccion', 'aws', 8, 6, 1, 1),
(8, 'conclusiones', 'Conclusiones', 'seccion', 'aws', 40, 7, 0, 1),
(9, 'recomendaciones', 'Recomendaciones Generales', 'seccion', 'aws', 41, 8, 0, 1),
(10, 'actividades', 'Actividades Realizadas', 'seccion', 'aws', 42, 9, 0, 1),
(11, 'anexo_metodologia', 'Anexo 1: Metodología', 'anexo', 'aws', 43, 10, 0, 1),
(12, 'anexo_herramientas', 'Anexo 2: Herramientas', 'anexo', 'aws', 44, 11, 0, 1),
(13, 'anexo_clasificacion', 'Anexo 3: Clasificación del Riesgo', 'anexo', 'aws', 45, 12, 0, 1);

-- --------------------------------------------------------

--
-- Estructura de tabla para la tabla `reporte_tema`
--

CREATE TABLE `reporte_tema` (
  `id` int(11) NOT NULL,
  `nombre` varchar(50) NOT NULL COMMENT 'ej: navy, cyan, orange',
  `descripcion` varchar(100) DEFAULT NULL COMMENT 'ej: Color principal de encabezados',
  `hex` varchar(7) NOT NULL COMMENT 'ej: #1E1B4B',
  `uso` enum('fondo_primario','fondo_secundario','acento','texto_claro','texto_oscuro','borde','fondo_tabla_header','fondo_tabla_fila_par') NOT NULL,
  `estado_id` int(11) NOT NULL DEFAULT 1
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

--
-- Volcado de datos para la tabla `reporte_tema`
--

INSERT INTO `reporte_tema` (`id`, `nombre`, `descripcion`, `hex`, `uso`, `estado_id`) VALUES
(1, 'navy', 'Fondo principal portada y headers', '#1E1B4B', 'fondo_primario', 1),
(2, 'navy_mid', 'Fondo secundario celdas label', '#2D2A6E', 'fondo_secundario', 1),
(3, 'cyan', 'Acento líneas y destacados', '#00B4D8', 'acento', 1),
(4, 'white', 'Texto sobre fondos oscuros', '#FFFFFF', 'texto_claro', 1),
(5, 'dark', 'Texto sobre fondos claros', '#111827', 'texto_oscuro', 1),
(6, 'gray', 'Texto secundario y bordes', '#CCCCCC', 'borde', 1),
(7, 'navy_header', 'Fondo header de tablas', '#1E1B4B', 'fondo_tabla_header', 1),
(8, 'light', 'Fondo filas pares de tablas', '#E8EAF6', 'fondo_tabla_fila_par', 1);

-- --------------------------------------------------------

--
-- Estructura de tabla para la tabla `roles`
--

CREATE TABLE `roles` (
  `id` int(11) NOT NULL,
  `nombre` varchar(255) NOT NULL,
  `estado_id` int(11) DEFAULT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

--
-- Volcado de datos para la tabla `roles`
--

INSERT INTO `roles` (`id`, `nombre`, `estado_id`) VALUES
(1, 'ROOT', 1),
(2, 'ADMIN', 1),
(3, 'USUARIO', 1);

-- --------------------------------------------------------

--
-- Estructura de tabla para la tabla `sectores`
--

CREATE TABLE `sectores` (
  `id` int(11) NOT NULL,
  `nombre` varchar(100) NOT NULL,
  `estado_id` int(11) NOT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

--
-- Volcado de datos para la tabla `sectores`
--

INSERT INTO `sectores` (`id`, `nombre`, `estado_id`) VALUES
(1, 'ETHICAL-HACKING', 1),
(2, 'SOC', 1),
(3, 'SASE', 1);

-- --------------------------------------------------------

--
-- Estructura de tabla para la tabla `security_rules`
--

CREATE TABLE `security_rules` (
  `id` int(11) NOT NULL,
  `provider` varchar(20) NOT NULL,
  `service` varchar(50) DEFAULT NULL,
  `check_id` varchar(100) DEFAULT NULL,
  `title` varchar(255) NOT NULL,
  `description` text DEFAULT NULL,
  `severidad_id` int(11) NOT NULL,
  `condition_logic` text DEFAULT NULL,
  `remediation` text DEFAULT NULL,
  `reference` text DEFAULT NULL,
  `creacion` datetime DEFAULT current_timestamp(),
  `actualizacion` datetime DEFAULT current_timestamp() ON UPDATE current_timestamp(),
  `display_name` varchar(255) DEFAULT NULL,
  `creado_por_ia` tinyint(1) NOT NULL DEFAULT 0,
  `validado_por` int(11) DEFAULT NULL,
  `estado_id` int(11) DEFAULT 1,
  `validado_at` datetime DEFAULT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

--
-- Volcado de datos para la tabla `security_rules`
--

INSERT INTO `security_rules` (`id`, `provider`, `service`, `check_id`, `title`, `description`, `severidad_id`, `condition_logic`, `remediation`, `reference`, `creacion`, `actualizacion`, `display_name`, `creado_por_ia`, `validado_por`, `estado_id`, `validado_at`) VALUES
(1, 'aws', 'S3', 'logging_enabled', 'S3 Bucket Server Access Logging Disabled', 'El bucket S3 iamcheckers3-593fr9cloketodrzq3vl no tiene habilitado el registro de accesos. Sin logging, no es posible auditar quién accedió al bucket, qué operaciones realizó ni detectar accesos no autorizados.', 3, 'El check falla si la configuración de logging del bucket S3 no tiene definido un bucket destino para los logs de acceso al servidor.', 'Habilitá Server Access Logging en el bucket desde la consola de S3 o vía AWS CLI, especificando un bucket destino dedicado para almacenar los logs de acceso.', 'https://docs.aws.amazon.com/AmazonS3/latest/userguide/ServerLogs.html', '2026-06-24 15:32:26', '2026-06-24 15:32:26', NULL, 1, NULL, 1, NULL),
(2, 'aws', 'S3', 'versioning_enabled', 'S3 Bucket Versioning Disabled', 'El bucket S3 \'redscope-test-public\' no tiene el versionado habilitado. Esto impide recuperar versiones anteriores de objetos ante modificaciones accidentales, sobreescrituras o eliminaciones no autorizadas.', 3, 'El check falla cuando la configuración de versionado del bucket retorna estado \'Disabled\' o ausente, indicando que no se preservan versiones históricas de los objetos almacenados.', 'Habilitá el versionado en el bucket desde la consola de S3 o mediante AWS CLI con \'put-bucket-versioning\'. Considerá también habilitar MFA Delete para mayor protección contra eliminaciones accidentales.', 'https://docs.aws.amazon.com/AmazonS3/latest/userguide/Versioning.html', '2026-06-24 15:32:31', '2026-06-24 15:32:31', NULL, 1, NULL, 1, NULL),
(3, 'aws', 'S3', 'replication_enabled', 'S3 Bucket Replication Not Enabled', 'El bucket S3 no tiene configurada la replicación entre regiones o dentro de la misma región, lo que puede comprometer la disponibilidad y recuperación ante desastres de los datos almacenados.', 3, 'El check falla si el bucket S3 analizado no tiene ninguna regla de replicación activa configurada en su política de replicación.', 'Configurar una regla de replicación en el bucket S3, habilitando CRR o SRR según los requisitos de disponibilidad y cumplimiento, y asegurando que el rol IAM asociado tenga los permisos necesarios.', 'https://docs.aws.amazon.com/AmazonS3/latest/userguide/replication.html', '2026-06-24 15:37:42', '2026-06-24 15:37:42', NULL, 1, NULL, 1, NULL),
(4, 'aws', 'S3', 'public_access', 'S3 Bucket Public Access Enabled', 'El bucket S3 \'redscope-test-public\' tiene habilitado el acceso público. Esto expone potencialmente objetos almacenados a cualquier usuario de internet, lo que puede derivar en fuga de datos sensibles o acceso no autorizado.', 5, 'Se detecta el finding cuando el bucket S3 tiene deshabilitado el bloque de acceso público (Block Public Access) a nivel de bucket o cuenta, permitiendo políticas o ACLs que habiliten acceso anónimo.', 'Habilitá las cuatro opciones de \'Block Public Access\' en la configuración del bucket. Revisá las políticas de bucket y ACLs para eliminar permisos que otorguen acceso a \'*\' o a usuarios no autenticados.', 'https://docs.aws.amazon.com/AmazonS3/latest/userguide/access-control-block-public-access.html', '2026-06-24 15:40:23', '2026-06-24 15:40:23', NULL, 1, NULL, 1, NULL),
(5, 'aws', 'S3', 'wildcard_resource', 'S3 Bucket Policy Allows Wildcard Resource', 'El bucket S3 \'redscope-test-public\' tiene una política que utiliza un comodín (*) en el elemento Resource, lo que puede permitir acceso no intencional a objetos o acciones sobre recursos no previstos.', 4, 'Se detecta cuando una política de bucket S3 contiene el carácter comodín \'*\' en el campo Resource, ampliando el alcance más allá del recurso específico deseado.', 'Reemplazá el comodín \'*\' en Resource por el ARN exacto del bucket y sus objetos. Usá el formato \'arn:aws:s3:::nombre-bucket\' y \'arn:aws:s3:::nombre-bucket/*\' según corresponda.', 'https://docs.aws.amazon.com/AmazonS3/latest/userguide/access-policy-language-overview.html', '2026-06-24 15:40:29', '2026-06-24 15:40:29', NULL, 1, NULL, 1, NULL),
(6, 'aws', 'S3', 'lifecycle_enabled', 'S3 Bucket Lifecycle Policy Not Enabled', 'El bucket S3 del contexto iamcheckers3-593fr9cloketodrzq3vl no tiene configurada una política de ciclo de vida. Esto puede generar acumulación innecesaria de objetos, incrementando costos y la superficie de exposición de datos.', 2, 'El check falla cuando el bucket S3 no posee ninguna regla de ciclo de vida activa configurada en su configuración de LifecycleConfiguration.', 'Configurar al menos una regla de ciclo de vida en el bucket para gestionar la expiración, transición o eliminación automática de objetos según políticas de retención definidas por la organización.', 'https://docs.aws.amazon.com/AmazonS3/latest/userguide/object-lifecycle-mgmt.html', '2026-06-24 15:40:35', '2026-06-24 15:40:35', NULL, 1, NULL, 1, NULL),
(7, 'aws', 'S3', 'block_public_access_disabled', 'S3 Block Public Access Disabled', 'El bucket S3 \'redscope-test-public\' no tiene habilitada la configuración de bloqueo de acceso público, lo que puede exponer objetos y datos sensibles a accesos no autorizados desde internet.', 4, 'Se detecta cuando alguna de las cuatro configuraciones de Block Public Access del bucket S3 está deshabilitada: BlockPublicAcls, IgnorePublicAcls, BlockPublicPolicy o RestrictPublicBuckets.', 'Habilitá las cuatro opciones de Block Public Access en el bucket S3 desde la consola AWS o mediante CLI. Revisá políticas y ACLs existentes para evitar exposición pública de objetos no intencionada.', 'https://docs.aws.amazon.com/AmazonS3/latest/userguide/access-control-block-public-access.html', '2026-06-24 15:40:41', '2026-06-24 15:40:41', NULL, 1, NULL, 1, NULL),
(8, 'aws', 'S3', 'public_via_policy', 'S3 Bucket Publicly Accessible via Bucket Policy', 'El bucket S3 \'redscope-test-public\' tiene una política que permite acceso público. Esto expone objetos almacenados a cualquier usuario de internet, representando un riesgo significativo de fuga de datos sensibles.', 4, 'Se detecta cuando la política del bucket contiene declaraciones con Principal \'*\' o \'AWS: *\' y Effect \'Allow\', sin condiciones restrictivas que limiten el acceso.', 'Revisá y restringí la política del bucket eliminando permisos con Principal \'*\'. Habilitá S3 Block Public Access a nivel de bucket y cuenta para prevenir exposiciones accidentales.', 'https://docs.aws.amazon.com/AmazonS3/latest/userguide/access-control-block-public-access.html', '2026-06-24 15:40:47', '2026-06-24 15:40:47', NULL, 1, NULL, 1, NULL),
(9, 'aws', 'S3', 'is_effectively_public', 'S3 Bucket Publicly Accessible', 'El bucket S3 \'redscope-test-public\' es accesible públicamente. Esto expone los objetos almacenados a cualquier usuario de internet, pudiendo provocar fuga de datos sensibles o acceso no autorizado a recursos críticos.', 5, 'Se verifica si el bucket tiene deshabilitado el bloqueo de acceso público (Block Public Access) o posee políticas de bucket o ACLs que otorguen permisos a \'*\' o \'AllUsers\'.', 'Activar las cuatro opciones de S3 Block Public Access en el bucket. Revisar y corregir políticas de bucket y ACLs para eliminar permisos otorgados a entidades públicas o anónimas.', 'https://docs.aws.amazon.com/AmazonS3/latest/userguide/access-control-block-public-access.html', '2026-06-24 15:40:53', '2026-06-24 15:40:53', NULL, 1, NULL, 1, NULL);

-- --------------------------------------------------------

--
-- Estructura de tabla para la tabla `servicios_aws`
--

CREATE TABLE `servicios_aws` (
  `id` int(11) NOT NULL,
  `nombre` varchar(255) NOT NULL,
  `descripcion` varchar(2500) DEFAULT NULL,
  `tipos_servicio_id` int(11) DEFAULT NULL,
  `creacion` datetime DEFAULT current_timestamp(),
  `actualizacion` datetime DEFAULT NULL,
  `estado_id` int(11) DEFAULT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

--
-- Volcado de datos para la tabla `servicios_aws`
--

INSERT INTO `servicios_aws` (`id`, `nombre`, `descripcion`, `tipos_servicio_id`, `creacion`, `actualizacion`, `estado_id`) VALUES
(1, 'S3', 'Auditoría de configuraciones y permisos en buckets S3. Identifica exposición pública, ACL incorrectas y filtración de datos sensibles.', 1, '2026-02-16 23:36:49', NULL, 1),
(2, 'EC2', 'Análisis de instancias y Security Groups en entornos cloud. Detecta puertos expuestos, accesos inseguros y riesgos en metadata service.', 1, '2026-02-16 23:36:49', NULL, 1),
(3, 'IAM', 'Evaluación de políticas, roles y privilegios en la cuenta AWS. Identifica permisos excesivos y posibles escenarios de escalamiento de privilegios.', 1, '2026-02-16 23:36:49', NULL, 1),
(4, 'API Gateway', 'Servicio de exposición y gestión de APIs en AWS.\nPermite auditar endpoints públicos, métodos habilitados, autenticación y configuraciones CORS inseguras.', 1, '2026-02-16 23:36:49', NULL, 1),
(5, 'AWS Lambda', 'Servicio de ejecución serverless que corre código bajo demanda.\nPermite evaluar permisos IAM asociados, exposición de secretos en variables de entorno y riesgos de ejecución no autorizada.Identifica accesibilidad pública, configuraciones débiles y falta de cifrado.', 1, '2026-02-16 23:36:49', NULL, 1),
(6, 'Amazon Inspector', 'Importa y gestiona hallazgos de vulnerabilidades CVE detectados por Amazon Inspector en recursos EC2, Lambda y contenedores.', 1, '2026-05-05 18:22:47', NULL, 1),
(7, 'VPC', 'VPC (Virtual Private Cloud): Audita la configuración de red virtual de AWS (subnets, security groups, rutas) detectando exposición a Internet, reglas de firewall permisivas y falta de segmentación.\nVulnerabilidades conocidas: Security Groups abiertos a 0.0.0.0/0, subnets públicas con recursos sensibles, ausencia de Flow Logs y VPC Peering sin restricción de rutas.', 1, '2026-05-05 18:22:47', NULL, 1),
(8, 'RDS', 'Auditoría de configuraciones y permisos en instancias Amazon RDS, identificando exposición pública, falta de cifrado y debilidades en backups y autenticación.', 1, '2026-06-16 17:01:26', NULL, 1),
(9, 'CloudTrail', 'Auditoría de configuración y estado del servicio de trazabilidad de eventos en AWS.', 1, '2026-06-24 15:46:23', NULL, 1),
(10, 'KMS', 'Auditoría de configuración y estado de claves de cifrado en AWS Key Management Service.', 1, '2026-06-24 16:01:01', NULL, 1),
(11, 'Secrets Manager', 'Auditoría de configuración y estado de secretos en AWS Secrets Manager.', 1, '2026-06-24 16:08:30', NULL, 1);

-- --------------------------------------------------------

--
-- Estructura de tabla para la tabla `servicios_aws_acciones`
--

CREATE TABLE `servicios_aws_acciones` (
  `id` int(11) NOT NULL,
  `servicios_aws_id` int(11) NOT NULL,
  `accion_key` varchar(100) NOT NULL,
  `nombre_ui` varchar(100) NOT NULL,
  `descripcion` text DEFAULT NULL,
  `handler` varchar(150) NOT NULL,
  `requiere_parametros` tinyint(1) DEFAULT 0,
  `orden` int(11) DEFAULT 1,
  `creacion` datetime DEFAULT current_timestamp(),
  `actualizacion` datetime DEFAULT current_timestamp() ON UPDATE current_timestamp(),
  `estado_id` int(11) DEFAULT 1
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

--
-- Volcado de datos para la tabla `servicios_aws_acciones`
--

INSERT INTO `servicios_aws_acciones` (`id`, `servicios_aws_id`, `accion_key`, `nombre_ui`, `descripcion`, `handler`, `requiere_parametros`, `orden`, `creacion`, `actualizacion`, `estado_id`) VALUES
(1, 3, 'iam.discovery.roles', 'Discovery Roles', 'Lista todos los roles IAM', 'cloud.aws.discovery_roles_job', 0, 1, '2026-02-17 16:56:00', '2026-02-18 20:25:51', 1),
(2, 3, 'iam.discovery.policies', 'Discovery Policies', 'Policies IAM activas (con attachments)', 'cloud.aws.discovery_policies_job', 0, 2, '2026-02-17 16:56:00', '2026-02-20 19:52:17', 1),
(3, 3, 'iam.password_policy', 'Password Policy', 'Obtiene política de password IAM', 'cloud.aws.password_policy_job', 0, 3, '2026-02-17 16:56:00', '2026-02-18 17:01:05', 1),
(4, 1, 's3.discovery.public_exposure', 'S3 Public Exposure', 'Detecta buckets S3 expuestos públicamente debido a configuraciones inseguras en listas de control de acceso (ACL) o políticas de bucket permisivas.', 'cloud.aws.s3_public_exposure_job', 0, 1, '2026-02-18 16:55:04', '2026-02-18 20:30:36', 1),
(5, 1, 's3.discovery.encryption_logging', 'S3 Encryption & Logging', 'Evalúa si los buckets S3 cuentan con cifrado habilitado, versionado activo y registro de accesos (logging) configurado correctamente.', 'cloud.aws.s3_encryption_logging_job', 0, 2, '2026-02-18 16:55:04', '2026-02-18 20:32:10', 1),
(6, 1, 's3.discovery.iam_access_review', 'S3 IAM Access Review', 'Analiza accesos excesivos y permisos IAM sobre buckets S3', 'cloud.aws.s3_iam_access_review_job', 0, 3, '2026-02-18 16:55:04', '2026-02-18 17:01:14', 1),
(7, 2, 'ec2.discovery.security_groups', 'EC2 Security Groups Exposure', 'Detecta reglas inseguras en Security Groups, incluyendo puertos expuestos a 0.0.0.0/0.', 'cloud.aws.ec2_security_groups_job', 0, 1, '2026-02-18 20:38:46', '2026-02-18 20:38:46', 1),
(8, 2, 'ec2.discovery.public_instances', 'EC2 Public Instances', 'Identifica instancias EC2 con IP pública asociada y exposición potencial a internet.', 'cloud.aws.ec2_public_instances_job', 0, 2, '2026-02-18 20:38:46', '2026-02-18 20:38:46', 1),
(9, 2, 'ec2.discovery.iam_roles', 'EC2 IAM Role Review', 'Revisa instancias EC2 con IAM Roles adjuntos para detectar privilegios excesivos.', 'cloud.aws.ec2_iam_role_review_job', 0, 3, '2026-02-18 20:38:46', '2026-02-18 20:38:46', 1),
(10, 4, 'apigateway.discovery.apis', 'Discovery APIs', 'Lista todas las APIs REST y HTTP expuestas en API Gateway', 'cloud.aws.apigateway_public_exposure_job', 0, 1, '2026-02-19 09:39:39', '2026-02-19 10:03:41', 1),
(11, 4, 'apigateway.discovery.stages', 'Discovery Stages', 'Lista stages configurados (dev, prod, test) y sus configuraciones', 'cloud.aws.apigateway_discovery_stages_job', 0, 2, '2026-02-19 09:39:47', '2026-02-19 09:39:47', 1),
(12, 4, 'apigateway.review.authorizers', 'Review Authorizers', 'Analiza configuraciones de autenticación y authorizers (JWT, Cognito, Lambda)', 'cloud.aws.apigateway_review_authorizers_job', 0, 3, '2026-02-19 09:39:55', '2026-02-19 09:39:55', 1),
(13, 4, 'apigateway.security.exposure', 'Security Exposure Review', 'Detecta APIs públicas, CORS abiertos y configuraciones inseguras', 'cloud.aws.apigateway_security_exposure_job', 0, 4, '2026-02-19 09:40:01', '2026-02-19 09:40:01', 1),
(14, 4, 'apigateway.review.logging', 'Logging Review', 'Verifica si CloudWatch logging y execution logs están habilitados', 'cloud.aws.apigateway_logging_review_job', 0, 5, '2026-02-19 09:40:07', '2026-02-19 09:40:07', 1),
(15, 5, 'lambda.discovery.functions', 'Discovery Functions', 'Lista todas las funciones Lambda configuradas en la cuenta', 'cloud.aws.discovery_functions_job', 0, 1, '2026-02-19 12:27:30', '2026-02-19 12:35:26', 1),
(16, 5, 'lambda.discovery.permissions', 'Discovery Permissions', 'Enumera las políticas de recurso asociadas a funciones Lambda', 'cloud.aws.discovery_permissions_job', 0, 2, '2026-02-19 12:27:30', '2026-02-19 12:37:14', 1),
(17, 5, 'lambda.discovery.triggers', 'Discovery Triggers', 'Lista los triggers configurados (API Gateway, S3, EventBridge, etc)', 'cloud.aws.discovery_triggers_job', 0, 3, '2026-02-19 12:27:30', '2026-02-19 12:38:55', 1),
(18, 5, 'lambda.security.public_exposure', 'Public Exposure Check', 'Detecta funciones Lambda expuestas públicamente', 'cloud.aws.public_exposure_review_job', 0, 10, '2026-02-19 12:27:30', '2026-02-19 12:44:11', 1),
(19, 5, 'lambda.security.overprivileged_role', 'Overprivileged Role Check', 'Detecta roles IAM con permisos excesivos asociados a Lambda', 'cloud.aws.overprivileged_role_review_job', 0, 11, '2026-02-19 12:27:30', '2026-02-19 12:45:37', 1),
(20, 5, 'lambda.security.wildcard_permissions', 'Wildcard Permissions Check', 'Detecta uso de * en políticas IAM asociadas a Lambda', 'cloud.aws.wildcard_permissions_review_job', 0, 12, '2026-02-19 12:27:30', '2026-02-19 12:50:42', 1),
(21, 5, 'lambda.security.no_vpc', 'VPC Not Configured', 'Detecta funciones Lambda que no están asociadas a una VPC', 'cloud.aws.no_vpc_review_job', 0, 13, '2026-02-19 12:27:30', '2026-02-19 12:54:07', 1),
(22, 5, 'lambda.security.old_runtime', 'Outdated Runtime Check', 'Detecta funciones usando runtimes obsoletos (versiones de lenguajes ya no soportadas por AWS)', 'cloud.aws.old_runtime_review_job', 0, 14, '2026-02-19 12:27:30', '2026-02-21 00:14:30', 1),
(23, 5, 'lambda.security.env_secrets', 'Environment Secrets Exposure', 'Detecta uso inseguro de secrets en variables de entorno', 'cloud.aws.env_secrets_review_job', 0, 15, '2026-02-19 12:27:30', '2026-02-19 12:58:31', 1),
(24, 5, 'lambda.security.logging_disabled', 'Logging Disabled Check', 'Verifica si la función Lambda no tiene logging activo en CloudWatch', 'cloud.aws.logging_review_job', 0, 16, '2026-02-19 12:27:30', '2026-02-19 13:00:15', 1),
(25, 1, 's3.replication.review', 'S3 Replication Review', 'Verifica si los buckets S3 tienen configurada replicación cross-region', 'cloud.aws.s3_replication_review_job', 0, 4, '2026-04-15 18:27:40', '2026-04-15 18:27:40', 1),
(26, 1, 's3.lifecycle.review', 'S3 Lifecycle Policy Review', 'Verifica si los buckets S3 tienen políticas de ciclo de vida configuradas', 'cloud.aws.s3_lifecycle_review_job', 0, 5, '2026-04-15 18:27:40', '2026-04-15 18:27:40', 1),
(27, 3, 'iam.users.review', 'IAM Users Review', 'Detecta usuarios IAM sin MFA, con acceso a consola sin restricciones o con access keys antiguas', 'cloud.aws.iam_users_review_job', 0, 4, '2026-04-15 18:47:28', '2026-04-15 18:47:28', 1),
(28, 3, 'iam.privilege.escalation', 'IAM Privilege Escalation Review', 'Detecta roles y usuarios con permisos que permiten escalar privilegios en la cuenta AWS', 'cloud.aws.iam_privilege_escalation_job', 0, 5, '2026-04-15 18:47:28', '2026-04-15 18:47:28', 1),
(29, 6, 'inspector.status.check', 'Inspector Status Check', 'Verifica si Amazon Inspector está habilitado en la cuenta y qué tipos de escaneo están activos', 'cloud.aws.inspector_status_job', 0, 1, '2026-05-05 20:01:52', '2026-05-05 20:01:52', 1),
(30, 6, 'inspector.findings.ec2', 'EC2 CVE Findings', 'Importa vulnerabilidades CVE detectadas por Amazon Inspector en instancias EC2', 'cloud.aws.inspector_ec2_findings_job', 0, 2, '2026-05-05 20:01:52', '2026-05-05 20:01:52', 1),
(31, 6, 'inspector.findings.lambda', 'Lambda CVE Findings', 'Importa vulnerabilidades CVE detectadas por Amazon Inspector en funciones Lambda', 'cloud.aws.inspector_lambda_findings_job', 0, 3, '2026-05-05 20:01:52', '2026-05-05 20:01:52', 1),
(32, 6, 'inspector.findings.ecr', 'ECR Image CVE Findings', 'Importa vulnerabilidades CVE detectadas por Amazon Inspector en imágenes de contenedores ECR', 'cloud.aws.inspector_ecr_findings_job', 0, 4, '2026-05-05 20:01:52', '2026-05-05 20:01:52', 1),
(33, 6, 'inspector.findings.critical', 'Critical Findings Review', 'Filtra y lista únicamente los hallazgos CRITICAL detectados por Amazon Inspector en todos los recursos', 'cloud.aws.inspector_critical_findings_job', 0, 5, '2026-05-05 20:02:37', '2026-05-05 20:02:37', 1),
(34, 6, 'inspector.findings.high', 'High Findings Review', 'Filtra y lista únicamente los hallazgos HIGH detectados por Amazon Inspector en todos los recursos', 'cloud.aws.inspector_high_findings_job', 0, 6, '2026-05-05 20:02:37', '2026-05-05 20:02:37', 1),
(35, 6, 'inspector.coverage.review', 'Coverage Review', 'Verifica qué recursos están siendo monitoreados por Inspector y cuáles quedaron fuera de cobertura', 'cloud.aws.inspector_coverage_job', 0, 7, '2026-05-05 20:02:37', '2026-05-05 20:02:37', 1),
(36, 6, 'inspector.findings.suppressed', 'Suppressed Findings Review', 'Lista hallazgos suprimidos o ignorados en Inspector para validar si la supresión es justificada', 'cloud.aws.inspector_suppressed_findings_job', 0, 8, '2026-05-05 20:02:37', '2026-05-05 20:02:37', 1),
(37, 6, 'inspector.sbom.export', 'SBOM Export Review', 'Exporta y analiza el Software Bill of Materials generado por Inspector para los recursos escaneados', 'cloud.aws.inspector_sbom_job', 0, 9, '2026-05-05 20:02:37', '2026-05-05 20:02:37', 1),
(38, 6, 'inspector.findings.summary', 'Findings Summary', 'Genera un resumen ejecutivo de todos los hallazgos agrupados por severidad, servicio y recurso', 'cloud.aws.inspector_summary_job', 0, 10, '2026-05-05 20:02:37', '2026-05-05 20:02:37', 1),
(39, 7, 'vpc.discovery.vpcs', 'Discovery VPCs', 'Lista todas las VPCs de la cuenta, incluyendo la VPC default', 'cloud.aws.vpc_discovery_job', 0, 1, '2026-06-16 10:36:45', '2026-06-16 10:36:45', 1),
(40, 7, 'vpc.discovery.subnets', 'Discovery Subnets', 'Lista subnets y verifica asignación automática de IP pública', 'cloud.aws.vpc_subnets_job', 0, 2, '2026-06-16 10:36:45', '2026-06-16 10:36:45', 1),
(41, 7, 'vpc.discovery.security_groups', 'Discovery Security Groups', 'Lista Security Groups y analiza reglas de ingreso/egreso', 'cloud.aws.vpc_security_groups_job', 0, 3, '2026-06-16 10:36:45', '2026-06-16 10:36:45', 1),
(42, 7, 'vpc.discovery.network_acls', 'Discovery Network ACLs', 'Lista Network ACLs y detecta reglas permisivas (ALLOW ALL)', 'cloud.aws.vpc_network_acls_job', 0, 4, '2026-06-16 10:36:45', '2026-06-16 10:36:45', 1),
(43, 7, 'vpc.discovery.flow_logs', 'Discovery Flow Logs', 'Verifica el estado de VPC Flow Logs por cada VPC', 'cloud.aws.vpc_flow_logs_job', 0, 5, '2026-06-16 10:36:45', '2026-06-16 10:36:45', 1),
(44, 7, 'vpc.discovery.route_tables', 'Discovery Route Tables', 'Lista tablas de rutas y rutas asociadas a peering connections', 'cloud.aws.vpc_route_tables_job', 0, 6, '2026-06-16 10:36:45', '2026-06-16 10:36:45', 1),
(45, 7, 'vpc.discovery.peering_connections', 'Discovery Peering Connections', 'Lista VPC Peering Connections y valida exposición de CIDR en rutas', 'cloud.aws.vpc_peering_job', 0, 7, '2026-06-16 10:36:45', '2026-06-16 10:36:45', 1),
(46, 8, 'rds.discovery.instances', 'Discovery DB Instances', 'Lista todas las instancias RDS de la cuenta con su configuración general', 'cloud.aws.rds_instances_job', 0, 1, '2026-06-16 17:04:54', '2026-06-16 17:04:54', 1),
(47, 8, 'rds.discovery.public_access', 'Public Accessibility Review', 'Verifica si las instancias RDS son públicamente accesibles', 'cloud.aws.rds_public_access_job', 0, 2, '2026-06-16 17:04:54', '2026-06-16 17:04:54', 1),
(48, 8, 'rds.discovery.encryption', 'Storage Encryption Review', 'Verifica si el almacenamiento de las instancias RDS tiene cifrado en reposo habilitado', 'cloud.aws.rds_encryption_job', 0, 3, '2026-06-16 17:04:54', '2026-06-16 17:04:54', 1),
(49, 8, 'rds.discovery.snapshots', 'Snapshot Exposure Review', 'Lista snapshots de RDS y detecta los configurados como públicos', 'cloud.aws.rds_snapshots_job', 0, 4, '2026-06-16 17:04:54', '2026-06-16 17:04:54', 1),
(50, 8, 'rds.discovery.backups', 'Backup Configuration Review', 'Verifica el período de retención de backups automáticos en cada instancia', 'cloud.aws.rds_backups_job', 0, 5, '2026-06-16 17:04:54', '2026-06-16 17:04:54', 1),
(51, 8, 'rds.discovery.iam_auth', 'IAM Authentication Review', 'Verifica si la autenticación vía IAM está habilitada en cada instancia', 'cloud.aws.rds_iam_auth_job', 0, 6, '2026-06-16 17:04:54', '2026-06-16 17:04:54', 1),
(52, 8, 'rds.discovery.maintenance', 'Maintenance & Protection Review', 'Verifica auto minor version upgrade y deletion protection en cada instancia', 'cloud.aws.rds_maintenance_job', 0, 7, '2026-06-16 17:04:54', '2026-06-16 17:04:54', 1),
(53, 9, 'cloudtrail.check.enabled', 'CloudTrail Enabled', 'Verifica que CloudTrail esté habilitado en todas las regiones', 'cloud.aws.cloudtrail_enabled_job', 0, 1, '2026-06-24 15:47:58', '2026-06-24 15:47:58', 1),
(54, 9, 'cloudtrail.check.log_validation', 'Log File Validation', 'Verifica que la validación de integridad de logs esté activada', 'cloud.aws.cloudtrail_log_validation_job', 0, 2, '2026-06-24 15:47:58', '2026-06-24 15:47:58', 1),
(55, 9, 'cloudtrail.check.s3_bucket_public', 'S3 Bucket Public Access', 'Verifica que el bucket de logs de CloudTrail no sea público', 'cloud.aws.cloudtrail_s3_bucket_public_job', 0, 3, '2026-06-24 15:47:58', '2026-06-24 15:47:58', 1),
(56, 9, 'cloudtrail.check.s3_access_logging', 'S3 Access Logging', 'Verifica que el logging de acceso al bucket de logs esté habilitado', 'cloud.aws.cloudtrail_s3_access_logging_job', 0, 4, '2026-06-24 15:47:58', '2026-06-24 15:47:58', 1),
(57, 9, 'cloudtrail.check.cloudwatch_integration', 'CloudWatch Logs Integration', 'Verifica que CloudTrail esté integrado con CloudWatch Logs', 'cloud.aws.cloudtrail_cloudwatch_integration_job', 0, 5, '2026-06-24 15:47:58', '2026-06-24 15:47:58', 1),
(58, 9, 'cloudtrail.check.kms_encryption', 'KMS Encryption', 'Verifica que los logs de CloudTrail estén cifrados con KMS', 'cloud.aws.cloudtrail_kms_encryption_job', 0, 6, '2026-06-24 15:47:58', '2026-06-24 15:47:58', 1),
(59, 10, 'kms.check.key_rotation', 'Key Rotation Enabled', 'Verifica que la rotación automática de claves esté habilitada', 'cloud.aws.kms_key_rotation_job', 0, 1, '2026-06-24 16:01:37', '2026-06-24 16:01:37', 1),
(60, 10, 'kms.check.key_exposed', 'Key Policy Public Access', 'Verifica que la política de clave no permita acceso público o cross-account', 'cloud.aws.kms_key_exposed_job', 0, 2, '2026-06-24 16:01:37', '2026-06-24 16:01:37', 1),
(61, 10, 'kms.check.key_unused', 'Unused Keys Review', 'Verifica claves sin uso en los últimos 90 días', 'cloud.aws.kms_key_unused_job', 0, 3, '2026-06-24 16:01:37', '2026-06-24 16:01:37', 1),
(62, 10, 'kms.check.key_pending_deletion', 'Keys Pending Deletion', 'Verifica claves programadas para eliminación', 'cloud.aws.kms_key_pending_deletion_job', 0, 4, '2026-06-24 16:01:37', '2026-06-24 16:01:37', 1),
(63, 10, 'kms.check.key_disabled', 'Disabled Keys Review', 'Verifica claves deshabilitadas que siguen siendo referenciadas', 'cloud.aws.kms_key_disabled_job', 0, 5, '2026-06-24 16:01:37', '2026-06-24 16:01:37', 1),
(64, 10, 'kms.check.key_no_policy', 'Key Default Policy Review', 'Verifica claves que usan únicamente la política por defecto sin customización', 'cloud.aws.kms_key_no_policy_job', 0, 6, '2026-06-24 16:01:37', '2026-06-24 16:01:37', 1),
(65, 10, 'kms.check.key_grants_review', 'Key Grants Review', 'Verifica grants activos con permisos amplios o a principals externos', 'cloud.aws.kms_key_grants_review_job', 0, 7, '2026-06-24 16:01:37', '2026-06-24 16:01:37', 1),
(66, 11, 'secretsmanager.check.rotation_disabled', 'Secret Rotation Disabled', 'Verifica que la rotación automática de secretos esté habilitada', 'cloud.aws.secretsmanager_rotation_disabled_job', 0, 1, '2026-06-24 16:09:03', '2026-06-24 16:09:03', 1),
(67, 11, 'secretsmanager.check.unused_secret', 'Unused Secrets Review', 'Verifica secretos no accedidos en los últimos 90 días', 'cloud.aws.secretsmanager_unused_secret_job', 0, 2, '2026-06-24 16:09:03', '2026-06-24 16:09:03', 1),
(68, 11, 'secretsmanager.check.exposed_secret', 'Secret Policy Public Access', 'Verifica que la política de recurso no permita acceso público o cross-account', 'cloud.aws.secretsmanager_exposed_secret_job', 0, 3, '2026-06-24 16:09:03', '2026-06-24 16:09:03', 1),
(69, 11, 'secretsmanager.check.no_kms', 'Secret KMS Encryption Review', 'Verifica que el secret esté cifrado con clave KMS CUSTOMER y no con la clave por defecto', 'cloud.aws.secretsmanager_no_kms_job', 0, 4, '2026-06-24 16:09:03', '2026-06-24 16:09:03', 1),
(70, 11, 'secretsmanager.check.old_secret', 'Old Secrets Review', 'Verifica secretos sin rotación hace más de 90 días', 'cloud.aws.secretsmanager_old_secret_job', 0, 5, '2026-06-24 16:09:03', '2026-06-24 16:09:03', 1),
(71, 11, 'secretsmanager.check.missing_tags', 'Missing Tags Review', 'Verifica secretos sin tags definidos', 'cloud.aws.secretsmanager_missing_tags_job', 0, 6, '2026-06-24 16:09:03', '2026-06-24 16:09:03', 1),
(72, 11, 'secretsmanager.check.cross_account_access', 'Cross Account Access Review', 'Verifica políticas con acceso a cuentas externas', 'cloud.aws.secretsmanager_cross_account_access_job', 0, 7, '2026-06-24 16:09:03', '2026-06-24 16:09:03', 1);

-- --------------------------------------------------------

--
-- Estructura de tabla para la tabla `severidades`
--

CREATE TABLE `severidades` (
  `id` int(11) NOT NULL,
  `nombre` varchar(20) NOT NULL,
  `score` int(11) DEFAULT NULL,
  `color` varchar(20) DEFAULT NULL,
  `orden` int(11) DEFAULT NULL,
  `estado_id` int(11) DEFAULT 1
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

--
-- Volcado de datos para la tabla `severidades`
--

INSERT INTO `severidades` (`id`, `nombre`, `score`, `color`, `orden`, `estado_id`) VALUES
(1, 'INFORMATIVO', 0, '#808080', 1, 2),
(2, 'BAJO', 2, '#00B050', 2, 1),
(3, 'MEDIO', 5, '#FFA500', 3, 1),
(4, 'ALTO', 8, '#FF0000', 4, 1),
(5, 'CRITICO', 10, '#800080', 5, 1);

-- --------------------------------------------------------

--
-- Estructura de tabla para la tabla `tenants`
--

CREATE TABLE `tenants` (
  `id` int(11) NOT NULL,
  `nombre` varchar(255) NOT NULL,
  `estado_id` int(11) DEFAULT NULL,
  `creacion` datetime DEFAULT current_timestamp(),
  `actualizacion` datetime DEFAULT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

-- --------------------------------------------------------

--
-- Estructura de tabla para la tabla `tipos_servicio`
--

CREATE TABLE `tipos_servicio` (
  `id` int(11) NOT NULL,
  `nombre` varchar(255) NOT NULL,
  `creacion` datetime DEFAULT current_timestamp(),
  `actualizacion` datetime DEFAULT NULL,
  `estado_id` int(11) DEFAULT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

--
-- Volcado de datos para la tabla `tipos_servicio`
--

INSERT INTO `tipos_servicio` (`id`, `nombre`, `creacion`, `actualizacion`, `estado_id`) VALUES
(1, 'AWS', '2026-02-15 11:45:58', NULL, 1),
(2, 'AZURE', '2026-02-15 11:45:58', NULL, 1),
(3, 'GCP', '2026-02-15 11:45:58', NULL, 1),
(5, 'HUAWEI', '2026-02-15 11:45:58', NULL, 1);

-- --------------------------------------------------------

--
-- Estructura de tabla para la tabla `tipo_proyecto`
--

CREATE TABLE `tipo_proyecto` (
  `id` int(11) NOT NULL,
  `nombre` varchar(255) NOT NULL,
  `estado_id` int(11) DEFAULT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

--
-- Volcado de datos para la tabla `tipo_proyecto`
--

INSERT INTO `tipo_proyecto` (`id`, `nombre`, `estado_id`) VALUES
(1, 'INFRAESTRUCTURA', 2),
(2, 'WEB', 2),
(3, 'CLOUD', 1),
(4, 'OSINT', 1);

-- --------------------------------------------------------

--
-- Estructura de tabla para la tabla `usuarios`
--

CREATE TABLE `usuarios` (
  `id` int(11) NOT NULL,
  `rol_id` int(11) NOT NULL,
  `sector_id` int(11) DEFAULT NULL,
  `email` varchar(255) NOT NULL,
  `password_hash` varchar(255) DEFAULT NULL,
  `cracion` datetime DEFAULT current_timestamp(),
  `actualizacion` datetime DEFAULT NULL,
  `estado_id` int(11) DEFAULT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

--
-- Volcado de datos para la tabla `usuarios`
--

INSERT INTO `usuarios` (`id`, `rol_id`, `sector_id`, `email`, `password_hash`, `cracion`, `actualizacion`, `estado_id`) VALUES
(1, 1, 1, 'mrgonzalez@personal.com.ar', 'scrypt:32768:8:1$ApYqTkmAIbwhtDio$14f69ecc068f8e3894e90463b6e5937476cbc8b813686203012ab445d2f20f53791d8682653d7c7f38c88945828aa30466690563c92f620cdc0d1e39721410a3', '2026-02-15 11:49:41', NULL, 1);

-- --------------------------------------------------------

--
-- Estructura de tabla para la tabla `versiones_deprecadas`
--

CREATE TABLE `versiones_deprecadas` (
  `id` int(11) NOT NULL,
  `tipo_proyecto_id` int(11) NOT NULL,
  `proveedor` varchar(50) DEFAULT NULL,
  `servicio` varchar(100) DEFAULT NULL,
  `categoria` varchar(50) NOT NULL,
  `nombre_version` varchar(100) NOT NULL,
  `fecha_deprecacion` date DEFAULT NULL,
  `fecha_fin_soporte` date DEFAULT NULL,
  `estado_id` int(11) NOT NULL,
  `fecha_creacion` datetime DEFAULT current_timestamp(),
  `fecha_actualizacion` datetime DEFAULT current_timestamp() ON UPDATE current_timestamp()
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

--
-- Volcado de datos para la tabla `versiones_deprecadas`
--

INSERT INTO `versiones_deprecadas` (`id`, `tipo_proyecto_id`, `proveedor`, `servicio`, `categoria`, `nombre_version`, `fecha_deprecacion`, `fecha_fin_soporte`, `estado_id`, `fecha_creacion`, `fecha_actualizacion`) VALUES
(1, 3, 'AWS', 'Lambda', 'runtime', 'python2.7', '2023-01-01', NULL, 1, '2026-02-20 23:35:26', '2026-02-20 23:35:26'),
(2, 3, 'AWS', 'Lambda', 'runtime', 'python3.6', '2023-01-01', NULL, 1, '2026-02-20 23:35:26', '2026-02-20 23:35:26'),
(3, 3, 'AWS', 'Lambda', 'runtime', 'python3.7', '2023-01-01', NULL, 1, '2026-02-20 23:35:26', '2026-02-20 23:35:26'),
(4, 3, 'AWS', 'Lambda', 'runtime', 'nodejs8.10', '2023-01-01', NULL, 1, '2026-02-20 23:35:26', '2026-02-20 23:35:26'),
(5, 3, 'AWS', 'Lambda', 'runtime', 'nodejs10.x', '2023-01-01', NULL, 1, '2026-02-20 23:35:26', '2026-02-20 23:35:26'),
(6, 3, 'AWS', 'Lambda', 'runtime', 'nodejs12.x', '2023-01-01', NULL, 1, '2026-02-20 23:35:26', '2026-02-20 23:35:26'),
(7, 3, 'AWS', 'Lambda', 'runtime', 'nodejs14.x', '2023-01-01', NULL, 1, '2026-02-20 23:35:26', '2026-02-20 23:35:26'),
(8, 3, 'AWS', 'Lambda', 'runtime', 'dotnetcore2.1', '2023-01-01', NULL, 1, '2026-02-20 23:35:26', '2026-02-20 23:35:26'),
(9, 3, 'GCP', 'CloudFunctions', 'runtime', 'nodejs10', '2023-01-01', NULL, 1, '2026-02-20 23:35:26', '2026-02-20 23:35:26'),
(10, 3, 'AZURE', 'Functions', 'runtime', 'dotnetcore2.1', '2023-01-01', NULL, 1, '2026-02-20 23:35:26', '2026-02-20 23:35:26');

--
-- Índices para tablas volcadas
--

--
-- Indices de la tabla `cloud_ejecuciones`
--
ALTER TABLE `cloud_ejecuciones`
  ADD PRIMARY KEY (`id`),
  ADD KEY `fk_cloud_ejec_accion` (`accion_id`),
  ADD KEY `fk_cloud_ejec_usuario` (`usuario_id`),
  ADD KEY `fk_cloud_ejecuciones_estados` (`estado_id`),
  ADD KEY `idx_proyecto_accion` (`proyecto_id`,`accion_id`);

--
-- Indices de la tabla `cloud_ejecucion_findings`
--
ALTER TABLE `cloud_ejecucion_findings`
  ADD PRIMARY KEY (`id`),
  ADD KEY `cloud_ejecucion_id` (`cloud_ejecucion_id`);

--
-- Indices de la tabla `estados`
--
ALTER TABLE `estados`
  ADD PRIMARY KEY (`id`);

--
-- Indices de la tabla `estados_findings`
--
ALTER TABLE `estados_findings`
  ADD PRIMARY KEY (`id`),
  ADD KEY `fk_estadosfindings_estado` (`estado_id`);

--
-- Indices de la tabla `findings`
--
ALTER TABLE `findings`
  ADD PRIMARY KEY (`id`),
  ADD UNIQUE KEY `unique_finding` (`proyecto_id`,`cloud_ejecucion_id`,`check_id`,`resource_id`),
  ADD KEY `rule_id` (`security_rules_id`),
  ADD KEY `severidad_id` (`severidad_id`),
  ADD KEY `fk_findings_usuario` (`usuario_id`),
  ADD KEY `fk_findings_estados_findings` (`estados_findings_id`),
  ADD KEY `fk_findings_estado` (`estado_id`),
  ADD KEY `idx_cloud_ejecucion_id` (`cloud_ejecucion_id`);

--
-- Indices de la tabla `findings_evidence`
--
ALTER TABLE `findings_evidence`
  ADD PRIMARY KEY (`id`),
  ADD KEY `finding_id` (`finding_id`),
  ADD KEY `fk_finding_evidence_estados` (`estado_id`);

--
-- Indices de la tabla `proyectos`
--
ALTER TABLE `proyectos`
  ADD PRIMARY KEY (`id`),
  ADD KEY `fk_proyectos_estados` (`estado_id`),
  ADD KEY `fk_proyectos_servicios` (`tipo_servicio_id`),
  ADD KEY `fk_proyectos_usuarios` (`usuario_creador_id`),
  ADD KEY `fk_proyectos_sectores` (`sector_id`);

--
-- Indices de la tabla `proyecto_cloud_config`
--
ALTER TABLE `proyecto_cloud_config`
  ADD PRIMARY KEY (`id`),
  ADD UNIQUE KEY `proyecto_id` (`proyecto_id`),
  ADD KEY `fk_proyecto_cloud_estado` (`estado_id`);

--
-- Indices de la tabla `puertos_comunes`
--
ALTER TABLE `puertos_comunes`
  ADD PRIMARY KEY (`id`),
  ADD KEY `estado_id` (`estado_id`);

--
-- Indices de la tabla `reporte_contenido_secciones`
--
ALTER TABLE `reporte_contenido_secciones`
  ADD PRIMARY KEY (`id`),
  ADD UNIQUE KEY `uk_tipo_servicio` (`tipo_servicio`);

--
-- Indices de la tabla `reporte_estructura_cloud`
--
ALTER TABLE `reporte_estructura_cloud`
  ADD PRIMARY KEY (`id`),
  ADD UNIQUE KEY `uq_clave_proveedor` (`clave`,`proveedor`);

--
-- Indices de la tabla `reporte_tema`
--
ALTER TABLE `reporte_tema`
  ADD PRIMARY KEY (`id`),
  ADD UNIQUE KEY `uq_uso` (`uso`);

--
-- Indices de la tabla `roles`
--
ALTER TABLE `roles`
  ADD PRIMARY KEY (`id`),
  ADD KEY `fk_roles_estados` (`estado_id`);

--
-- Indices de la tabla `sectores`
--
ALTER TABLE `sectores`
  ADD PRIMARY KEY (`id`),
  ADD KEY `fk_sectores_estados` (`estado_id`);

--
-- Indices de la tabla `security_rules`
--
ALTER TABLE `security_rules`
  ADD PRIMARY KEY (`id`),
  ADD UNIQUE KEY `rule_code` (`check_id`),
  ADD UNIQUE KEY `check_id` (`check_id`),
  ADD UNIQUE KEY `check_id_2` (`check_id`),
  ADD UNIQUE KEY `unique_rule` (`provider`,`service`,`check_id`),
  ADD KEY `estado_id` (`estado_id`),
  ADD KEY `severidad_id` (`severidad_id`),
  ADD KEY `idx_security_rules_check` (`check_id`),
  ADD KEY `fk_security_rules_validado_por` (`validado_por`);

--
-- Indices de la tabla `servicios_aws`
--
ALTER TABLE `servicios_aws`
  ADD PRIMARY KEY (`id`),
  ADD KEY `fk_tipos_servicio_servicios_aws` (`tipos_servicio_id`),
  ADD KEY `fk_estados_servicios_aws` (`estado_id`);

--
-- Indices de la tabla `servicios_aws_acciones`
--
ALTER TABLE `servicios_aws_acciones`
  ADD PRIMARY KEY (`id`),
  ADD UNIQUE KEY `uk_accion_key` (`accion_key`),
  ADD KEY `fk_accion_servicio` (`servicios_aws_id`),
  ADD KEY `fk_accion_estado` (`estado_id`);

--
-- Indices de la tabla `severidades`
--
ALTER TABLE `severidades`
  ADD PRIMARY KEY (`id`),
  ADD KEY `estado_id` (`estado_id`);

--
-- Indices de la tabla `tenants`
--
ALTER TABLE `tenants`
  ADD PRIMARY KEY (`id`),
  ADD KEY `fk_tenants_estados` (`estado_id`);

--
-- Indices de la tabla `tipos_servicio`
--
ALTER TABLE `tipos_servicio`
  ADD PRIMARY KEY (`id`),
  ADD KEY `fk_servicio_cloud_estado` (`estado_id`);

--
-- Indices de la tabla `tipo_proyecto`
--
ALTER TABLE `tipo_proyecto`
  ADD PRIMARY KEY (`id`),
  ADD KEY `fk_tipo_proyectos_estado` (`estado_id`);

--
-- Indices de la tabla `usuarios`
--
ALTER TABLE `usuarios`
  ADD PRIMARY KEY (`id`),
  ADD KEY `fk_usuarios_sectores` (`sector_id`),
  ADD KEY `fk_usuarios_estados` (`estado_id`),
  ADD KEY `fk_usuarios_roles` (`rol_id`);

--
-- Indices de la tabla `versiones_deprecadas`
--
ALTER TABLE `versiones_deprecadas`
  ADD PRIMARY KEY (`id`),
  ADD UNIQUE KEY `uq_scope_version` (`tipo_proyecto_id`,`proveedor`,`servicio`,`categoria`,`nombre_version`),
  ADD KEY `fk_versiones_deprecadas_estado` (`estado_id`);

--
-- AUTO_INCREMENT de las tablas volcadas
--

--
-- AUTO_INCREMENT de la tabla `cloud_ejecuciones`
--
ALTER TABLE `cloud_ejecuciones`
  MODIFY `id` int(11) NOT NULL AUTO_INCREMENT;

--
-- AUTO_INCREMENT de la tabla `cloud_ejecucion_findings`
--
ALTER TABLE `cloud_ejecucion_findings`
  MODIFY `id` int(11) NOT NULL AUTO_INCREMENT;

--
-- AUTO_INCREMENT de la tabla `estados`
--
ALTER TABLE `estados`
  MODIFY `id` int(11) NOT NULL AUTO_INCREMENT, AUTO_INCREMENT=8;

--
-- AUTO_INCREMENT de la tabla `estados_findings`
--
ALTER TABLE `estados_findings`
  MODIFY `id` int(11) NOT NULL AUTO_INCREMENT, AUTO_INCREMENT=5;

--
-- AUTO_INCREMENT de la tabla `findings`
--
ALTER TABLE `findings`
  MODIFY `id` int(11) NOT NULL AUTO_INCREMENT;

--
-- AUTO_INCREMENT de la tabla `findings_evidence`
--
ALTER TABLE `findings_evidence`
  MODIFY `id` int(11) NOT NULL AUTO_INCREMENT;

--
-- AUTO_INCREMENT de la tabla `proyectos`
--
ALTER TABLE `proyectos`
  MODIFY `id` int(11) NOT NULL AUTO_INCREMENT, AUTO_INCREMENT=30;

--
-- AUTO_INCREMENT de la tabla `proyecto_cloud_config`
--
ALTER TABLE `proyecto_cloud_config`
  MODIFY `id` int(11) NOT NULL AUTO_INCREMENT, AUTO_INCREMENT=14;

--
-- AUTO_INCREMENT de la tabla `puertos_comunes`
--
ALTER TABLE `puertos_comunes`
  MODIFY `id` int(11) NOT NULL AUTO_INCREMENT, AUTO_INCREMENT=3;

--
-- AUTO_INCREMENT de la tabla `reporte_contenido_secciones`
--
ALTER TABLE `reporte_contenido_secciones`
  MODIFY `id` int(11) NOT NULL AUTO_INCREMENT, AUTO_INCREMENT=2;

--
-- AUTO_INCREMENT de la tabla `reporte_estructura_cloud`
--
ALTER TABLE `reporte_estructura_cloud`
  MODIFY `id` int(11) NOT NULL AUTO_INCREMENT, AUTO_INCREMENT=14;

--
-- AUTO_INCREMENT de la tabla `reporte_tema`
--
ALTER TABLE `reporte_tema`
  MODIFY `id` int(11) NOT NULL AUTO_INCREMENT, AUTO_INCREMENT=9;

--
-- AUTO_INCREMENT de la tabla `roles`
--
ALTER TABLE `roles`
  MODIFY `id` int(11) NOT NULL AUTO_INCREMENT, AUTO_INCREMENT=4;

--
-- AUTO_INCREMENT de la tabla `sectores`
--
ALTER TABLE `sectores`
  MODIFY `id` int(11) NOT NULL AUTO_INCREMENT, AUTO_INCREMENT=4;

--
-- AUTO_INCREMENT de la tabla `security_rules`
--
ALTER TABLE `security_rules`
  MODIFY `id` int(11) NOT NULL AUTO_INCREMENT, AUTO_INCREMENT=10;

--
-- AUTO_INCREMENT de la tabla `servicios_aws`
--
ALTER TABLE `servicios_aws`
  MODIFY `id` int(11) NOT NULL AUTO_INCREMENT, AUTO_INCREMENT=12;

--
-- AUTO_INCREMENT de la tabla `servicios_aws_acciones`
--
ALTER TABLE `servicios_aws_acciones`
  MODIFY `id` int(11) NOT NULL AUTO_INCREMENT, AUTO_INCREMENT=73;

--
-- AUTO_INCREMENT de la tabla `severidades`
--
ALTER TABLE `severidades`
  MODIFY `id` int(11) NOT NULL AUTO_INCREMENT, AUTO_INCREMENT=6;

--
-- AUTO_INCREMENT de la tabla `tenants`
--
ALTER TABLE `tenants`
  MODIFY `id` int(11) NOT NULL AUTO_INCREMENT;

--
-- AUTO_INCREMENT de la tabla `tipos_servicio`
--
ALTER TABLE `tipos_servicio`
  MODIFY `id` int(11) NOT NULL AUTO_INCREMENT, AUTO_INCREMENT=6;

--
-- AUTO_INCREMENT de la tabla `tipo_proyecto`
--
ALTER TABLE `tipo_proyecto`
  MODIFY `id` int(11) NOT NULL AUTO_INCREMENT, AUTO_INCREMENT=5;

--
-- AUTO_INCREMENT de la tabla `usuarios`
--
ALTER TABLE `usuarios`
  MODIFY `id` int(11) NOT NULL AUTO_INCREMENT, AUTO_INCREMENT=2;

--
-- AUTO_INCREMENT de la tabla `versiones_deprecadas`
--
ALTER TABLE `versiones_deprecadas`
  MODIFY `id` int(11) NOT NULL AUTO_INCREMENT, AUTO_INCREMENT=11;

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

--
-- Filtros para la tabla `cloud_ejecucion_findings`
--
ALTER TABLE `cloud_ejecucion_findings`
  ADD CONSTRAINT `cloud_ejecucion_findings_ibfk_1` FOREIGN KEY (`cloud_ejecucion_id`) REFERENCES `cloud_ejecuciones` (`id`) ON DELETE CASCADE;

--
-- Filtros para la tabla `estados_findings`
--
ALTER TABLE `estados_findings`
  ADD CONSTRAINT `fk_estadosfindings_estado` FOREIGN KEY (`estado_id`) REFERENCES `estados` (`id`) ON UPDATE CASCADE;

--
-- Filtros para la tabla `findings`
--
ALTER TABLE `findings`
  ADD CONSTRAINT `findings_ibfk_2` FOREIGN KEY (`severidad_id`) REFERENCES `severidades` (`id`) ON UPDATE CASCADE,
  ADD CONSTRAINT `fk_findings_cloud_ejecucion` FOREIGN KEY (`cloud_ejecucion_id`) REFERENCES `cloud_ejecuciones` (`id`) ON UPDATE CASCADE,
  ADD CONSTRAINT `fk_findings_estado` FOREIGN KEY (`estado_id`) REFERENCES `estados` (`id`) ON UPDATE CASCADE,
  ADD CONSTRAINT `fk_findings_estados_findings` FOREIGN KEY (`estados_findings_id`) REFERENCES `estados_findings` (`id`) ON UPDATE CASCADE,
  ADD CONSTRAINT `fk_findings_usuario` FOREIGN KEY (`usuario_id`) REFERENCES `usuarios` (`id`) ON UPDATE CASCADE;

--
-- Filtros para la tabla `findings_evidence`
--
ALTER TABLE `findings_evidence`
  ADD CONSTRAINT `fk_finding_evidence_estados` FOREIGN KEY (`estado_id`) REFERENCES `estados` (`id`) ON UPDATE CASCADE;

--
-- Filtros para la tabla `proyectos`
--
ALTER TABLE `proyectos`
  ADD CONSTRAINT `fk_proyectos_estados` FOREIGN KEY (`estado_id`) REFERENCES `estados` (`id`),
  ADD CONSTRAINT `fk_proyectos_sectores` FOREIGN KEY (`sector_id`) REFERENCES `sectores` (`id`),
  ADD CONSTRAINT `fk_proyectos_servicios` FOREIGN KEY (`tipo_servicio_id`) REFERENCES `tipos_servicio` (`id`),
  ADD CONSTRAINT `fk_proyectos_usuarios` FOREIGN KEY (`usuario_creador_id`) REFERENCES `usuarios` (`id`);

--
-- Filtros para la tabla `proyecto_cloud_config`
--
ALTER TABLE `proyecto_cloud_config`
  ADD CONSTRAINT `fk_proyecto_cloud` FOREIGN KEY (`proyecto_id`) REFERENCES `proyectos` (`id`) ON DELETE CASCADE,
  ADD CONSTRAINT `fk_proyecto_cloud_estado` FOREIGN KEY (`estado_id`) REFERENCES `estados` (`id`);

--
-- Filtros para la tabla `puertos_comunes`
--
ALTER TABLE `puertos_comunes`
  ADD CONSTRAINT `puertos_comunes_ibfk_1` FOREIGN KEY (`estado_id`) REFERENCES `estados` (`id`);

--
-- Filtros para la tabla `roles`
--
ALTER TABLE `roles`
  ADD CONSTRAINT `fk_roles_estados` FOREIGN KEY (`estado_id`) REFERENCES `estados` (`id`);

--
-- Filtros para la tabla `sectores`
--
ALTER TABLE `sectores`
  ADD CONSTRAINT `fk_sectores_estados` FOREIGN KEY (`estado_id`) REFERENCES `estados` (`id`);

--
-- Filtros para la tabla `security_rules`
--
ALTER TABLE `security_rules`
  ADD CONSTRAINT `fk_security_rules_validado_por` FOREIGN KEY (`validado_por`) REFERENCES `usuarios` (`id`),
  ADD CONSTRAINT `security_rules_ibfk_1` FOREIGN KEY (`estado_id`) REFERENCES `estados` (`id`) ON UPDATE CASCADE,
  ADD CONSTRAINT `security_rules_ibfk_2` FOREIGN KEY (`severidad_id`) REFERENCES `severidades` (`id`) ON UPDATE CASCADE;

--
-- Filtros para la tabla `servicios_aws`
--
ALTER TABLE `servicios_aws`
  ADD CONSTRAINT `fk_estados_servicios_aws` FOREIGN KEY (`estado_id`) REFERENCES `estados` (`id`),
  ADD CONSTRAINT `fk_tipos_servicio_servicios_aws` FOREIGN KEY (`tipos_servicio_id`) REFERENCES `tipos_servicio` (`id`);

--
-- Filtros para la tabla `servicios_aws_acciones`
--
ALTER TABLE `servicios_aws_acciones`
  ADD CONSTRAINT `fk_accion_estado` FOREIGN KEY (`estado_id`) REFERENCES `estados` (`id`) ON UPDATE CASCADE,
  ADD CONSTRAINT `fk_accion_servicio` FOREIGN KEY (`servicios_aws_id`) REFERENCES `servicios_aws` (`id`) ON UPDATE CASCADE;

--
-- Filtros para la tabla `severidades`
--
ALTER TABLE `severidades`
  ADD CONSTRAINT `severidades_ibfk_1` FOREIGN KEY (`estado_id`) REFERENCES `estados` (`id`) ON UPDATE CASCADE;

--
-- Filtros para la tabla `tenants`
--
ALTER TABLE `tenants`
  ADD CONSTRAINT `fk_tenants_estados` FOREIGN KEY (`estado_id`) REFERENCES `estados` (`id`);

--
-- Filtros para la tabla `tipos_servicio`
--
ALTER TABLE `tipos_servicio`
  ADD CONSTRAINT `fk_servicio_cloud_estado` FOREIGN KEY (`estado_id`) REFERENCES `estados` (`id`);

--
-- Filtros para la tabla `tipo_proyecto`
--
ALTER TABLE `tipo_proyecto`
  ADD CONSTRAINT `fk_tipo_proyectos_estado` FOREIGN KEY (`estado_id`) REFERENCES `estados` (`id`);

--
-- Filtros para la tabla `usuarios`
--
ALTER TABLE `usuarios`
  ADD CONSTRAINT `fk_usuarios_estados` FOREIGN KEY (`estado_id`) REFERENCES `estados` (`id`),
  ADD CONSTRAINT `fk_usuarios_roles` FOREIGN KEY (`rol_id`) REFERENCES `roles` (`id`),
  ADD CONSTRAINT `fk_usuarios_sectores` FOREIGN KEY (`sector_id`) REFERENCES `sectores` (`id`);

--
-- Filtros para la tabla `versiones_deprecadas`
--
ALTER TABLE `versiones_deprecadas`
  ADD CONSTRAINT `fk_versiones_deprecadas_estado` FOREIGN KEY (`estado_id`) REFERENCES `estados` (`id`),
  ADD CONSTRAINT `fk_versiones_deprecadas_tipo` FOREIGN KEY (`tipo_proyecto_id`) REFERENCES `tipo_proyecto` (`id`);
COMMIT;

/*!40101 SET CHARACTER_SET_CLIENT=@OLD_CHARACTER_SET_CLIENT */;
/*!40101 SET CHARACTER_SET_RESULTS=@OLD_CHARACTER_SET_RESULTS */;
/*!40101 SET COLLATION_CONNECTION=@OLD_COLLATION_CONNECTION */;
