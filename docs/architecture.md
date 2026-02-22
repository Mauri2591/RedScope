# RedScope Architecture

## 1. Overview

RedScope es una plataforma modular de seguridad ofensiva diseñada para automatizar análisis técnicos sobre distintos dominios de infraestructura.

Actualmente incluye un módulo de seguridad Cloud y está diseñada para expandirse hacia OSINT avanzado, análisis de infraestructura y análisis de aplicaciones web.

---

## 2. Access & Segmentation Model

RedScope utiliza un modelo basado en roles y segmentación por sectores.

### 2.1 Roles

- ROOT  
- ADMIN  
- USER  

### 2.2 Sectores

La plataforma se organiza en sectores funcionales:

- Ethical Hacking
- SOC
- SASE
- (Extensibles dinámicamente)

Cada proyecto pertenece a un sector y los usuarios operan dentro de los sectores habilitados según su rol.

---

## 3. Current Modules

### 3.1 Cloud Security Module

- Enumeración de activos
- Revisión de configuraciones inseguras
- Detección de privilege escalation
- Análisis de exposición y malas configuraciones
- Ejecución asíncrona mediante workers

---

## 4. Future Modules (Planned)

RedScope está diseñada bajo un principio de arquitectura modular extensible.  
Los siguientes módulos forman parte del roadmap evolutivo:

### 4.1 OSINT Avanzado

- Enumeración de dominios y subdominios
- Integración con Certificate Transparency
- Descubrimiento de activos expuestos
- Correlación de información pública
- Surface mapping automatizado

### 4.2 Análisis de Infraestructura

- Descubrimiento de servicios expuestos
- Identificación de versiones y configuraciones inseguras
- Integración con scanners externos
- Análisis de exposición de red
- Evaluación de endurecimiento (hardening review)

### 4.3 Análisis Web

- Identificación de tecnologías
- Detección de configuraciones débiles
- Enumeración de endpoints
- Análisis de headers de seguridad
- Integración con motores de escaneo automatizado

---

## 5. Unified Scan Result Model

Todos los módulos de análisis en RedScope devuelven resultados siguiendo un esquema JSON unificado.  
Este diseño garantiza consistencia entre servicios y facilita:

- Procesamiento uniforme
- Renderizado dinámico en UI
- Persistencia estructurada
- Extensibilidad hacia nuevos módulos

### 5.1 Base Structure

Cada ejecución retorna una estructura con los siguientes campos:

{
  "provider": "<Proveedor o dominio analizado>",
  "service": "<Servicio analizado>",
  "account_id": "<Identificador del entorno objetivo>",
  "region": "<Región evaluada o alcance>",
  "inventory_type": "<Tipo de análisis ejecutado>",
  "total_resources_checked": 0,
  "total_resources": 0,
  "resources": []
}

### 5.2 Design Decision

- La estructura se mantiene incluso cuando no se detectan recursos.
- El campo `resources` puede estar vacío (`[]`).
- Todos los módulos respetan este esquema independientemente del dominio (Cloud, OSINT, Infraestructura, Web).
- Permite integrar nuevos motores sin modificar el modelo central de persistencia ni la lógica de visualización.

---

## 6. Architectural Principles

- Diseño modular
- RBAC centralizado
- Segmentación por sector
- Ejecución asíncrona
- Persistencia estructurada
- Contrato de resultados unificado

---

## 7. Technology Stack

RedScope está construida sobre una arquitectura basada en componentes desacoplados y ejecución asíncrona.

### 7.1 Backend

- Python  
- Flask (Web framework)

### 7.2 Execution Engine

- Redis Server (cola de tareas)
- RQ Workers (procesamiento asíncrono de análisis)

### 7.3 Base de Datos

- MariaDB (persistencia relacional)
- Modelo estructurado para:
  - Proyectos
  - Sectores
  - Usuarios y roles
  - Ejecuciones de escaneo
  - Resultados estructurados

### 7.4 Cloud Integration

Actualmente RedScope integra servicios de AWS mediante:

- AWS
  - Boto3 (integración con APIs oficiales)

La arquitectura está diseñada para permitir la incorporación futura de nuevos proveedores Cloud sin modificar el núcleo del motor de ejecución.

Proveedores planificados:
- Azure
- GCP
- Huawe