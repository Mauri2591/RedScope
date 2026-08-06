# SCOUTSUITE
Al momento de parsear el js primero éstos se deben pasar a formato json y eliminar de su contenido la variable [scoutsuite_results=].

Mapeo ScoutSuite → Severidades RedScope:
JSON "level"	→	Severity	→	severidad_id	tu tabla
"danger"	    →	"critical"	→	5	CRITICAL
"warning"	    →	"medium"	→	3	MEDIUM
"info"	        →	"low"	    →	2	LOW

Para mantener congruencia en la clasificacion hago:
level_map = {
    'danger': 'critical',
    'warning': 'medium',
    'info': 'low'
}


# PROWLER
Prowler tiene `severity_id` del (1-5) en el JSON.

Mapeo Prowler → Severidades RedScope:
JSON "severity_id"	→	Severity	        →	severidad_id	tu tabla
1	                →	"informational"	    →	1	INFORMATIONAL
2	                →	"low"	            →	2	LOW
3	                →	"medium"	        →	3	MEDIUM
4	                →	"high"	            →	4	HIGH
5	                →	"critical"	        →	5	CRITICAL

Para mantener congruencia en la clasificación hago:
severidad_id = item.get('severity_id', 3)  # Default MEDIUM (3)