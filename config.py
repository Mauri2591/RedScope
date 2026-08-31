import os
from dotenv import load_dotenv
from redis import Redis

load_dotenv()

class Config:

    # -------------------
    # BASE DE DATOS
    # -------------------
    DB_HOST = os.getenv("DB_HOST")
    DB_USER = os.getenv("DB_USER")
    DB_PASSWORD = os.getenv("DB_PASSWORD")
    DB_NAME = os.getenv("DB_NAME")

    # -------------------
    # SEGURIDAD / FLASK
    # -------------------
    SECRET_KEY = os.getenv("FLASK_SECRET_KEY")

    fernet_key = os.getenv("FERNET_KEY")
    FERNET_KEY = fernet_key.encode() if fernet_key else None

    APP_HOST = os.getenv("APP_HOST", "127.0.0.1")
    APP_PORT = int(os.getenv("APP_PORT", 5000))
    APP_DEBUG = os.getenv("APP_DEBUG", "false").lower() == "true"

    # -------------------
    # REDIS
    # -------------------
    REDIS_HOST = os.getenv("REDIS_HOST", "localhost")
    REDIS_PORT = int(os.getenv("REDIS_PORT", 6379))
    REDIS_DB = int(os.getenv("REDIS_DB", 0))
    REDIS_PASSWORD = os.getenv("REDIS_PASSWORD")

    redis_conn = Redis(
        host=REDIS_HOST,
        port=REDIS_PORT,
        db=REDIS_DB,
        password=REDIS_PASSWORD if REDIS_PASSWORD else None
    )

    # -------------------
    # RUTAS / ARCHIVOS
    # -------------------
    BASE_DIR = os.path.dirname(os.path.abspath(__file__))
    
    USE_PROXY_FIX = os.getenv("USE_PROXY_FIX", "false").lower() == "true"
    
    # Esto toma la variable de entorno si existe, sino usa BASE_DIR/data
    DATA_DIR = os.getenv("DATA_DIR", os.path.join(BASE_DIR, "data"))
    BASE_PATH = os.getenv("BASE_PATH", "")
    
    # Asegurarse de que la carpeta exista
    os.makedirs(DATA_DIR, exist_ok=True)
    
    
    #Anthropic
    ANTHROPIC_API_KEY = os.getenv("ANTHROPIC_API_KEY")
    CLAUDE_HABILITAR = os.getenv("CLAUDE_HABILITAR", "true").lower() == "true"
    
    
# Timeouts específicos por handler OSINT (RQ posee un delay de 60 segundos antes de iniciar el conteo)
OSINT_JOB_TIMEOUTS = {
    'discovery_subdominios': 1800,              # 30 min
    'enumeracion_servicios': 1200,              # 20 min
    'mapeo_ips': 1200,                          # 20 min
    'recon_cloud': 1800,                        # 30 min
    'escaneo_repositorios': 600,                # 10 min
    'analisis_dns': 900,                        # 15 min
    'busqueda_endpoints': 1800,                 # 30 min
    'google_dorking': 900,                      # 15 min
    'urls_historicas': 9800,                    # 3 horas (2+ horas de ejecución + 60s delay)
    'sensitive_data_extraction': 3600,          # 1 hora
    'default': 3600                             # Fallback 1 hora
}