"""
Servicio modular de traducción
Encapsula la lógica de traducción para permitir cambio fácil entre proveedores
"""

class TraductorBase:
    """Interfaz base para traductores"""

    def traducir(self, texto, idioma_origen="en", idioma_destino="es"):
        """
        Traduce texto de un idioma a otro

        Args:
            texto: Texto a traducir
            idioma_origen: Código de idioma origen (ej: "en")
            idioma_destino: Código de idioma destino (ej: "es")

        Returns:
            str: Texto traducido
        """
        raise NotImplementedError


class TraductorLibreTranslate(TraductorBase):
    """
    Implementación con LibreTranslate (gratuito)

    Soporta dos modos:
    1. Servidor local: libretranslate ejecutándose en localhost:5000
    2. Mock/Development: retorna texto sin traducir (para testing)
    """

    def __init__(self, api_url="http://localhost:5000/translate", modo="local"):
        """
        Args:
            api_url: URL del servidor LibreTranslate
            modo: "local" (servidor local) o "mock" (para testing)
        """
        try:
            import requests
            self.requests = requests
        except ImportError:
            raise ImportError(
                "requests no está instalado. "
                "Instala con: pip install requests --break-system-packages"
            )
        self.api_url = api_url
        self.modo = modo
        self._verificar_servidor()

    def _verificar_servidor(self):
        """Verifica si el servidor está disponible"""
        if self.modo == "mock":
            print("⚠ LibreTranslate en modo mock (no traducirá, retorna texto original)")
            return

        try:
            response = self.requests.get("http://localhost:5000/", timeout=2)
            print("✓ Servidor LibreTranslate detectado en localhost:5000")
        except Exception:
            print("⚠ Servidor LibreTranslate no encontrado en localhost:5000")
            print("  Modo mock activado - textos no se traducirán")
            self.modo = "mock"

    def traducir(self, texto, idioma_origen="en", idioma_destino="es"):
        """Traduce usando LibreTranslate (local o mock)"""
        if self.modo == "mock":
            # En modo mock, solo retorna el texto original
            # Esto permite que el código funcione durante desarrollo
            return texto

        try:
            payload = {
                "q": texto,
                "source": idioma_origen,
                "target": idioma_destino
            }
            response = self.requests.post(self.api_url, json=payload, timeout=10)
            response.raise_for_status()
            result = response.json()
            return result.get("translatedText", texto)
        except Exception as e:
            print(f"⚠ Error en traducción (retornando texto original): {str(e)}")
            return texto  # Retorna el texto original si falla


class TraductorDeepL(TraductorBase):
    """Implementación con DeepL (premium) - para usar en futuro"""

    def __init__(self, api_key):
        try:
            import deepl
            self.translator = deepl.Translator(api_key)
        except ImportError:
            raise ImportError(
                "DeepL no está instalado. "
                "Instala con: pip install deepl --break-system-packages"
            )
        self.api_key = api_key

    def traducir(self, texto, idioma_origen="en", idioma_destino="es"):
        """Traduce usando DeepL"""
        try:
            result = self.translator.translate_text(
                texto,
                source_lang=idioma_origen.upper(),
                target_lang=idioma_destino.upper()
            )
            return result.text
        except Exception as e:
            print(f"Error en traducción DeepL: {str(e)}")
            return texto


class TraductorGoogle(TraductorBase):
    """Implementación con Google Translate API (premium) - para usar en futuro"""

    def __init__(self, api_key=None):
        try:
            from google.cloud import translate_v2
            self.client = translate_v2.Client()
        except ImportError:
            raise ImportError(
                "Google Cloud Translation no está instalada. "
                "Instala con: pip install google-cloud-translate --break-system-packages"
            )

    def traducir(self, texto, idioma_origen="en", idioma_destino="es"):
        """Traduce usando Google Translate API"""
        try:
            result = self.client.translate_text(
                texto,
                source_language=idioma_origen,
                target_language=idioma_destino
            )
            return result["translatedText"]
        except Exception as e:
            print(f"Error en traducción Google: {str(e)}")
            return texto


# Factory - permite cambiar fácilmente de proveedor
def obtener_traductor(proveedor="libretranslate", **kwargs):
    """
    Obtiene una instancia del traductor especificado

    Args:
        proveedor: "libretranslate", "deepl", o "google"
        **kwargs: argumentos adicionales (ej: api_key para DeepL)

    Returns:
        Instancia de TraductorBase

    Ejemplo:
        # Usando LibreTranslate (gratuito)
        traductor = obtener_traductor("libretranslate")
        texto_traducido = traductor.traducir("Hello world")

        # Cambiar a DeepL en el futuro (sin afectar el resto del código)
        traductor = obtener_traductor("deepl", api_key="tu-api-key")
        texto_traducido = traductor.traducir("Hello world")
    """
    if proveedor == "libretranslate":
        return TraductorLibreTranslate()
    elif proveedor == "deepl":
        api_key = kwargs.get("api_key")
        if not api_key:
            raise ValueError("DeepL requiere 'api_key'")
        return TraductorDeepL(api_key)
    elif proveedor == "google":
        return TraductorGoogle()
    else:
        raise ValueError(f"Proveedor desconocido: {proveedor}")
