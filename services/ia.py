# services/ia.py
import anthropic
import json
import logging
from config import Config

log = logging.getLogger(__name__)


class IA:
    def __init__(self, modelo="claude-sonnet-4-6", max_tokens=1000):
        self.client = anthropic.Anthropic(api_key=Config.ANTHROPIC_API_KEY)
        self.modelo = modelo
        self.max_tokens = max_tokens

    def generar_json(self, prompt, max_tokens=None):
        """Espera una respuesta JSON estricta de la IA. Devuelve dict o None."""
        texto = None
        try:
            response = self.client.messages.create(
                model=self.modelo,
                max_tokens=max_tokens or self.max_tokens,
                messages=[{"role": "user", "content": prompt}]
            )
            texto = response.content[0].text.strip()
            texto = texto.removeprefix("```json").removesuffix("```").strip()
            return json.loads(texto)
        except json.JSONDecodeError as e:
            log.error(f"IA devolvió JSON inválido: {e} | respuesta: {texto[:300] if texto else 'N/A'}")
            return None
        except Exception as e:
            log.error(f"Error llamando a IA (generar_json): {e}")
            return None

    def generar_texto(self, prompt, max_tokens=None):
        """Espera texto libre. Útil para resúmenes, OSINT, redacción de reportes."""
        try:
            response = self.client.messages.create(
                model=self.modelo,
                max_tokens=max_tokens or self.max_tokens,
                messages=[{"role": "user", "content": prompt}]
            )
            return response.content[0].text.strip()
        except Exception as e:
            log.error(f"Error llamando a IA (generar_texto): {e}")
            return None