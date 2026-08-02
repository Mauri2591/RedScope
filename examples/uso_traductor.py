"""
Ejemplo de uso del módulo traductor modular
"""

from services.traductor import obtener_traductor

# ══════════════════════════════════════════════════════════════════
# USO ACTUAL: LibreTranslate (GRATUITO)
# ══════════════════════════════════════════════════════════════════

def ejemplo_libretranslate():
    """Usa LibreTranslate - gratis, sin API key"""
    traductor = obtener_traductor("libretranslate")

    textos = [
        "The bucket has default encryption enabled",
        "Security group changes detected",
        "Access Analyzer is not enabled"
    ]

    for texto in textos:
        traducido = traductor.traducir(texto)
        print(f"EN: {texto}")
        print(f"ES: {traducido}")
        print()


# ══════════════════════════════════════════════════════════════════
# USO FUTURO: Si pagan por DeepL (cambio de 1 línea)
# ══════════════════════════════════════════════════════════════════

def ejemplo_deepl_futuro():
    """
    Cuando tengan API key de DeepL, solo cambiar esta línea:
    traductor = obtener_traductor("deepl", api_key="tu-api-key-aqui")
    """
    # traductor = obtener_traductor("deepl", api_key="sk-123456")
    # traducido = traductor.traducir("Hello world")
    pass


# ══════════════════════════════════════════════════════════════════
# USO EN REPORTES
# ══════════════════════════════════════════════════════════════════

def traducir_campos_reporte(hallazgo):
    """
    Ejemplo: traducir campos de un hallazgo de Prowler
    """
    traductor = obtener_traductor("libretranslate")

    hallazgo_traducido = {
        "titulo": traductor.traducir(hallazgo.get("titulo")),
        "descripcion": traductor.traducir(hallazgo.get("descripcion")),
        "remediacion": traductor.traducir(hallazgo.get("remediacion")),
    }

    return hallazgo_traducido


if __name__ == "__main__":
    print("=" * 70)
    print("EJEMPLO: LibreTranslate")
    print("=" * 70)
    ejemplo_libretranslate()

    print("\n✨ Para cambiar a DeepL en el futuro:")
    print("   1. Obtener API key de DeepL")
    print("   2. Cambiar línea en el código: obtener_traductor('deepl', api_key='...')")
    print("   3. ¡Listo! Sin cambios en el resto del código")
