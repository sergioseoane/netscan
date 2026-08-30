#!/usr/bin/env python3
"""
audit_informe_semanal.py - ejecuta el diagnostico de conectividad, el
comparador de linea base y (opcionalmente) los certificados SSL, y
junta todo en un unico informe HTML con fecha - pensado para
programarse solo (Programador de tareas de Windows) y acumular un
historico real, no una foto suelta cada vez.

Uso:
  python audit_informe_semanal.py --subnet 192.168.1.0/24 --certificados sergioseoane.com github.com
"""

import argparse
import html
import os
import sys
from datetime import datetime

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
import netscan
import audit_comparador
import audit_certificados

CARPETA_INFORMES = os.path.join(os.path.dirname(__file__), "informes")


def enviar_notificacion_escritorio(titulo: str, mensaje: str):
    """Aviso de escritorio de Windows (una notificacion emergente, como
    las de cualquier programa normal), en vez de un email - no requiere
    configurar ningun servidor de correo.

    Usa la libreria 'plyer' (opcional, ver requirements.txt). Si no
    esta instalada o algo falla, se degrada a un aviso por consola en
    vez de romper la ejecucion - un aviso de escritorio que falla no
    debe impedir que el resto del informe se genere igualmente.

    No se ha podido probar esta notificacion de verdad en el entorno
    donde se escribio el codigo (sin interfaz grafica de Windows) -
    confirma que aparece correctamente la primera vez que lo uses.
    """
    try:
        from plyer import notification
        notification.notify(title=titulo, message=mensaje, timeout=10, app_name="Auditoría de red")
    except Exception as e:
        print(f"(No se pudo mostrar la notificación de escritorio: {e})")


def generar_html(subnet: str, diagnostico: list, diff_red: dict, certificados: list) -> str:
    fecha = datetime.now().strftime("%Y-%m-%d %H:%M")

    def led(ok):
        color = "var(--ok)" if ok else "var(--fail)"
        return f'<span class="led" style="background:{color};box-shadow:0 0 6px {color}"></span>'

    def fila_diag(p):
        return (
            f"<tr><td>{led(p['ok'])}{html.escape(p['paso'])}</td>"
            f"<td class='mono muted'>{html.escape(str(p['detalle'] or ''))}</td>"
            f"<td class='mono {'ok' if p['ok'] else 'fail'}'>{'OK' if p['ok'] else 'FALLA'}</td>"
            f"<td>{html.escape(p['mensaje'])}</td></tr>"
        )
    filas_diag = "\n".join(fila_diag(p) for p in diagnostico)

    def bloque_cambios(titulo, macs, datos, tono):
        if not macs:
            return ""
        filas = "\n".join(
            f"<li><span class='mono {tono}'>{html.escape(datos[m]['ip'])}</span> "
            f"<span class='muted mono'>{html.escape(m)}</span> "
            f"{html.escape(datos[m]['hostname'])}</li>"
            for m in macs
        )
        return f"<p class='label {tono}'>{html.escape(titulo)}</p><ul>{filas}</ul>"

    if diff_red.get("_primera_ejecucion"):
        seccion_red = (
            "<p class='muted'><em>Primera ejecución: línea base creada ahora. "
            "Nada con qué comparar todavía — la próxima ejecución ya detectará cambios.</em></p>"
        )
    else:
        bloques = (
            bloque_cambios("Dispositivos nuevos", diff_red.get("nuevos", []), diff_red.get("_actual", {}), "warn")
            + bloque_cambios("Dispositivos desaparecidos", diff_red.get("desaparecidos", []), diff_red.get("_base", {}), "fail")
        )
        seccion_red = bloques or "<p class='muted'>Sin cambios respecto a la línea base. Todo en orden.</p>"

    def fila_cert(c):
        if not c.get("ok"):
            return f"<tr><td>{html.escape(c['host'])}</td><td class='fail mono' colspan='3'>ERROR — {html.escape(c['error'])}</td></tr>"
        tono = {"OK": "ok", "AVISO": "warn", "CRITICO": "fail", "CADUCADO": "fail"}.get(c["estado"], "")
        return (
            f"<tr><td>{html.escape(c['host'])}</td>"
            f"<td class='mono {tono}'>{c['estado']}</td>"
            f"<td class='mono'>{c['dias_restantes']} días</td>"
            f"<td class='mono muted'>{html.escape(c['caduca_el'])}</td></tr>"
        )
    filas_cert = "\n".join(fila_cert(c) for c in certificados) if certificados else ""
    seccion_cert = (
        f"<table><tr><th>Host</th><th>Estado</th><th>Caduca en</th><th>Fecha</th></tr>{filas_cert}</table>"
        if certificados else "<p class='muted'>No se comprobó ningún certificado en esta ejecución.</p>"
    )

    return f"""<!DOCTYPE html>
<html lang="es">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Auditoría de red — {fecha}</title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link href="https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;500;700&family=Inter:wght@400;500;600&display=swap" rel="stylesheet">
<style>
  :root {{
    --bg: #12161d; --panel: #1a2029; --border: #2a3340;
    --text: #e7eaf0; --muted: #8892a0; --accent: #f0b429;
    --ok: #4ade80; --warn: #f0b429; --fail: #f0665a;
  }}
  * {{ box-sizing: border-box; }}
  body {{
    margin: 0; background: var(--bg); color: var(--text);
    font-family: 'Inter', sans-serif; line-height: 1.55;
    background-image: linear-gradient(rgba(255,255,255,.015) 1px, transparent 1px),
                       linear-gradient(90deg, rgba(255,255,255,.015) 1px, transparent 1px);
    background-size: 32px 32px;
  }}
  .wrap {{ max-width: 900px; margin: 0 auto; padding: 48px 24px; }}
  .prompt {{ font-family: 'JetBrains Mono', monospace; color: var(--muted); font-size: 13px; margin-bottom: 10px; }}
  .prompt .accent {{ color: var(--ok); }}
  h1 {{ font-family: 'JetBrains Mono', monospace; font-size: 26px; margin: 0 0 6px; }}
  .subt {{ color: var(--muted); font-size: 14px; margin-bottom: 36px; }}
  .subt strong {{ color: var(--text); font-family: 'JetBrains Mono', monospace; }}
  h2 {{
    font-family: 'JetBrains Mono', monospace; font-size: 15px; text-transform: uppercase;
    letter-spacing: 1px; color: var(--muted); margin: 40px 0 14px;
    display: flex; align-items: center; gap: 10px;
  }}
  h2::after {{ content: ""; flex: 1; height: 1px; background: var(--border); }}
  table {{ width: 100%; border-collapse: collapse; background: var(--panel); border: 1px solid var(--border); border-radius: 8px; overflow: hidden; }}
  th {{ text-align: left; font-family: 'JetBrains Mono', monospace; font-size: 12px; text-transform: uppercase; letter-spacing: .5px; color: var(--muted); padding: 10px 14px; border-bottom: 1px solid var(--border); }}
  td {{ padding: 10px 14px; border-bottom: 1px solid var(--border); font-size: 14px; }}
  tr:last-child td {{ border-bottom: none; }}
  .mono {{ font-family: 'JetBrains Mono', monospace; font-size: 13px; }}
  .muted {{ color: var(--muted); }}
  .ok {{ color: var(--ok); }}
  .warn {{ color: var(--warn); }}
  .fail {{ color: var(--fail); }}
  .label {{ font-family: 'JetBrains Mono', monospace; font-size: 13px; text-transform: uppercase; letter-spacing: .5px; margin: 18px 0 6px; }}
  ul {{ margin: 0 0 10px; padding-left: 4px; list-style: none; }}
  li {{ padding: 6px 0; border-bottom: 1px dashed var(--border); font-size: 14px; }}
  li:last-child {{ border-bottom: none; }}
  .led {{ display: inline-block; width: 8px; height: 8px; border-radius: 50%; margin-right: 10px; }}
  footer {{ margin-top: 48px; padding-top: 16px; border-top: 1px solid var(--border); color: var(--muted); font-family: 'JetBrains Mono', monospace; font-size: 12px; }}
</style>
</head>
<body>
<div class="wrap">
  <div class="prompt">sergio@homelab:~$ <span class="accent">auditoria --subnet {html.escape(subnet)}</span></div>
  <h1>Informe de auditoría de red</h1>
  <p class="subt">Subred: <strong>{html.escape(subnet)}</strong> · Generado el {fecha}</p>

  <h2>Diagnóstico de conectividad</h2>
  <table><tr><th>Paso</th><th>Detalle</th><th>Estado</th><th>Mensaje</th></tr>{filas_diag}</table>

  <h2>Cambios respecto a la línea base</h2>
  {seccion_red}

  <h2>Certificados SSL/TLS</h2>
  {seccion_cert}

  <footer>netscan/auditoria · informe generado automáticamente</footer>
</div>
</body>
</html>"""


def main():
    parser = argparse.ArgumentParser(description="Genera un informe semanal de auditoría en HTML")
    parser.add_argument("--subnet", required=True, help="Subred a auditar")
    parser.add_argument("--certificados", nargs="*", default=[], help="Hosts a comprobar certificado SSL")
    parser.add_argument("--archivo-base", default=None, help="Ruta del archivo de línea base (por defecto, el de audit_comparador)")
    parser.add_argument("--sin-notificacion", action="store_true", help="No mostrar la notificación de escritorio al terminar")
    args = parser.parse_args()

    archivo_base = args.archivo_base or audit_comparador.ARCHIVO_LINEA_BASE_DEFECTO

    print("1/3 - Diagnóstico de conectividad...")
    diagnostico = netscan.diagnostico_conectividad()

    print("2/3 - Comparando con línea base de red...")
    actual = audit_comparador.escanear_estado_actual(args.subnet)
    if os.path.exists(archivo_base):
        base = audit_comparador.cargar_linea_base(archivo_base)
        diff = audit_comparador.comparar(base, actual)
        diff["_actual"] = actual
        diff["_base"] = base
    else:
        audit_comparador.guardar_linea_base(archivo_base, actual)
        diff = {"nuevos": [], "desaparecidos": [], "cambiados_ip": [], "_actual": actual, "_base": {}, "_primera_ejecucion": True}
        print(f"   (no había línea base, se ha creado una nueva en {archivo_base})")

    print("3/3 - Comprobando certificados...")
    certificados = [audit_certificados.comprobar_certificado(h) for h in args.certificados]

    os.makedirs(CARPETA_INFORMES, exist_ok=True)
    nombre_archivo = f"informe_{datetime.now().strftime('%Y%m%d_%H%M%S')}.html"
    ruta = os.path.join(CARPETA_INFORMES, nombre_archivo)

    contenido = generar_html(args.subnet, diagnostico, diff, certificados)
    with open(ruta, "w", encoding="utf-8") as f:
        f.write(contenido)

    print(f"\nInforme generado: {ruta}")

    if not args.sin_notificacion:
        problemas = []
        if any(not p["ok"] for p in diagnostico):
            problemas.append("fallo de conectividad")
        if diff.get("nuevos") or diff.get("desaparecidos"):
            problemas.append("cambios en la red")
        if any(c.get("estado") in ("CRITICO", "CADUCADO") for c in certificados if c.get("ok")):
            problemas.append("certificado crítico")

        if problemas:
            enviar_notificacion_escritorio(
                "⚠ Auditoría de red: revisar",
                f"Se detectó: {', '.join(problemas)}. Ver informe en {ruta}",
            )
        else:
            enviar_notificacion_escritorio(
                "Auditoría de red completada",
                "Todo en orden. Sin incidencias detectadas.",
            )


if __name__ == "__main__":
    main()
