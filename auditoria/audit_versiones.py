#!/usr/bin/env python3
"""
audit_versiones.py - se conecta a los puertos abiertos de un host y
lee el "banner" que cada servicio anuncia de si mismo, para detectar
versiones antiguas sin necesitar una base de datos de CVEs completa.

Uso:
  python audit_versiones.py 192.168.1.130
  python audit_versiones.py 192.168.1.130 --puertos 22,80,443
"""

import argparse
import re
import socket
import sys
import urllib.error
import urllib.parse
import urllib.request
import json
from datetime import datetime

# Puertos donde se asume TLS (para saber si envolver la conexion en
# SSL antes de hablar) - el resto se prueba primero como banner crudo
# y, si no responde nada, como HTTP en claro (ver auditar_host).
PUERTOS_HTTPS = {443, 8443}

# Umbrales orientativos de "esto ya es antiguo" - no es una base de
# datos de CVEs, es una comprobacion simple de version minima razonable.
VERSIONES_MINIMAS_RECOMENDADAS = {
    "openssh": (8, 0),
    "nginx": (1, 20),
    "apache": (2, 4),
}


def leer_banner_crudo(ip: str, puerto: int, timeout: float = 3.0) -> str:
    """Para servicios como SSH/FTP/SMTP: el propio servicio envia su
    banner nada mas conectar, sin que haga falta pedir nada."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            s.connect((ip, puerto))
            data = s.recv(256)
            return data.decode(errors="replace").strip()
    except (socket.timeout, ConnectionRefusedError, OSError):
        return None


def leer_banner_http(ip: str, puerto: int, usar_tls: bool = False, timeout: float = 3.0) -> str:
    """Para HTTP(S): hay que pedir algo (una peticion GET simple) antes
    de que el servidor responda con sus cabeceras, entre ellas 'Server:'."""
    import ssl
    try:
        sock = socket.create_connection((ip, puerto), timeout=timeout)
        if usar_tls:
            contexto = ssl.create_default_context()
            contexto.check_hostname = False
            contexto.verify_mode = ssl.CERT_NONE
            sock = contexto.wrap_socket(sock)
        peticion = f"HEAD / HTTP/1.1\r\nHost: {ip}\r\nConnection: close\r\n\r\n"
        sock.sendall(peticion.encode())
        respuesta = sock.recv(1024).decode(errors="replace")
        sock.close()
        m = re.search(r"Server:\s*(.+)", respuesta, re.IGNORECASE)
        return m.group(1).strip() if m else None
    except (socket.timeout, ConnectionRefusedError, OSError, ssl.SSLError):
        return None


def evaluar_version(banner: str) -> str:
    """Compara contra la tabla de versiones minimas razonables - es
    una comprobacion simple, no un escaner de CVEs real."""
    if not banner:
        return None
    banner_lower = banner.lower()
    for producto, (major_min, minor_min) in VERSIONES_MINIMAS_RECOMENDADAS.items():
        if producto in banner_lower:
            m = re.search(r"(\d+)\.(\d+)", banner_lower.split(producto, 1)[1])
            if m:
                major, minor = int(m.group(1)), int(m.group(2))
                if (major, minor) < (major_min, minor_min):
                    return f"Posiblemente desactualizado (< {producto} {major_min}.{minor_min})"
                return "Version razonablemente reciente"

    # Respaldo generico: muchos dispositivos de red (routers, camaras,
    # impresoras) meten directamente el ano de compilacion del firmware
    # en el propio banner, aunque el producto no este en la tabla de
    # arriba. Un ano antiguo ahi es una senal real de firmware sin
    # actualizar, aunque no sepamos identificar el producto exacto.
    anos = re.findall(r"\b(19[9]\d|20[0-2]\d)\b", banner)
    if anos:
        ano_detectado = int(anos[0])
        antiguedad = datetime.now().year - ano_detectado
        if antiguedad >= 5:
            return f"El banner incluye el año {ano_detectado} ({antiguedad} años) - revisar si el firmware sigue recibiendo actualizaciones"
        return f"El banner incluye el año {ano_detectado} ({antiguedad} años) - relativamente reciente"

    return None


def extraer_termino_busqueda(banner: str) -> str:
    """Aisla un termino de busqueda mas limpio (producto + version) a
    partir del banner completo, en vez de mandar la frase entera al
    NVD. Una busqueda por palabras clave en el NVD funciona mucho
    mejor con "producto version" (ej. "OpenSSH 7.4") que con una
    frase larga con ruido alrededor (ej. el nombre del fabricante,
    anos sueltos, texto de copyright) - eso era justo lo que pasaba
    con el banner real "ZTE web server 1.0 ZTE corp 2015.", donde el
    "ZTE corp 2015." final no aporta nada a la busqueda y solo la
    ensucia.

    Toma la ULTIMA coincidencia de "palabras + numero de version" en
    el banner, no la primera - esto importa para banners como
    "SSH-2.0-OpenSSH_7.4", donde la primera coincidencia seria
    "SSH 2.0" (el protocolo, no el producto) y la que de verdad
    interesa es "OpenSSH 7.4", al final.
    """
    normalizado = re.sub(r"[/_\-]", " ", banner)
    coincidencias = re.findall(r"([A-Za-z]+(?:\s+[A-Za-z]+){0,2})\s+(\d+\.\d+(?:\.\d+)?)", normalizado)
    if coincidencias:
        palabras, version = coincidencias[-1]
        return f"{palabras.strip()} {version}"
    return banner


def buscar_cves(termino_busqueda: str, max_resultados: int = 5, timeout: float = 6.0) -> dict:
    """Consulta la API publica y gratuita del NVD (National Vulnerability
    Database, del NIST de EEUU) para saber si una version concreta de
    un producto tiene vulnerabilidades (CVEs) reales y documentadas -
    a diferencia de VERSIONES_MINIMAS_RECOMENDADAS (que es una opinion
    nuestra), esto es un dato oficial.

    IMPORTANTE: la API publica del NVD tiene un limite de unas 5
    peticiones cada 30 segundos sin clave de API - por eso solo se usa
    bajo demanda (--cve), no en cada auditoria automatica.

    No se ha podido probar esta llamada de verdad en el entorno donde
    se escribio este codigo (sin salida a ese dominio concreto) - se
    ha escrito siguiendo el formato documentado de la API NVD 2.0.
    """
    url = (
        "https://services.nvd.nist.gov/rest/json/cves/2.0"
        f"?keywordSearch={urllib.parse.quote(termino_busqueda)}"
        f"&resultsPerPage={max_resultados}"
    )
    try:
        with urllib.request.urlopen(url, timeout=timeout) as resp:
            datos = json.loads(resp.read().decode("utf-8"))
    except (urllib.error.URLError, urllib.error.HTTPError, TimeoutError, OSError, json.JSONDecodeError) as e:
        return {"ok": False, "error": str(e)}

    resultados = []
    for item in datos.get("vulnerabilities", []):
        cve = item.get("cve", {})
        cve_id = cve.get("id", "?")
        descripciones = cve.get("descriptions", [])
        descripcion = next((d["value"] for d in descripciones if d.get("lang") == "en"), "")

        severidad, puntuacion = "?", None
        metrics = cve.get("metrics", {})
        for clave in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
            if clave in metrics and metrics[clave]:
                cvss_data = metrics[clave][0].get("cvssData", {})
                puntuacion = cvss_data.get("baseScore")
                severidad = cvss_data.get("baseSeverity") or metrics[clave][0].get("baseSeverity", "?")
                break

        resultados.append({
            "id": cve_id, "severidad": severidad, "puntuacion": puntuacion,
            "descripcion": (descripcion[:150] + "...") if len(descripcion) > 150 else descripcion,
        })

    return {"ok": True, "total": datos.get("totalResults", len(resultados)), "resultados": resultados}


def auditar_host(ip: str, puertos: list) -> list:
    resultados = []
    for puerto in puertos:
        if puerto in PUERTOS_HTTPS:
            banner = leer_banner_http(ip, puerto, usar_tls=True)
        else:
            # Primero se prueba si el servicio "habla solo" nada mas
            # conectar (SSH, FTP, SMTP...). Si no dice nada en un
            # tiempo corto, es probable que sea HTTP esperando a que
            # el cliente hable primero - se prueba eso como respaldo,
            # sin depender de una lista fija de "puertos HTTP conocidos"
            # (asi tambien funciona en puertos HTTP no estandar).
            banner = leer_banner_crudo(ip, puerto, timeout=1.5)
            if not banner:
                banner = leer_banner_http(ip, puerto, usar_tls=False)

        if banner:
            resultados.append({
                "puerto": puerto, "banner": banner,
                "evaluacion": evaluar_version(banner) or "Sin evaluar (producto no reconocido)",
            })
    return resultados


def main():
    parser = argparse.ArgumentParser(description="Lee versiones anunciadas por los servicios de un host")
    parser.add_argument("ip", help="IP del host a auditar")
    parser.add_argument("--puertos", default="21,22,25,80,443,3306,8080,8443",
                         help="Lista de puertos separados por coma")
    parser.add_argument("--txt", metavar="ARCHIVO", help="Guardar tambien la salida en un archivo de texto")
    parser.add_argument("--cve", action="store_true", help="Consultar el NVD (NIST) por CVEs reales de cada banner detectado (limite ~5 peticiones/30s sin clave de API)")
    args = parser.parse_args()

    puertos = [int(p) for p in args.puertos.split(",")]
    lineas = [f"Auditando versiones en {args.ip} (puertos: {args.puertos})...", ""]
    resultados = auditar_host(args.ip, puertos)

    if not resultados:
        lineas.append("Ningun servicio respondio con un banner identificable en esos puertos.")
    else:
        for r in resultados:
            lineas.append(f"Puerto {r['puerto']}:")
            lineas.append(f"  Banner: {r['banner']}")
            lineas.append(f"  {r['evaluacion']}")

            if args.cve:
                termino = extraer_termino_busqueda(r["banner"])
                cve_info = buscar_cves(termino)
                if not cve_info["ok"]:
                    lineas.append(f"  CVEs (buscado: '{termino}'): no se pudo consultar el NVD ({cve_info['error']})")
                elif cve_info["total"] == 0:
                    lineas.append(f"  CVEs (buscado: '{termino}'): ninguno encontrado en el NVD")
                else:
                    lineas.append(f"  CVEs (buscado: '{termino}', {cve_info['total']} en total, mostrando {len(cve_info['resultados'])}):")
                    for cve in cve_info["resultados"]:
                        punt = f"{cve['puntuacion']}" if cve["puntuacion"] is not None else "?"
                        lineas.append(f"    {cve['id']} - {cve['severidad']} ({punt}) - {cve['descripcion']}")
            lineas.append("")

    salida = "\n".join(lineas)
    print(salida)

    if args.txt:
        with open(args.txt, "w", encoding="utf-8") as f:
            f.write(salida + "\n")
        print(f"Guardado en {args.txt}")


if __name__ == "__main__":
    main()
