#!/usr/bin/env python3
"""
audit_certificados.py - comprueba cuantos dias quedan para que caduque
el certificado SSL/TLS de uno o varios servicios HTTPS.

Uso:
  python audit_certificados.py sergioseoane.com
  python audit_certificados.py sergioseoane.com github.com 192.168.1.10
  python audit_certificados.py --archivo hosts.txt
"""

import argparse
import socket
import ssl
import sys
from datetime import datetime, timezone

AVISO_DIAS = 30
CRITICO_DIAS = 7


def comprobar_certificado(host: str, puerto: int = 443, timeout: float = 5.0) -> dict:
    """Se conecta por TLS, sin descargar nada del sitio (solo el
    'apreton de manos' inicial), y lee la fecha de caducidad real del
    certificado que presenta el servidor."""
    contexto = ssl.create_default_context()
    try:
        with socket.create_connection((host, puerto), timeout=timeout) as sock:
            with contexto.wrap_socket(sock, server_hostname=host) as ssock:
                cert = ssock.getpeercert()
    except (socket.timeout, socket.gaierror, ConnectionRefusedError, OSError) as e:
        return {"host": host, "ok": False, "error": str(e)}
    except ssl.SSLCertVerificationError as e:
        return {"host": host, "ok": False, "error": f"Certificado no valido: {e}"}

    fecha_fin = datetime.strptime(cert["notAfter"], "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
    dias_restantes = (fecha_fin - datetime.now(timezone.utc)).days

    if dias_restantes < 0:
        estado = "CADUCADO"
    elif dias_restantes <= CRITICO_DIAS:
        estado = "CRITICO"
    elif dias_restantes <= AVISO_DIAS:
        estado = "AVISO"
    else:
        estado = "OK"

    return {
        "host": host, "ok": True, "estado": estado,
        "dias_restantes": dias_restantes,
        "caduca_el": fecha_fin.strftime("%Y-%m-%d"),
        "emisor": dict(x[0] for x in cert.get("issuer", [])).get("organizationName", "?"),
    }


def main():
    parser = argparse.ArgumentParser(description="Comprueba la caducidad de certificados SSL/TLS")
    parser.add_argument("hosts", nargs="*", help="Uno o varios hosts a comprobar (ej. midominio.com)")
    parser.add_argument("--archivo", help="Archivo de texto con un host por linea")
    parser.add_argument("--puerto", type=int, default=443, help="Puerto HTTPS (por defecto 443)")
    parser.add_argument("--txt", metavar="ARCHIVO", help="Guardar tambien la salida en un archivo de texto")
    args = parser.parse_args()

    hosts = list(args.hosts)
    if args.archivo:
        with open(args.archivo, encoding="utf-8") as f:
            hosts += [linea.strip() for linea in f if linea.strip() and not linea.startswith("#")]

    if not hosts:
        parser.print_help()
        sys.exit(1)

    lineas = []
    lineas.append(f"{'Host':<30}{'Estado':<10}{'Dias':<8}{'Caduca el':<14}{'Emisor'}")
    lineas.append("-" * 90)

    hubo_problema = False
    for host in hosts:
        r = comprobar_certificado(host, args.puerto)
        if not r["ok"]:
            lineas.append(f"{host:<30}{'ERROR':<10}{'':<8}{'':<14}{r['error']}")
            hubo_problema = True
            continue
        lineas.append(f"{r['host']:<30}{r['estado']:<10}{r['dias_restantes']:<8}{r['caduca_el']:<14}{r['emisor']}")
        if r["estado"] in ("CRITICO", "CADUCADO"):
            hubo_problema = True

    salida = "\n".join(lineas)
    print(salida)

    if args.txt:
        with open(args.txt, "w", encoding="utf-8") as f:
            f.write(salida + "\n")
        print(f"\nGuardado en {args.txt}")

    sys.exit(1 if hubo_problema else 0)


if __name__ == "__main__":
    main()
