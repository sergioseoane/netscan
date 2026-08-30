#!/usr/bin/env python3
"""
audit_comparador.py - guarda un "inventario conocido" de tu red y, en
cada ejecucion posterior, avisa de que ha cambiado: dispositivos
nuevos, dispositivos que ya no responden, o que han cambiado de IP.

Reutiliza netscan.py (mismo motor de escaneo), no duplica logica.

Uso:
  python audit_comparador.py --subnet 192.168.1.0/24 --guardar
  python audit_comparador.py --subnet 192.168.1.0/24
"""

import argparse
import json
import os
import sys
from datetime import datetime, timezone

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
import netscan

ARCHIVO_LINEA_BASE_DEFECTO = os.path.join(os.path.dirname(__file__), "linea_base.json")


def escanear_estado_actual(subnet: str) -> dict:
    """Barre la subred y arma un diccionario {mac: {ip, hostname}} -
    se indexa por MAC, no por IP, porque la IP puede cambiar (DHCP)
    pero la MAC identifica al mismo dispositivo fisico."""
    active, _ = netscan.scan_subnet(subnet)
    tabla_arp = netscan.obtener_tabla_arp()
    mis_macs = netscan.obtener_mis_macs()
    hostnames = netscan.resolver_hostnames_paralelo(active)

    dispositivos = {}
    for ip in active:
        mac = mis_macs.get(ip) or tabla_arp.get(ip)
        if not mac:
            # Sin MAC no se puede identificar el dispositivo de forma
            # fiable entre ejecuciones (la IP sola no basta, cambia con DHCP)
            continue
        dispositivos[mac] = {"ip": ip, "hostname": hostnames.get(ip) or ""}
    return dispositivos


def cargar_linea_base(archivo: str) -> dict:
    if not os.path.exists(archivo):
        return {}
    with open(archivo, encoding="utf-8") as f:
        return json.load(f).get("dispositivos", {})


def guardar_linea_base(archivo: str, dispositivos: dict):
    with open(archivo, "w", encoding="utf-8") as f:
        json.dump({
            "guardado_en": datetime.now(timezone.utc).isoformat(),
            "dispositivos": dispositivos,
        }, f, indent=2, ensure_ascii=False)


def comparar(base: dict, actual: dict) -> dict:
    macs_base = set(base.keys())
    macs_actual = set(actual.keys())

    nuevos = macs_actual - macs_base
    desaparecidos = macs_base - macs_actual
    cambiados_ip = {
        mac for mac in (macs_base & macs_actual)
        if base[mac]["ip"] != actual[mac]["ip"]
    }

    return {"nuevos": nuevos, "desaparecidos": desaparecidos, "cambiados_ip": cambiados_ip}


def main():
    parser = argparse.ArgumentParser(description="Compara el estado de la red contra una linea base guardada")
    parser.add_argument("--subnet", required=True, help="Subred a auditar, ej. 192.168.1.0/24")
    parser.add_argument("--guardar", action="store_true", help="Guardar el estado actual como nueva linea base (no compara)")
    parser.add_argument("--archivo", default=ARCHIVO_LINEA_BASE_DEFECTO, help="Ruta del archivo de linea base")
    parser.add_argument("--txt", metavar="ARCHIVO", help="Guardar tambien el resultado de la comparacion en un archivo de texto")
    args = parser.parse_args()

    print(f"Escaneando {args.subnet}...")
    actual = escanear_estado_actual(args.subnet)

    if args.guardar or not os.path.exists(args.archivo):
        guardar_linea_base(args.archivo, actual)
        print(f"Linea base guardada en {args.archivo} ({len(actual)} dispositivos con MAC identificada).")
        return

    base = cargar_linea_base(args.archivo)
    diff = comparar(base, actual)
    hubo_cambios = any(diff.values())

    lineas = [f"Comparacion de red - {args.subnet}", ""]
    if not hubo_cambios:
        lineas.append("Sin cambios respecto a la linea base. Todo en orden.")
    else:
        if diff["nuevos"]:
            lineas.append(f"[NUEVO] {len(diff['nuevos'])} dispositivo(s) que no estaban en la linea base:")
            for mac in diff["nuevos"]:
                d = actual[mac]
                lineas.append(f"  {d['ip']}  {mac}  {d['hostname']}")
            lineas.append("")
        if diff["desaparecidos"]:
            lineas.append(f"[DESAPARECIDO] {len(diff['desaparecidos'])} dispositivo(s) que ya no responden:")
            for mac in diff["desaparecidos"]:
                d = base[mac]
                lineas.append(f"  {d['ip']}  {mac}  {d['hostname']}")
            lineas.append("")
        if diff["cambiados_ip"]:
            lineas.append(f"[CAMBIO DE IP] {len(diff['cambiados_ip'])} dispositivo(s):")
            for mac in diff["cambiados_ip"]:
                lineas.append(f"  {mac}: {base[mac]['ip']} -> {actual[mac]['ip']}")

    salida = "\n".join(lineas)
    print(salida)

    if args.txt:
        with open(args.txt, "w", encoding="utf-8") as f:
            f.write(salida + "\n")
        print(f"\nGuardado en {args.txt}")

    sys.exit(1 if hubo_cambios else 0)


if __name__ == "__main__":
    main()
