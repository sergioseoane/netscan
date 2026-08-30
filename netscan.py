#!/usr/bin/env python3
"""
netscan - escaner de red sencillo para uso personal/homelab.

Que hace:
  1. Lista tus propias interfaces de red y las subredes a las que perteneces.
  2. Barre una subred haciendo ping a cada IP para ver cuales estan
     activas (en uso) y cuales estan libres.
  3. Para cada host activo, comprueba que puertos comunes tiene abiertos
     (escaneo TCP connect, sin privilegios especiales).

Uso:
  python netscan.py --networks                     # ver tus redes locales
  python netscan.py --subnet 192.168.1.0/24         # barrido de hosts
  python netscan.py --subnet 192.168.1.0/24 --ports # + escaneo de puertos
  python netscan.py --subnet 192.168.1.0/24 --ports --json salida.json
"""

import argparse
import ipaddress
import json
import platform
import re
import socket
import struct
import subprocess
import sys
import urllib.error
import urllib.request
from concurrent.futures import ThreadPoolExecutor, as_completed

try:
    import psutil
except ImportError:
    psutil = None

# Puertos TCP mas comunes a comprobar en cada host activo.
# Puedes ampliar esta lista segun lo que te interese vigilar.
COMMON_PORTS = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
    80: "HTTP", 110: "POP3", 143: "IMAP", 443: "HTTPS", 445: "SMB",
    3306: "MySQL", 3389: "RDP", 5432: "PostgreSQL", 8080: "HTTP-alt",
}

IS_WINDOWS = platform.system().lower() == "windows"

# Tabla reducida de prefijos OUI (los 3 primeros bytes de una MAC
# identifican al fabricante). No es la base de datos oficial completa
# del IEEE (tiene decenas de miles de entradas) - es un subconjunto
# de fabricantes muy habituales en una red domestica, suficiente para
# dar contexto util sin depender de descargar un fichero externo.
FABRICANTES_OUI = {
    "3C:5A:B4": "Google", "F4:F5:D8": "Google", "AC:87:A3": "Apple",
    "F0:18:98": "Apple", "A4:83:E7": "Apple", "DC:A6:32": "Raspberry Pi",
    "B8:27:EB": "Raspberry Pi", "E4:5F:01": "Raspberry Pi",
    "00:1A:11": "Google", "F8:0F:41": "TP-Link", "50:C7:BF": "TP-Link",
    "AC:84:C6": "TP-Link", "00:0C:29": "VMware", "00:50:56": "VMware",
    "08:00:27": "VirtualBox", "00:1C:42": "Parallels",
    "3C:D9:2B": "Hewlett Packard", "94:57:A5": "Hewlett Packard",
    "00:15:5D": "Microsoft (Hyper-V)", "00:1D:D8": "Microsoft",
    "18:66:DA": "Dell", "F8:BC:12": "Dell", "D4:81:D7": "Dell",
    "3C:52:82": "Intel", "00:1B:21": "Intel", "A4:C3:F0": "Intel",
    "CC:46:D6": "Cisco", "00:1A:A1": "Cisco", "00:26:99": "Samsung",
    "5C:0A:5B": "Samsung", "8C:79:F5": "Samsung", "68:9C:70": "Amazon",
    "FC:65:DE": "Amazon", "18:FE:34": "Espressif (IoT/ESP)",
    "CC:50:E3": "Espressif (IoT/ESP)", "24:6F:28": "Espressif (IoT/ESP)",
    "B0:BE:76": "Xiaomi", "78:11:DC": "Xiaomi",
}


def resolver_hostname(ip: str, timeout: float = 1.0) -> str:
    """Intenta averiguar el nombre de un dispositivo a partir de su IP
    (DNS inverso). Devuelve None si no se puede resolver - es normal
    que muchos dispositivos domesticos (moviles, IoT) no respondan."""
    socket.setdefaulttimeout(timeout)
    try:
        nombre, _, _ = socket.gethostbyaddr(ip)
        # En Windows, gethostbyaddr a veces devuelve la propia IP como
        # si fuera un "nombre" en vez de lanzar un error cuando no hay
        # un DNS inverso real - eso no es informacion util, se descarta.
        if nombre == ip:
            return None
        return nombre
    except (socket.herror, socket.gaierror, socket.timeout):
        return None
    finally:
        socket.setdefaulttimeout(None)


def resolver_hostnames_paralelo(ips: list, timeout: float = 1.0) -> dict:
    """Resuelve el hostname de varias IPs a la vez, en paralelo - igual
    que ping_host/scan_ports. Sin esto, con varios dispositivos que no
    respondan a DNS inverso (movil, IoT), la espera se suma en serie
    (varios segundos), rompiendo la logica de "todo en paralelo" del
    resto del programa."""
    resultado = {}
    with ThreadPoolExecutor(max_workers=min(50, len(ips) or 1)) as pool:
        futures = {pool.submit(resolver_hostname, ip, timeout): ip for ip in ips}
        for future in as_completed(futures):
            ip = futures[future]
            resultado[ip] = future.result()
    return resultado


def obtener_tabla_arp() -> dict:
    """Lee la tabla ARP del sistema (IP -> MAC) para los dispositivos
    con los que ya se ha hablado recientemente (por eso conviene hacer
    ping antes de leerla: sin trafico previo, muchas IPs no aparecen
    todavia en la tabla ARP del sistema operativo)."""
    resultado = {}
    try:
        if IS_WINDOWS:
            salida = subprocess.run(
                ["arp", "-a"], capture_output=True, text=True, timeout=5
            ).stdout
            # Formato Windows: "  192.168.1.1          aa-bb-cc-dd-ee-ff     dinamico"
            patron = re.compile(
                r"(\d+\.\d+\.\d+\.\d+)\s+([0-9a-fA-F]{2}(?:-[0-9a-fA-F]{2}){5})"
            )
            for ip, mac in patron.findall(salida):
                resultado[ip] = mac.upper().replace("-", ":")
        else:
            salida = subprocess.run(
                ["ip", "neigh"], capture_output=True, text=True, timeout=5
            ).stdout
            # Formato Linux: "192.168.1.1 dev eth0 lladdr aa:bb:cc:dd:ee:ff REACHABLE"
            patron = re.compile(
                r"(\d+\.\d+\.\d+\.\d+).*?lladdr\s+([0-9a-fA-F]{2}(?::[0-9a-fA-F]{2}){5})"
            )
            for ip, mac in patron.findall(salida):
                resultado[ip] = mac.upper()
    except (subprocess.SubprocessError, FileNotFoundError, OSError):
        pass
    return resultado


def obtener_mis_macs() -> dict:
    """Devuelve {ip_propia: mac_propia} de tus propias interfaces.
    Hace falta por separado porque un equipo nunca aparece en su
    propia tabla ARP (no necesita 'preguntarse' su propia MAC) - sin
    esto, tu propia fila del escaneo saldria siempre sin MAC, aunque
    el resto de dispositivos si la tengan."""
    resultado = {}
    if psutil is None:
        return resultado
    for iface, addrs in psutil.net_if_addrs().items():
        ip_iface = None
        mac_iface = None
        for addr in addrs:
            if addr.family == socket.AF_INET and not addr.address.startswith("127."):
                ip_iface = addr.address
            elif addr.family == psutil.AF_LINK and addr.address:
                mac_iface = addr.address.upper().replace("-", ":")
        if ip_iface and mac_iface and len(mac_iface) == 17:
            resultado[ip_iface] = mac_iface
    return resultado


def fabricante_por_mac(mac: str) -> str:
    """Busca el fabricante a partir de los 3 primeros bytes de la MAC."""
    if not mac:
        return None
    prefijo = mac.upper()[:8]  # "AA:BB:CC"
    return FABRICANTES_OUI.get(prefijo, "Desconocido")


def es_mac_aleatoria(mac: str) -> bool:
    """Detecta si una MAC es aleatoria/privada (la genera el propio
    dispositivo, no viene grabada de fabrica). Se sabe mirando el
    segundo bit del primer byte ('bit administrado localmente') - si
    esta a 1, la MAC no es la real de fabrica. iOS y Android generan
    una MAC de este tipo distinta para cada red WiFi, por privacidad,
    desde hace varios años - por eso nunca se encontrara fabricante
    para estas, ni en la tabla local ni en linea, y no es un fallo."""
    if not mac:
        return False
    try:
        primer_byte = int(mac.split(":")[0], 16)
    except (ValueError, IndexError):
        return False
    return bool(primer_byte & 0b00000010)


def fabricante_por_mac_online(mac: str, timeout: float = 2.0) -> str:
    """Respaldo online cuando la tabla local (corta, ~15 fabricantes) no
    encuentra la MAC: consulta la API publica y gratuita de macvendors.com,
    que si tiene la base de datos oficial completa del IEEE.

    AVISO DE PRIVACIDAD: esto envia la direccion MAC del dispositivo a un
    servicio externo por internet. Por eso es una funcion APARTE, que solo
    se activa explicitamente con --online (nunca por defecto) - un escaner
    de tu propia red domestica no deberia mandar datos fuera sin que lo
    pidas tu mismo.

    No se ha podido probar esta llamada de verdad en el entorno donde se
    escribio este codigo (sin salida a ese dominio concreto) - se ha
    escrito siguiendo el formato documentado de la API, pero conviene
    confirmar que responde como se espera en tu propia maquina.
    """
    try:
        url = f"https://api.macvendors.com/{mac}"
        with urllib.request.urlopen(url, timeout=timeout) as resp:
            return resp.read().decode("utf-8").strip()
    except (urllib.error.URLError, urllib.error.HTTPError, TimeoutError, OSError):
        return None


def enviar_wol(mac: str, broadcast_ip: str = "255.255.255.255", port: int = 9) -> bool:
    """Envia un 'paquete magico' de Wake-on-LAN para encender remotamente
    un equipo apagado, a partir de su direccion MAC.

    El paquete tiene un formato fijo y muy simple: 6 bytes a 0xFF,
    seguidos de la MAC de destino repetida 16 veces (102 bytes en
    total) - cualquier tarjeta de red con WoL activado que vea ese
    patron especifico en un paquete UDP se enciende, sin necesitar
    que el sistema operativo este arrancado para recibirlo.

    Requisito para que funcione de verdad (no depende de este script):
    el equipo de destino debe tener Wake-on-LAN activado en la BIOS/
    UEFI y en las propiedades de su adaptador de red.
    """
    mac_limpia = re.sub(r"[^0-9a-fA-F]", "", mac)
    if len(mac_limpia) != 12:
        raise ValueError(f"MAC invalida: '{mac}' (deben ser 12 caracteres hexadecimales)")

    mac_bytes = bytes.fromhex(mac_limpia)
    paquete = b"\xff" * 6 + mac_bytes * 16

    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        s.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        s.sendto(paquete, (broadcast_ip, port))
    return True


def diagnostico_conectividad() -> list:
    """Diagnostico en cascada, igual que el que haria un tecnico de
    soporte a mano: puerta de enlace -> DNS -> Internet. Cada paso
    devuelve OK/FALLA con un mensaje, para saber exactamente en que
    punto de la cadena esta el problema, no solo "no hay red"."""
    pasos = []

    # 1. Puerta de enlace
    gateway = _obtener_puerta_enlace()
    if gateway:
        ok = ping_host(gateway, timeout_ms=1000)
        pasos.append({
            "paso": "Puerta de enlace",
            "detalle": gateway,
            "ok": ok,
            "mensaje": "Responde correctamente" if ok else "No responde - revisa el cable/WiFi o el propio router",
        })
    else:
        pasos.append({"paso": "Puerta de enlace", "detalle": None, "ok": False,
                       "mensaje": "No se ha podido determinar la puerta de enlace"})
        return pasos  # sin gateway, no tiene sentido seguir

    # 2. DNS
    try:
        socket.setdefaulttimeout(2)
        socket.gethostbyname("www.google.com")
        pasos.append({"paso": "Resolución DNS", "detalle": "www.google.com", "ok": True,
                       "mensaje": "El DNS resuelve nombres correctamente"})
    except (socket.gaierror, socket.timeout):
        pasos.append({"paso": "Resolución DNS", "detalle": "www.google.com", "ok": False,
                       "mensaje": "No resuelve nombres - revisa el DNS configurado (router o manual)"})
    finally:
        socket.setdefaulttimeout(None)

    # 3. Internet real (más allá del router)
    ok_internet = ping_host("1.1.1.1", timeout_ms=1500)
    pasos.append({"paso": "Salida a Internet", "detalle": "1.1.1.1", "ok": ok_internet,
                   "mensaje": "Hay salida real a Internet" if ok_internet else "No llega a Internet - el problema está más allá del router (ISP)"})

    return pasos


def _obtener_puerta_enlace() -> str:
    """Obtiene la puerta de enlace por defecto, sin depender de librerias
    externas - se apoya en la utilidad de red propia del sistema."""
    try:
        if IS_WINDOWS:
            salida = subprocess.run(["ipconfig"], capture_output=True, text=True, timeout=5).stdout
            m = re.search(r"Puerta de enlace predeterminada[.\s]*:\s*([\d.]+)", salida)
            if not m:
                # Version en ingles, por si el sistema esta en otro idioma
                m = re.search(r"Default Gateway[.\s]*:\s*([\d.]+)", salida)
            return m.group(1) if m and m.group(1) else None
        else:
            salida = subprocess.run(["ip", "route"], capture_output=True, text=True, timeout=5).stdout
            m = re.search(r"default via (\d+\.\d+\.\d+\.\d+)", salida)
            return m.group(1) if m else None
    except (subprocess.SubprocessError, FileNotFoundError, OSError):
        return None


def ping_host(ip: str, timeout_ms: int = 500) -> bool:
    """Hace un solo ping a la IP indicada. Devuelve True si responde."""
    if IS_WINDOWS:
        cmd = ["ping", "-n", "1", "-w", str(timeout_ms), str(ip)]
    else:
        cmd = ["ping", "-c", "1", "-W", str(max(1, timeout_ms // 1000)), str(ip)]

    result = subprocess.run(
        cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
    )
    return result.returncode == 0


def ping_con_ttl(ip: str, timeout_ms: int = 500):
    """Como ping_host, pero ademas devuelve el TTL de la respuesta -
    se usa para estimar el sistema operativo (ver estimar_so_por_ttl)."""
    if IS_WINDOWS:
        cmd = ["ping", "-n", "1", "-w", str(timeout_ms), str(ip)]
    else:
        cmd = ["ping", "-c", "1", "-W", str(max(1, timeout_ms // 1000)), str(ip)]

    result = subprocess.run(cmd, capture_output=True, text=True)
    if result.returncode != 0:
        return False, None

    # Windows: "TTL=64"   /   Linux: "ttl=64"
    m = re.search(r"[Tt][Tt][Ll][=:]\s*(\d+)", result.stdout)
    ttl = int(m.group(1)) if m else None
    return True, ttl


def estimar_so_por_ttl(ttl: int) -> str:
    """Estimacion (NO certeza) del sistema operativo a partir del TTL
    inicial tipico de cada uno. Cada salto de red resta 1 al TTL, asi
    que en una red local el valor observado suele estar muy cerca del
    inicial. Es una tecnica real de reconocimiento de redes, pero
    orientativa: se puede falsificar, y algunos sistemas la cambian."""
    if ttl is None:
        return None
    if ttl > 128:
        return "Dispositivo de red / Cisco / Solaris (TTL inicial ~255)"
    if ttl > 64:
        return "Windows (TTL inicial ~128)"
    return "Linux / macOS / Android / iOS (TTL inicial ~64)"


def scan_subnet(subnet: str, max_workers: int = 50):
    """Barre todas las IPs de una subred en paralelo. Devuelve (activas, libres)."""
    network = ipaddress.ip_network(subnet, strict=False)
    hosts = list(network.hosts())

    active = []
    with ThreadPoolExecutor(max_workers=max_workers) as pool:
        future_to_ip = {pool.submit(ping_host, ip): ip for ip in hosts}
        for future in as_completed(future_to_ip):
            ip = future_to_ip[future]
            if future.result():
                active.append(str(ip))

    active_set = set(active)
    free = [str(ip) for ip in hosts if str(ip) not in active_set]
    return sorted(active, key=ipaddress.ip_address), sorted(free, key=ipaddress.ip_address)


def scan_ports(ip: str, ports: dict = COMMON_PORTS, timeout: float = 0.5) -> list:
    """Comprueba, uno a uno, si cada puerto de la lista esta abierto en esa IP."""
    open_ports = []

    def check(port):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            if s.connect_ex((ip, port)) == 0:
                return port
        return None

    with ThreadPoolExecutor(max_workers=len(ports)) as pool:
        futures = {pool.submit(check, p): p for p in ports}
        for future in as_completed(futures):
            port = future.result()
            if port:
                open_ports.append(port)

    return sorted(open_ports)


def list_local_networks() -> list:
    """Lista las interfaces de red locales y a que subred pertenece cada una."""
    if psutil is None:
        print("Necesitas instalar psutil: pip install psutil", file=sys.stderr)
        return []

    results = []
    for iface, addrs in psutil.net_if_addrs().items():
        for addr in addrs:
            if addr.family == socket.AF_INET and not addr.address.startswith("127."):
                try:
                    net = ipaddress.ip_network(
                        f"{addr.address}/{addr.netmask}", strict=False
                    )
                except ValueError:
                    continue
                results.append(
                    {"interface": iface, "ip": addr.address, "network": str(net)}
                )
    return results


def agrupar_en_rangos(ips: list) -> list:
    """Agrupa una lista de IPs consecutivas en tramos continuos.
    Ej: [.2, .3, .4, .7, .8] -> [(.2, .4), (.7, .8)]
    Evita el error de mostrar solo "primera .. ultima", que es
    enganoso si hay huecos (IPs activas) en medio del rango."""
    if not ips:
        return []

    ips_ordenadas = sorted(ips, key=ipaddress.ip_address)
    rangos = []
    inicio = ips_ordenadas[0]
    anterior = ips_ordenadas[0]

    for ip in ips_ordenadas[1:]:
        if int(ipaddress.ip_address(ip)) == int(ipaddress.ip_address(anterior)) + 1:
            anterior = ip
        else:
            rangos.append((inicio, anterior))
            inicio = ip
            anterior = ip
    rangos.append((inicio, anterior))
    return rangos


def print_table(rows: list, headers: list):
    """Tabla en texto plano, sin dependencias externas."""
    widths = [
        max(len(str(h)), max((len(str(r.get(h, ""))) for r in rows), default=0))
        for h in headers
    ]
    line = "  ".join(h.ljust(w) for h, w in zip(headers, widths))
    print(line)
    print("-" * len(line))
    for row in rows:
        print("  ".join(str(row.get(h, "")).ljust(w) for h, w in zip(headers, widths)))


def main():
    parser = argparse.ArgumentParser(description="Escaner de red para homelab")
    parser.add_argument("--networks", action="store_true", help="Listar tus redes locales")
    parser.add_argument("--subnet", help="Subred a escanear, ej. 192.168.1.0/24")
    parser.add_argument("--ports", action="store_true", help="Escanear puertos comunes en los hosts activos")
    parser.add_argument("--info", action="store_true", help="Resolver hostname y fabricante (MAC) de cada host activo")
    parser.add_argument("--online", action="store_true", help="Si el fabricante no esta en la tabla local, consultarlo en macvendors.com (envia la MAC a un servicio externo)")
    parser.add_argument("--os", action="store_true", help="Estimar el sistema operativo de cada host activo, a partir del TTL del ping (orientativo, no una certeza)")
    parser.add_argument("--json", metavar="ARCHIVO", help="Guardar el resultado en un archivo JSON")
    parser.add_argument("--wol", metavar="MAC", help="Enviar un paquete Wake-on-LAN a esta MAC (ej. AA:BB:CC:DD:EE:FF)")
    parser.add_argument("--check-internet", action="store_true", help="Diagnostico en cascada: puerta de enlace -> DNS -> Internet")
    args = parser.parse_args()

    result = {}

    if args.networks:
        networks = list_local_networks()
        print(f"\n=== Tus redes locales ===")
        print_table(networks, ["interface", "ip", "network"])
        result["local_networks"] = networks

    if args.subnet:
        print(f"\n=== Barriendo {args.subnet} (esto puede tardar un poco) ===")
        active, free = scan_subnet(args.subnet)
        print(f"\nIPs activas ({len(active)}):")
        info_extra = {}
        if args.info:
            tabla_arp = obtener_tabla_arp()
            mis_macs = obtener_mis_macs()
            hostnames = resolver_hostnames_paralelo(active)
            for ip in active:
                es_mi_equipo = ip in mis_macs
                mac = mis_macs.get(ip) or tabla_arp.get(ip)

                if mac and es_mac_aleatoria(mac) and not es_mi_equipo:
                    fabricante = "MAC aleatoria (privacidad - iOS/Android en esta red, no es de fábrica)"
                elif mac:
                    fabricante = fabricante_por_mac(mac)
                    if fabricante == "Desconocido" and args.online:
                        fabricante = fabricante_por_mac_online(mac) or "Desconocido (tampoco en línea)"
                else:
                    fabricante = None

                so_estimado = None
                if args.os:
                    _, ttl = ping_con_ttl(ip)
                    so_estimado = estimar_so_por_ttl(ttl)

                info_extra[ip] = {
                    "hostname": ("Este equipo" if es_mi_equipo else hostnames.get(ip)),
                    "mac": mac,
                    "fabricante": fabricante,
                    "so_estimado": so_estimado,
                }

        if args.info:
            filas = []
            for ip in active:
                extra = info_extra.get(ip, {})
                fila = {
                    "ip": ip,
                    "hostname": extra.get("hostname") or "",
                    "mac": extra.get("mac") or "",
                    "fabricante": extra.get("fabricante") or "",
                }
                if args.os:
                    fila["so_estimado"] = extra.get("so_estimado") or ""
                filas.append(fila)
            columnas = ["ip", "hostname", "mac", "fabricante"]
            if args.os:
                columnas.append("so_estimado")
            print_table(filas, columnas)
        else:
            for ip in active:
                print(f"  {ip}")

        print(f"\nIPs libres ({len(free)}):")
        if free:
            for inicio, fin in agrupar_en_rangos(free):
                if inicio == fin:
                    print(f"  {inicio}")
                else:
                    print(f"  {inicio} - {fin}")
        else:
            print("  (ninguna)")

        result["subnet"] = args.subnet
        result["active_ips"] = active
        result["free_ips"] = free
        if args.info:
            result["info_extra"] = info_extra

        if args.ports and active:
            print(f"\n=== Puertos abiertos en hosts activos ===")
            port_results = {}
            for ip in active:
                open_ports = scan_ports(ip)
                port_results[ip] = [
                    {"port": p, "service": COMMON_PORTS.get(p, "?")} for p in open_ports
                ]
                if open_ports:
                    labels = ", ".join(f"{p}/{COMMON_PORTS.get(p, '?')}" for p in open_ports)
                    print(f"  {ip}: {labels}")
                else:
                    print(f"  {ip}: (ninguno de los comunes)")
            result["open_ports"] = port_results

    if not args.networks and not args.subnet and not args.wol and not args.check_internet:
        parser.print_help()
        return

    if args.wol:
        try:
            enviar_wol(args.wol)
            print(f"Paquete Wake-on-LAN enviado a {args.wol}")
        except ValueError as e:
            print(f"Error: {e}", file=sys.stderr)
            sys.exit(1)

    if args.check_internet:
        print("\n=== Diagnóstico de conectividad ===")
        pasos = diagnostico_conectividad()
        for paso in pasos:
            estado = "OK" if paso["ok"] else "FALLA"
            detalle = f" ({paso['detalle']})" if paso["detalle"] else ""
            print(f"  [{estado}] {paso['paso']}{detalle}: {paso['mensaje']}")
        result["diagnostico_conectividad"] = pasos

    if args.json:
        with open(args.json, "w", encoding="utf-8") as f:
            json.dump(result, f, indent=2, ensure_ascii=False)
        print(f"\nResultado guardado en {args.json}")


if __name__ == "__main__":
    main()
