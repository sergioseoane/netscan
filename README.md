# netscan

Escáner de red en Python para uso personal/homelab. Sin dependencias de herramientas externas como `nmap` — solo Python estándar más `psutil` para leer las interfaces de red.

## Qué hace

- **Detecta tus redes locales**: qué interfaces tienes y a qué subred pertenece cada una.
- **Barrido de host activos/libres**: dado un rango (ej. `192.168.1.0/24`), hace ping a cada IP en paralelo para saber cuáles están en uso y cuáles libres — útil para asignar una IP fija sin chocar con nada. Los tramos libres se muestran agrupados en rangos reales (ej. `.2 - .128`), no como un único rango de punta a punta que ocultaría huecos donde hay IPs activas en medio.
- **Escaneo de puertos comunes**: para cada host activo, comprueba (con un connect TCP normal, sin privilegios especiales) si tiene abiertos puertos habituales (SSH, HTTP, RDP, bases de datos, etc.).
- **Identificación de dispositivos** (`--info`): resuelve el nombre de host (DNS inverso) y el fabricante a partir de la MAC (tabla de prefijos OUI de fabricantes habituales en redes domésticas) — para saber "esto es un Raspberry Pi" en vez de solo ver una IP suelta. Como la tabla local es corta, si un fabricante no aparece ahí sale como "Desconocido" — para esos casos existe `--online` (ver abajo).
- **Búsqueda de fabricante en línea** (`--online`, opcional, **nunca activado por defecto**): si la tabla local no reconoce una MAC, consulta la API pública y gratuita de `macvendors.com`, que sí tiene la base de datos oficial completa. Al activarla, tu dirección MAC se envía a ese servicio externo por internet — por eso es una opción explícita, no algo que un escáner de tu propia red debería hacer sin que tú lo pidas.
- **Wake-on-LAN** (`--wol MAC`): enciende remotamente un equipo apagado enviándole un "paquete mágico" — construido y verificado byte a byte (6 bytes `0xFF` + la MAC repetida 16 veces = 102 bytes exactos). Requiere que el equipo de destino tenga Wake-on-LAN activado en la BIOS/UEFI y en su adaptador de red.
- **Diagnóstico de conectividad** (`--check-internet`): la misma secuencia que haría un técnico de soporte a mano — ¿responde la puerta de enlace? → ¿resuelve DNS? → ¿hay salida real a Internet? — cada paso identifica exactamente dónde se corta la cadena, en vez de un genérico "no hay red".
- **Detección de "Este equipo"**: tu propia IP se identifica y etiqueta aparte, con tu MAC real (obtenida de tus propias interfaces, no de la tabla ARP — un equipo nunca aparece en su propia tabla ARP, por eso hace falta un método distinto).
- **Detección de MAC aleatoria/privada** (`--info`): identifica cuándo una MAC no es de fábrica sino generada al azar por privacidad (la técnica que usan iOS/Android desde hace años en redes WiFi), en vez de mostrar un simple "Desconocido" sin explicación — se detecta por el bit "administrado localmente" del primer byte, no por prueba y error.
- **Estimación de sistema operativo por TTL** (`--os`, orientativo, no una certeza): a partir del TTL de la respuesta al ping (Linux/macOS/Android arrancan en 64, Windows en 128, muchos dispositivos de red en 255), da una estimación razonable de qué tipo de sistema hay detrás de cada IP — una técnica real de reconocimiento de redes, aunque no infalible.
- **Exportación a JSON**: para guardar el resultado y compararlo con un barrido anterior, o procesarlo con otra herramienta.

## Dos formas de usarlo: terminal o interfaz gráfica

### Por comandos (`netscan.py`)

```bash
pip install -r requirements.txt

python netscan.py --networks
python netscan.py --subnet 192.168.1.0/24
python netscan.py --subnet 192.168.1.0/24 --ports --info
python netscan.py --subnet 192.168.1.0/24 --ports --json resultado.json
```

### Con ventana (`netscan_gui.py`)

```bash
python netscan_gui.py
```

Misma lógica de escaneo por debajo (reutiliza las funciones de
`netscan.py`, no hay código duplicado) — organizada en cuatro pestañas,
detalladas más abajo. El escaneo corre en un hilo aparte para que la
ventana no se quede congelada mientras tarda.

### Convertirlo en un .exe instalable (Windows)

Para que cualquiera pueda ejecutarlo con doble clic, sin tener Python
instalado:

```bash
pip install pyinstaller
pyinstaller --onefile --windowed --name netscan netscan_gui.py
```

El ejecutable queda en `dist/netscan.exe`. `--windowed` evita que se
abra una consola negra detrás de la ventana; `--onefile` empaqueta
todo en un único archivo, fácil de compartir.

## Por qué está hecho así

- El barrido de hosts y el escaneo de puertos van **en paralelo** (con `ThreadPoolExecutor`), no uno a uno — barrer una subred /24 (254 IPs) de una en una tardaría varios minutos; en paralelo, segundos.
- El ping se hace llamando al comando `ping` del sistema operativo (detectando si estás en Windows o Linux y ajustando los parámetros), en vez de sockets ICMP en crudo — así funciona sin permisos de administrador/root.
- El escaneo de puertos es un **connect scan** normal (abrir y cerrar la conexión TCP), no un escaneo SYN a bajo nivel — es más lento que herramientas como `nmap`, pero no requiere privilegios especiales ni librerías extra como `scapy`.

## Referencia rápida de comandos

```bash
# Ver tus redes locales
python netscan.py --networks

# Barrer una subred (hosts activos y libres)
python netscan.py --subnet 192.168.1.0/24

# Barrer + escanear puertos comunes en los hosts activos
python netscan.py --subnet 192.168.1.0/24 --ports

# Barrer + identificar hostname/fabricante de cada host activo
python netscan.py --subnet 192.168.1.0/24 --info

# Igual, y si un fabricante no esta en la tabla local, buscarlo tambien
# en macvendors.com (envia esa MAC a un servicio externo)
python netscan.py --subnet 192.168.1.0/24 --info --online

# Guardar el resultado en JSON
python netscan.py --subnet 192.168.1.0/24 --ports --info --json resultado.json

# Encender remotamente un equipo por Wake-on-LAN
python netscan.py --wol AA:BB:CC:DD:EE:FF

# Diagnostico de conectividad: puerta de enlace -> DNS -> Internet
python netscan.py --check-internet

# Estimar el sistema operativo de cada host activo (orientativo, via TTL)
python netscan.py --subnet 192.168.1.0/24 --info --os
```

## Interfaz gráfica: cuatro pestañas.

```bash
python netscan_gui.py
```

- **Escanear red**: igual que por comandos. Clic derecho sobre una
  fila con MAC detectada para enviarle un Wake-on-LAN directamente.
- **Redes locales**: tus interfaces en una tabla dentro de la propia
  pestaña (se carga sola al abrirla) — nada de diálogos aparte.
- **Herramientas**: Wake-on-LAN (MAC + IP de broadcast) y el
  diagnóstico de conectividad, con resultados en verde/rojo.
- **Auditoría**: los scripts de `auditoria/` con botones — cada uno
  en su propia sub-pestaña (Certificados, Comparador, Versiones,
  Informe semanal, Programar), corriendo en un hilo aparte para no
  congelar la ventana. El informe semanal se puede abrir directamente
  en el navegador desde un botón, sin salir de la aplicación.

## Limitaciones conocidas

- Algunos dispositivos (routers, firewalls) pueden estar configurados para no responder a ping aunque estén activos — en ese caso aparecerían como "libres" sin estarlo. Es una limitación del propio ICMP, no del script.
- El escaneo de puertos solo comprueba TCP, no UDP.
- La tabla de fabricantes (`--info`) es un subconjunto reducido de prefijos OUI habituales en redes domésticas, no la base de datos oficial completa del IEEE (que tiene decenas de miles de entradas) — un dispositivo real puede aparecer como "Desconocido" simplemente porque su fabricante no está en esta lista corta. Para esos casos existe `--online`, respaldado en la API pública de macvendors.com (no se ha podido probar esta llamada concreta en el entorno donde se escribió el código, por no tener salida a ese dominio — confirma que responde bien en tu propia máquina).
- En Windows, `gethostbyaddr` a veces devuelve la propia IP como si fuera un "hostname" real cuando no hay DNS inverso configurado, en vez de dar un error como hace Linux — el script filtra ese caso y lo trata como "no resuelto", para no mostrar información falsa.
- El Wake-on-LAN solo envía el paquete: no hay forma de confirmar desde el script si el equipo se ha encendido de verdad, ya que por definición está apagado y no puede responder todavía.
- La estimación de sistema operativo por TTL es orientativa, no una certeza: algunos sistemas modifican su TTL inicial, y un dispositivo de red intermedio (NAT, firewall) puede alterarlo — es una técnica real de reconocimiento, pero no infalible ni pensada para sustituir un análisis serio (para eso existen herramientas como `nmap -O`, mucho más completas).
- La detección de MAC depende de la tabla ARP del sistema, que solo tiene entradas de dispositivos con los que ya ha habido tráfico reciente — por eso el barrido de ping se hace siempre antes de leerla.
- Pensado para redes pequeñas/domésticas (homelab). Para entornos con cientos de hosts, una herramienta como `nmap` es más rápida y completa.

## Scripts de auditoría rutinaria (`auditoria/`)

Cuatro scripts pensados para ejecutarse periódicamente, no solo una
vez, reutilizando la lógica de `netscan.py` (sin duplicar código):

```bash
cd auditoria

# Certificados SSL/TLS - dice cuántos días quedan para que caduquen
python audit_certificados.py sergioseoane.com github.com --txt resultado.txt

# Comparador de línea base - detecta dispositivos nuevos/desaparecidos/con IP cambiada
python audit_comparador.py --subnet 192.168.1.0/24 --guardar   # primera vez
python audit_comparador.py --subnet 192.168.1.0/24             # siguientes veces

# Versiones por banner - lee que version anuncia cada servicio abierto
python audit_versiones.py 192.168.1.1

# Informe semanal en HTML - junta los tres anteriores + diagnostico de conectividad
python audit_informe_semanal.py --subnet 192.168.1.0/24 --certificados sergioseoane.com
```

Los tres primeros aceptan `--txt ARCHIVO` para guardar la salida en
texto plano, además de imprimirla en pantalla. El informe semanal se
guarda como HTML en `auditoria/informes/`, con la misma estética
oscura tipo terminal del portfolio (`portfolio-infra`) — no una tabla
corporativa genérica, mismo lenguaje visual en todo el conjunto.

### Limitaciones honestas de estos cuatro scripts

- `audit_versiones.py` compara solo contra una tabla local de
  versiones mínimas razonables (OpenSSH, nginx, Apache) — no es un
  escáner de CVEs real como el motor `vuln` de Nmap, es un primer
  filtro razonable, no una auditoría de vulnerabilidades exhaustiva.
- `audit_comparador.py` identifica dispositivos por MAC — si un
  dispositivo no responde a ARP (poco tráfico reciente), puede no
  detectarse aunque esté activo.
- `audit_certificados.py` con una IP en vez de un dominio dará
  previsiblemente un error de "hostname no coincide" — es el
  comportamiento correcto de TLS, no un fallo del script (la mayoría
  de certificados solo cubren dominios, no IPs).

## CVEs reales (NVD/NIST)

`audit_versiones.py --cve` consulta la API pública y gratuita del NVD
para saber si una versión detectada tiene vulnerabilidades reales
documentadas, con su gravedad — en vez de solo la comparación local
de "versión mínima razonable". Límite de la propia API sin clave:
~5 peticiones cada 30 segundos, por eso es opcional (`--cve`), no
automático en cada auditoría.

```bash
python audit_versiones.py 192.168.1.1 --cve
```

> No se ha podido probar esta llamada de verdad en el entorno donde se
> escribió el código (sin salida a ese dominio) — confirma que
> responde bien en tu propia máquina.

## Notificación de escritorio (en vez de email)

El informe semanal muestra una notificación de escritorio de Windows
al terminar (usando la librería opcional `plyer`), sin necesitar
configurar ningún servidor de correo — un aviso normal, como el de
cualquier programa, resumiendo si hubo algo que revisar o si todo
salió bien. Desactivable con `--sin-notificacion`.

## Tarea programada automática

En vez de configurar el Programador de tareas de Windows a mano,
`audit_programar_tarea.py` lo hace por ti (solo Windows), usando
PowerShell (`Register-ScheduledTask`) en vez del `schtasks` clásico,
para poder activar `StartWhenAvailable` — si el PC está apagado a la
hora programada, la tarea se ejecuta en cuanto vuelve a encenderse,
en vez de perderse esa semana entera.

```bash
python audit_programar_tarea.py --subnet 192.168.1.0/24 --certificados sergioseoane.com --dia MON --hora 07:00

# Para quitarla despues:
python audit_programar_tarea.py --eliminar
```

Por defecto se programa a las **07:00**, no a media mañana — antes de
que empiece la actividad normal de la red (menos ruido en el
escaneo) y con el informe ya listo cuando empiezas la jornada.

También disponible desde la GUI, en Auditoría → Programar.
