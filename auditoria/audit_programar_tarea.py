#!/usr/bin/env python3
"""
audit_programar_tarea.py - crea (o elimina) automaticamente una tarea
programada de Windows para ejecutar audit_informe_semanal.py de forma
periodica, sin tener que configurarla a mano en el Programador de
tareas de Windows.

Usa PowerShell (Register-ScheduledTask), no el "schtasks" clasico -
asi se puede activar "StartWhenAvailable" (si el PC estaba apagado a
la hora programada, la tarea se ejecuta en cuanto vuelve a encenderse,
en vez de perderse esa semana), algo que el comando schtasks basico
no permite configurar directamente.

Solo funciona en Windows.

Uso:
  python audit_programar_tarea.py --subnet 192.168.1.0/24 --certificados sergioseoane.com
  python audit_programar_tarea.py --subnet 192.168.1.0/24 --dia MON --hora 07:00
  python audit_programar_tarea.py --eliminar
"""

import argparse
import os
import platform
import subprocess
import sys

NOMBRE_TAREA_DEFECTO = "AuditoriaRedSemanal"

# PowerShell usa el nombre completo del dia en ingles para DaysOfWeek,
# pero se sigue aceptando la abreviatura de siempre (MON, TUE...) en
# la linea de comandos, para no romper como se venia usando.
DIAS_POWERSHELL = {
    "MON": "Monday", "TUE": "Tuesday", "WED": "Wednesday", "THU": "Thursday",
    "FRI": "Friday", "SAT": "Saturday", "SUN": "Sunday",
}


def crear_tarea(nombre: str, subnet: str, certificados: list, dia: str, hora: str) -> bool:
    script = os.path.join(os.path.dirname(os.path.abspath(__file__)), "audit_informe_semanal.py")
    python_exe = sys.executable
    dia_ps = DIAS_POWERSHELL.get(dia, "Monday")

    argumentos = f'"{script}" --subnet {subnet}'
    if certificados:
        argumentos += " --certificados " + " ".join(certificados)

    # Se genera un script de PowerShell en vez de un unico comando, para
    # poder activar StartWhenAvailable via New-ScheduledTaskSettingsSet -
    # esto es lo que el "schtasks" clasico no permite hacer directamente.
    script_ps = f"""
$accion = New-ScheduledTaskAction -Execute '{python_exe}' -Argument '{argumentos}'
$disparador = New-ScheduledTaskTrigger -Weekly -DaysOfWeek {dia_ps} -At {hora}
$ajustes = New-ScheduledTaskSettingsSet -StartWhenAvailable
Register-ScheduledTask -TaskName '{nombre}' -Action $accion -Trigger $disparador -Settings $ajustes -Force | Out-Null
Write-Output "OK"
"""

    print("Creando la tarea programada con PowerShell (Register-ScheduledTask)...")
    resultado = subprocess.run(
        ["powershell", "-NoProfile", "-NonInteractive", "-Command", script_ps],
        capture_output=True, text=True,
    )

    if resultado.returncode == 0 and "OK" in resultado.stdout:
        print(f"\nTarea '{nombre}' creada correctamente.")
        print(f"Se ejecutará cada {dia_ps} a las {hora}.")
        print("Si el PC está apagado a esa hora, se ejecutará en cuanto vuelva a encenderse (StartWhenAvailable).")
        return True
    else:
        print(f"\nError al crear la tarea:\n{resultado.stderr or resultado.stdout}")
        return False


def eliminar_tarea(nombre: str) -> bool:
    script_ps = f"Unregister-ScheduledTask -TaskName '{nombre}' -Confirm:$false; Write-Output 'OK'"
    resultado = subprocess.run(
        ["powershell", "-NoProfile", "-NonInteractive", "-Command", script_ps],
        capture_output=True, text=True,
    )
    if resultado.returncode == 0 and "OK" in resultado.stdout:
        print(f"Tarea '{nombre}' eliminada.")
        return True
    else:
        print(f"Error al eliminar la tarea (¿existía?):\n{resultado.stderr or resultado.stdout}")
        return False


def main():
    parser = argparse.ArgumentParser(description="Crea o elimina la tarea programada de auditoría semanal")
    parser.add_argument("--subnet", help="Subred a auditar, ej. 192.168.1.0/24")
    parser.add_argument("--certificados", nargs="*", default=[], help="Hosts a comprobar certificado SSL")
    parser.add_argument("--dia", default="MON", choices=list(DIAS_POWERSHELL.keys()),
                         help="Día de la semana (por defecto lunes)")
    parser.add_argument("--hora", default="07:00",
                         help="Hora en formato HH:MM (por defecto 07:00, antes de que empiece la actividad normal de la red)")
    parser.add_argument("--nombre", default=NOMBRE_TAREA_DEFECTO, help="Nombre de la tarea en el Programador")
    parser.add_argument("--eliminar", action="store_true", help="Eliminar la tarea en vez de crearla")
    args = parser.parse_args()

    # La comprobacion de Windows va DESPUES de argparse, a proposito:
    # asi "--help" (que argparse gestiona el solo y termina el programa
    # antes de llegar aqui) funciona igual en cualquier sistema - el
    # bloqueo real solo aplica cuando de verdad se va a ejecutar algo.
    if platform.system().lower() != "windows":
        print("Este script solo funciona en Windows (usa PowerShell/Task Scheduler).")
        print("En Linux/macOS, el equivalente sería una tarea de cron.")
        sys.exit(1)

    if args.eliminar:
        eliminar_tarea(args.nombre)
        return

    if not args.subnet:
        parser.error("--subnet es obligatorio para crear la tarea (o usa --eliminar)")

    crear_tarea(args.nombre, args.subnet, args.certificados, args.dia, args.hora)


if __name__ == "__main__":
    main()
