#!/usr/bin/env python3
"""
netscan_gui.py - interfaz grafica para netscan, con botones en vez de
comandos. Reutiliza exactamente la misma logica de netscan.py (no hay
codigo de escaneo duplicado) - esta version solo se encarga de la
ventana y de no congelarse mientras escanea.

Organizada en pestanas:
  - Escanear red: el barrido de subred de siempre.
  - Redes locales: tus interfaces, mostradas EN la ventana (sin pop-ups).
  - Herramientas: Wake-on-LAN y diagnostico de conectividad.
"""

import ipaddress
import os
import platform
import sys
import threading
import webbrowser
import tkinter as tk
from tkinter import ttk, messagebox

import netscan

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "auditoria"))
import audit_certificados
import audit_comparador
import audit_versiones
import audit_informe_semanal
import audit_programar_tarea


class NetscanGUI:
    def __init__(self, root):
        self.root = root
        root.title("netscan - Escaner de red")
        root.geometry("820x560")

        notebook = ttk.Notebook(root)
        notebook.pack(fill="both", expand=True, padx=8, pady=8)

        self.tab_escaneo = ttk.Frame(notebook)
        self.tab_redes = ttk.Frame(notebook)
        self.tab_herramientas = ttk.Frame(notebook)
        self.tab_auditoria = ttk.Frame(notebook)
        notebook.add(self.tab_escaneo, text="Escanear red")
        notebook.add(self.tab_redes, text="Redes locales")
        notebook.add(self.tab_herramientas, text="Herramientas")
        notebook.add(self.tab_auditoria, text="Auditoría")

        self._montar_tab_escaneo()
        self._montar_tab_redes_locales()
        self._montar_tab_herramientas()
        self._montar_tab_auditoria()

    # ------------------------------------------------------------------
    # Pestana 1: Escanear red
    # ------------------------------------------------------------------
    def _montar_tab_escaneo(self):
        top = ttk.Frame(self.tab_escaneo, padding=10)
        top.pack(fill="x")

        ttk.Label(top, text="Subred (CIDR):").grid(row=0, column=0, sticky="w")
        self.subred_var = tk.StringVar(value="192.168.1.0/24")
        ttk.Entry(top, textvariable=self.subred_var, width=20).grid(row=0, column=1, padx=5)

        self.ports_var = tk.BooleanVar(value=True)
        ttk.Checkbutton(top, text="Escanear puertos", variable=self.ports_var).grid(row=0, column=2, padx=10)

        self.info_var = tk.BooleanVar(value=True)
        ttk.Checkbutton(top, text="Hostname / fabricante", variable=self.info_var).grid(row=0, column=3, padx=10)

        self.btn_escanear = ttk.Button(top, text="Escanear red", command=self.iniciar_escaneo)
        self.btn_escanear.grid(row=0, column=4, padx=10)

        self.online_var = tk.BooleanVar(value=False)
        ttk.Checkbutton(
            top, text="Buscar fabricante en línea (envía la MAC a macvendors.com)",
            variable=self.online_var
        ).grid(row=1, column=0, columnspan=3, sticky="w", pady=(4, 0))

        self.os_var = tk.BooleanVar(value=False)
        ttk.Checkbutton(
            top, text="Estimar SO por TTL (orientativo)",
            variable=self.os_var
        ).grid(row=1, column=3, columnspan=2, sticky="w", pady=(4, 0))

        self.progress = ttk.Progressbar(self.tab_escaneo, mode="indeterminate")
        self.status_var = tk.StringVar(value="Listo.")
        ttk.Label(self.tab_escaneo, textvariable=self.status_var, padding=(10, 0)).pack(fill="x")
        self.progress.pack(fill="x", padx=10, pady=(0, 5))

        columnas = ("ip", "estado", "hostname", "mac", "fabricante", "so", "puertos")
        self.tabla = ttk.Treeview(self.tab_escaneo, columns=columnas, show="headings")
        titulos = {
            "ip": "IP", "estado": "Estado", "hostname": "Hostname",
            "mac": "MAC", "fabricante": "Fabricante", "so": "SO estimado", "puertos": "Puertos abiertos",
        }
        anchos = {"ip": 110, "estado": 70, "hostname": 120, "mac": 130, "fabricante": 150, "so": 160, "puertos": 140}
        for col in columnas:
            self.tabla.heading(col, text=titulos[col])
            self.tabla.column(col, width=anchos[col])
        self.tabla.pack(fill="both", expand=True, padx=10, pady=5)
        self.tabla.tag_configure("activo", background="#e6f4ea")
        self.tabla.tag_configure("mi_equipo", background="#fff3cd")

        # Clic derecho sobre una fila -> menu contextual para enviar WoL
        # directamente a esa MAC (si la tiene), sin ir a la otra pestana.
        self.menu_fila = tk.Menu(self.root, tearoff=0)
        self.menu_fila.add_command(label="Enviar Wake-on-LAN a esta MAC", command=self._wol_desde_tabla)
        self.tabla.bind("<Button-3>", self._click_derecho_tabla)

    def _click_derecho_tabla(self, event):
        item = self.tabla.identify_row(event.y)
        if item:
            self.tabla.selection_set(item)
            self.menu_fila.post(event.x_root, event.y_root)

    def _wol_desde_tabla(self):
        seleccion = self.tabla.selection()
        if not seleccion:
            return
        valores = self.tabla.item(seleccion[0], "values")
        mac = valores[3] if len(valores) > 3 else ""
        if not mac:
            messagebox.showwarning("Sin MAC", "Esta fila no tiene una MAC detectada (activa 'Hostname / fabricante' al escanear).")
            return
        self.mac_wol_var.set(mac)
        messagebox.showinfo("MAC copiada", f"MAC {mac} copiada a la pestaña Herramientas. Ve ahí para enviar el Wake-on-LAN.")

    def iniciar_escaneo(self):
        subred = self.subred_var.get().strip()
        try:
            ipaddress.ip_network(subred, strict=False)
        except ValueError:
            messagebox.showerror("Subred inválida", f"'{subred}' no es una subred CIDR válida (ej. 192.168.1.0/24).")
            return

        self.btn_escanear.config(state="disabled")
        self.tabla.delete(*self.tabla.get_children())
        self.progress.start(10)
        self.status_var.set(f"Barriendo {subred}... esto puede tardar un poco.")

        hilo = threading.Thread(target=self._ejecutar_escaneo, args=(subred,), daemon=True)
        hilo.start()

    def _ejecutar_escaneo(self, subred):
        try:
            active, free = netscan.scan_subnet(subred)

            info_extra = {}
            if self.info_var.get():
                tabla_arp = netscan.obtener_tabla_arp()
                mis_macs = netscan.obtener_mis_macs()
                hostnames = netscan.resolver_hostnames_paralelo(active)
                for ip in active:
                    es_mi_equipo = ip in mis_macs
                    mac = mis_macs.get(ip) or tabla_arp.get(ip)

                    if mac and netscan.es_mac_aleatoria(mac) and not es_mi_equipo:
                        fabricante = "MAC aleatoria (privacidad)"
                    elif mac:
                        fabricante = netscan.fabricante_por_mac(mac)
                        if fabricante == "Desconocido" and self.online_var.get():
                            fabricante = netscan.fabricante_por_mac_online(mac) or "Desconocido (tampoco en línea)"
                    else:
                        fabricante = ""

                    so_estimado = ""
                    if self.os_var.get():
                        _, ttl = netscan.ping_con_ttl(ip)
                        so_estimado = netscan.estimar_so_por_ttl(ttl) or ""

                    info_extra[ip] = {
                        "hostname": ("Este equipo" if es_mi_equipo else (hostnames.get(ip) or "")),
                        "mac": mac or "",
                        "fabricante": fabricante,
                        "so_estimado": so_estimado,
                        "es_mi_equipo": es_mi_equipo,
                    }

            puertos_por_ip = {}
            if self.ports_var.get():
                for ip in active:
                    puertos_por_ip[ip] = netscan.scan_ports(ip)

            self.root.after(0, self._pintar_resultados, active, free, info_extra, puertos_por_ip)
        except Exception as e:
            self.root.after(0, self._mostrar_error, str(e))

    def _pintar_resultados(self, active, free, info_extra, puertos_por_ip):
        for ip in active:
            extra = info_extra.get(ip, {})
            puertos = puertos_por_ip.get(ip, [])
            etiquetas_puertos = ", ".join(
                f"{p}/{netscan.COMMON_PORTS.get(p, '?')}" for p in puertos
            ) if puertos else ("(ninguno)" if ip in puertos_por_ip else "")
            etiqueta = "mi_equipo" if extra.get("es_mi_equipo") else "activo"
            self.tabla.insert("", "end", values=(
                ip, "Activo", extra.get("hostname", ""), extra.get("mac", ""),
                extra.get("fabricante", ""), extra.get("so_estimado", ""), etiquetas_puertos,
            ), tags=(etiqueta,))

        self.progress.stop()
        self.btn_escanear.config(state="normal")
        self.status_var.set(f"Listo. {len(active)} IPs activas, {len(free)} libres en la subred.")

    def _mostrar_error(self, mensaje):
        self.progress.stop()
        self.btn_escanear.config(state="normal")
        self.status_var.set("Error durante el escaneo.")
        messagebox.showerror("Error", mensaje)

    # ------------------------------------------------------------------
    # Pestana 2: Redes locales (SIN pop-up, mostrado en la propia ventana)
    # ------------------------------------------------------------------
    def _montar_tab_redes_locales(self):
        frame = ttk.Frame(self.tab_redes, padding=10)
        frame.pack(fill="both", expand=True)

        ttk.Button(frame, text="Actualizar", command=self._actualizar_redes_locales).pack(anchor="w")

        columnas = ("interface", "ip", "network")
        self.tabla_redes = ttk.Treeview(frame, columns=columnas, show="headings", height=10)
        for col, titulo in zip(columnas, ["Interfaz", "IP", "Red"]):
            self.tabla_redes.heading(col, text=titulo)
            self.tabla_redes.column(col, width=220)
        self.tabla_redes.pack(fill="both", expand=True, pady=(8, 0))

        # Se carga automaticamente al abrir la pestana, sin que haga falta pulsar nada.
        self._actualizar_redes_locales()

    def _actualizar_redes_locales(self):
        self.tabla_redes.delete(*self.tabla_redes.get_children())
        redes = netscan.list_local_networks()
        if not redes:
            self.tabla_redes.insert("", "end", values=("(ninguna detectada - ¿falta psutil?)", "", ""))
            return
        for r in redes:
            self.tabla_redes.insert("", "end", values=(r["interface"], r["ip"], r["network"]))

    # ------------------------------------------------------------------
    # Pestana 3: Herramientas (Wake-on-LAN + diagnostico de conectividad)
    # ------------------------------------------------------------------
    def _montar_tab_herramientas(self):
        # --- Wake-on-LAN ---
        wol_frame = ttk.LabelFrame(self.tab_herramientas, text="Wake-on-LAN (encender un equipo remoto)", padding=10)
        wol_frame.pack(fill="x", padx=10, pady=10)

        ttk.Label(wol_frame, text="MAC del equipo:").grid(row=0, column=0, sticky="w")
        self.mac_wol_var = tk.StringVar()
        ttk.Entry(wol_frame, textvariable=self.mac_wol_var, width=25).grid(row=0, column=1, padx=5)

        ttk.Label(wol_frame, text="IP de broadcast:").grid(row=0, column=2, sticky="w", padx=(15, 0))
        self.broadcast_var = tk.StringVar(value="255.255.255.255")
        ttk.Entry(wol_frame, textvariable=self.broadcast_var, width=18).grid(row=0, column=3, padx=5)

        ttk.Button(wol_frame, text="Enviar Wake-on-LAN", command=self._enviar_wol).grid(row=0, column=4, padx=10)

        self.wol_status_var = tk.StringVar(value="")
        ttk.Label(wol_frame, textvariable=self.wol_status_var, foreground="#2e7d32").grid(
            row=1, column=0, columnspan=5, sticky="w", pady=(6, 0)
        )
        ttk.Label(
            wol_frame,
            text="Nota: el equipo de destino debe tener Wake-on-LAN activado en la BIOS y en el adaptador de red.",
            foreground="#666",
        ).grid(row=2, column=0, columnspan=5, sticky="w", pady=(4, 0))

        # --- Diagnostico de conectividad ---
        diag_frame = ttk.LabelFrame(self.tab_herramientas, text="Diagnóstico de conectividad", padding=10)
        diag_frame.pack(fill="both", expand=True, padx=10, pady=(0, 10))

        ttk.Button(diag_frame, text="Ejecutar diagnóstico", command=self._ejecutar_diagnostico).pack(anchor="w")

        columnas = ("paso", "detalle", "estado", "mensaje")
        self.tabla_diag = ttk.Treeview(diag_frame, columns=columnas, show="headings", height=6)
        for col, titulo, ancho in zip(columnas, ["Paso", "Detalle", "Estado", "Mensaje"], [140, 120, 70, 380]):
            self.tabla_diag.heading(col, text=titulo)
            self.tabla_diag.column(col, width=ancho)
        self.tabla_diag.pack(fill="both", expand=True, pady=(8, 0))
        self.tabla_diag.tag_configure("ok", background="#e6f4ea")
        self.tabla_diag.tag_configure("falla", background="#fdecea")

    def _enviar_wol(self):
        mac = self.mac_wol_var.get().strip()
        broadcast = self.broadcast_var.get().strip() or "255.255.255.255"
        if not mac:
            messagebox.showwarning("Falta la MAC", "Introduce la MAC del equipo a encender.")
            return
        try:
            netscan.enviar_wol(mac, broadcast_ip=broadcast)
            self.wol_status_var.set(f"Paquete enviado a {mac} vía {broadcast}.")
        except ValueError as e:
            messagebox.showerror("MAC inválida", str(e))
        except OSError as e:
            messagebox.showerror("Error de red", f"No se pudo enviar el paquete: {e}")

    def _ejecutar_diagnostico(self):
        self.tabla_diag.delete(*self.tabla_diag.get_children())
        # En un hilo aparte: cada paso hace ping/DNS con su propio timeout,
        # y no queremos congelar la ventana mientras se ejecutan en cascada.
        hilo = threading.Thread(target=self._ejecutar_diagnostico_hilo, daemon=True)
        hilo.start()

    def _ejecutar_diagnostico_hilo(self):
        pasos = netscan.diagnostico_conectividad()
        self.root.after(0, self._pintar_diagnostico, pasos)

    def _pintar_diagnostico(self, pasos):
        for p in pasos:
            tag = "ok" if p["ok"] else "falla"
            estado = "OK" if p["ok"] else "FALLA"
            self.tabla_diag.insert("", "end", values=(
                p["paso"], p["detalle"] or "", estado, p["mensaje"],
            ), tags=(tag,))

    # ------------------------------------------------------------------
    # Pestana 4: Auditoria (los 4 scripts de auditoria/)
    # ------------------------------------------------------------------
    def _montar_tab_auditoria(self):
        sub = ttk.Notebook(self.tab_auditoria)
        sub.pack(fill="both", expand=True, padx=6, pady=6)

        tab_cert = ttk.Frame(sub)
        tab_comp = ttk.Frame(sub)
        tab_ver = ttk.Frame(sub)
        tab_inf = ttk.Frame(sub)
        tab_prog = ttk.Frame(sub)
        sub.add(tab_cert, text="Certificados")
        sub.add(tab_comp, text="Comparador")
        sub.add(tab_ver, text="Versiones")
        sub.add(tab_inf, text="Informe semanal")
        sub.add(tab_prog, text="Programar")

        self._montar_sub_certificados(tab_cert)
        self._montar_sub_comparador(tab_comp)
        self._montar_sub_versiones(tab_ver)
        self._montar_sub_informe(tab_inf)
        self._montar_sub_programar(tab_prog)

    def _montar_sub_certificados(self, tab):
        frame = ttk.Frame(tab, padding=10)
        frame.pack(fill="both", expand=True)

        ttk.Label(frame, text="Hosts (separados por coma):").grid(row=0, column=0, sticky="w")
        self.cert_hosts_var = tk.StringVar(value="")
        ttk.Entry(frame, textvariable=self.cert_hosts_var, width=45).grid(row=0, column=1, padx=5)
        self.btn_cert = ttk.Button(frame, text="Comprobar", command=self._ejecutar_certificados)
        self.btn_cert.grid(row=0, column=2, padx=5)

        self.cert_status_var = tk.StringVar(value="")
        ttk.Label(frame, textvariable=self.cert_status_var, foreground="#666").grid(
            row=1, column=0, columnspan=3, sticky="w", pady=(4, 0)
        )
        self.cert_progress = ttk.Progressbar(frame, mode="indeterminate")
        self.cert_progress.grid(row=2, column=0, columnspan=3, sticky="ew", pady=(2, 0))

        columnas = ("host", "estado", "dias", "caduca", "emisor")
        self.tabla_cert = ttk.Treeview(frame, columns=columnas, show="headings", height=10)
        for col, titulo, ancho in zip(columnas, ["Host", "Estado", "Días", "Caduca el", "Emisor"], [180, 90, 60, 100, 200]):
            self.tabla_cert.heading(col, text=titulo)
            self.tabla_cert.column(col, width=ancho)
        self.tabla_cert.grid(row=3, column=0, columnspan=3, sticky="nsew", pady=(10, 0))
        self.tabla_cert.tag_configure("ok", background="#e6f4ea")
        self.tabla_cert.tag_configure("warn", background="#fff3cd")
        self.tabla_cert.tag_configure("fail", background="#fdecea")
        frame.rowconfigure(3, weight=1)
        frame.columnconfigure(1, weight=1)

    def _ejecutar_certificados(self):
        hosts = [h.strip() for h in self.cert_hosts_var.get().split(",") if h.strip()]
        if not hosts:
            messagebox.showwarning("Sin hosts", "Introduce al menos un host.")
            return
        self.tabla_cert.delete(*self.tabla_cert.get_children())
        self.btn_cert.config(state="disabled")
        self.cert_status_var.set(f"Comprobando {len(hosts)} host(s)...")
        self.cert_progress.start(10)
        threading.Thread(target=self._hilo_certificados, args=(hosts,), daemon=True).start()

    def _hilo_certificados(self, hosts):
        resultados = [audit_certificados.comprobar_certificado(h) for h in hosts]
        self.root.after(0, self._pintar_certificados, resultados)

    def _pintar_certificados(self, resultados):
        for r in resultados:
            if not r["ok"]:
                self.tabla_cert.insert("", "end", values=(r["host"], "ERROR", "", "", r["error"]), tags=("fail",))
                continue
            tono = {"OK": "ok", "AVISO": "warn", "CRITICO": "fail", "CADUCADO": "fail"}.get(r["estado"], "")
            self.tabla_cert.insert("", "end", values=(
                r["host"], r["estado"], r["dias_restantes"], r["caduca_el"], r["emisor"],
            ), tags=(tono,))
        self.cert_progress.stop()
        self.btn_cert.config(state="normal")
        self.cert_status_var.set(f"Listo. {len(resultados)} host(s) comprobado(s).")

    def _montar_sub_comparador(self, tab):
        frame = ttk.Frame(tab, padding=10)
        frame.pack(fill="both", expand=True)

        ttk.Label(frame, text="Subred (CIDR):").grid(row=0, column=0, sticky="w")
        self.comp_subred_var = tk.StringVar(value="192.168.1.0/24")
        ttk.Entry(frame, textvariable=self.comp_subred_var, width=20).grid(row=0, column=1, padx=5)
        self.btn_comp_guardar = ttk.Button(frame, text="Guardar línea base", command=lambda: self._ejecutar_comparador(guardar=True))
        self.btn_comp_guardar.grid(row=0, column=2, padx=5)
        self.btn_comp_comparar = ttk.Button(frame, text="Comparar ahora", command=lambda: self._ejecutar_comparador(guardar=False))
        self.btn_comp_comparar.grid(row=0, column=3, padx=5)

        self.comp_status_var = tk.StringVar(value="")
        ttk.Label(frame, textvariable=self.comp_status_var, foreground="#666").grid(row=1, column=0, columnspan=4, sticky="w", pady=(8, 0))
        self.comp_progress = ttk.Progressbar(frame, mode="indeterminate")
        self.comp_progress.grid(row=2, column=0, columnspan=4, sticky="ew", pady=(2, 4))

        self.texto_comp = tk.Text(frame, height=13, wrap="word")
        self.texto_comp.grid(row=3, column=0, columnspan=4, sticky="nsew")
        frame.rowconfigure(3, weight=1)
        frame.columnconfigure(3, weight=1)

    def _ejecutar_comparador(self, guardar: bool):
        subred = self.comp_subred_var.get().strip()
        try:
            ipaddress.ip_network(subred, strict=False)
        except ValueError:
            messagebox.showerror("Subred inválida", f"'{subred}' no es una subred CIDR válida.")
            return
        self.btn_comp_guardar.config(state="disabled")
        self.btn_comp_comparar.config(state="disabled")
        self.comp_status_var.set("Escaneando la red...")
        self.comp_progress.start(10)
        self.texto_comp.delete("1.0", "end")
        threading.Thread(target=self._hilo_comparador, args=(subred, guardar), daemon=True).start()

    def _hilo_comparador(self, subred, guardar):
        actual = audit_comparador.escanear_estado_actual(subred)
        archivo = audit_comparador.ARCHIVO_LINEA_BASE_DEFECTO

        if guardar or not os.path.exists(archivo):
            audit_comparador.guardar_linea_base(archivo, actual)
            texto = f"Línea base guardada ({len(actual)} dispositivos con MAC identificada)."
            self.root.after(0, self._pintar_comparador, texto)
            return

        base = audit_comparador.cargar_linea_base(archivo)
        diff = audit_comparador.comparar(base, actual)
        lineas = []
        if not any(diff.values()):
            lineas.append("Sin cambios respecto a la línea base. Todo en orden.")
        else:
            if diff["nuevos"]:
                lineas.append(f"[NUEVO] {len(diff['nuevos'])} dispositivo(s):")
                lineas += [f"  {actual[m]['ip']}  {m}  {actual[m]['hostname']}" for m in diff["nuevos"]]
            if diff["desaparecidos"]:
                lineas.append(f"[DESAPARECIDO] {len(diff['desaparecidos'])} dispositivo(s):")
                lineas += [f"  {base[m]['ip']}  {m}  {base[m]['hostname']}" for m in diff["desaparecidos"]]
            if diff["cambiados_ip"]:
                lineas.append(f"[CAMBIO DE IP] {len(diff['cambiados_ip'])} dispositivo(s):")
                lineas += [f"  {m}: {base[m]['ip']} -> {actual[m]['ip']}" for m in diff["cambiados_ip"]]
        self.root.after(0, self._pintar_comparador, "\n".join(lineas))

    def _pintar_comparador(self, texto):
        self.comp_progress.stop()
        self.btn_comp_guardar.config(state="normal")
        self.btn_comp_comparar.config(state="normal")
        self.comp_status_var.set("Listo.")
        self.texto_comp.insert("1.0", texto)

    def _montar_sub_versiones(self, tab):
        frame = ttk.Frame(tab, padding=10)
        frame.pack(fill="both", expand=True)

        ttk.Label(frame, text="IP:").grid(row=0, column=0, sticky="w")
        self.ver_ip_var = tk.StringVar()
        ttk.Entry(frame, textvariable=self.ver_ip_var, width=18).grid(row=0, column=1, padx=5)

        ttk.Label(frame, text="Puertos:").grid(row=0, column=2, sticky="w", padx=(10, 0))
        self.ver_puertos_var = tk.StringVar(value="21,22,25,80,443,3306,8080,8443")
        ttk.Entry(frame, textvariable=self.ver_puertos_var, width=30).grid(row=0, column=3, padx=5)

        self.btn_versiones = ttk.Button(frame, text="Auditar", command=self._ejecutar_versiones)
        self.btn_versiones.grid(row=0, column=4, padx=5)

        self.ver_cve_var = tk.BooleanVar(value=False)
        ttk.Checkbutton(frame, text="Consultar CVEs reales (NVD/NIST) - más lento", variable=self.ver_cve_var).grid(
            row=1, column=0, columnspan=5, sticky="w", pady=(6, 0)
        )

        self.ver_status_var = tk.StringVar(value="")
        ttk.Label(frame, textvariable=self.ver_status_var, foreground="#666").grid(
            row=2, column=0, columnspan=5, sticky="w", pady=(4, 0)
        )
        self.ver_progress = ttk.Progressbar(frame, mode="indeterminate")
        self.ver_progress.grid(row=3, column=0, columnspan=5, sticky="ew", pady=(4, 0))

        self.texto_ver = tk.Text(frame, height=12, wrap="word")
        self.texto_ver.grid(row=4, column=0, columnspan=5, sticky="nsew", pady=(8, 0))
        frame.rowconfigure(4, weight=1)
        frame.columnconfigure(4, weight=1)

    def _ejecutar_versiones(self):
        ip = self.ver_ip_var.get().strip()
        if not ip:
            messagebox.showwarning("Falta la IP", "Introduce la IP del host a auditar.")
            return
        try:
            puertos = [int(p) for p in self.ver_puertos_var.get().split(",")]
        except ValueError:
            messagebox.showerror("Puertos inválidos", "Usa números separados por coma, ej. 22,80,443")
            return
        self.texto_ver.delete("1.0", "end")
        self.btn_versiones.config(state="disabled")
        self.ver_status_var.set(f"Auditando {ip} ({len(puertos)} puertos)... esto puede tardar unos segundos.")
        self.ver_progress.start(10)
        threading.Thread(target=self._hilo_versiones, args=(ip, puertos), daemon=True).start()

    def _hilo_versiones(self, ip, puertos):
        resultados = audit_versiones.auditar_host(ip, puertos)
        if not resultados:
            texto = "Ningún servicio respondió con un banner identificable en esos puertos."
        else:
            lineas = []
            for r in resultados:
                lineas.append(f"Puerto {r['puerto']}: {r['banner']}")
                lineas.append(f"  {r['evaluacion']}")
                if self.ver_cve_var.get():
                    termino = audit_versiones.extraer_termino_busqueda(r["banner"])
                    cve_info = audit_versiones.buscar_cves(termino)
                    if not cve_info["ok"]:
                        lineas.append(f"  CVEs (buscado: '{termino}'): no se pudo consultar el NVD ({cve_info['error']})")
                    elif cve_info["total"] == 0:
                        lineas.append(f"  CVEs (buscado: '{termino}'): ninguno encontrado")
                    else:
                        lineas.append(f"  CVEs (buscado: '{termino}', {cve_info['total']} en total):")
                        for cve in cve_info["resultados"]:
                            punt = cve["puntuacion"] if cve["puntuacion"] is not None else "?"
                            lineas.append(f"    {cve['id']} - {cve['severidad']} ({punt})")
            texto = "\n".join(lineas)
        self.root.after(0, self._versiones_listo, texto, len(resultados))

    def _versiones_listo(self, texto, num_resultados):
        self.ver_progress.stop()
        self.btn_versiones.config(state="normal")
        self.ver_status_var.set(f"Listo. {num_resultados} servicio(s) con banner identificado.")
        self.texto_ver.insert("1.0", texto)

    def _montar_sub_informe(self, tab):
        frame = ttk.Frame(tab, padding=10)
        frame.pack(fill="both", expand=True)

        ttk.Label(frame, text="Subred:").grid(row=0, column=0, sticky="w")
        self.inf_subred_var = tk.StringVar(value="192.168.1.0/24")
        ttk.Entry(frame, textvariable=self.inf_subred_var, width=20).grid(row=0, column=1, padx=5)

        ttk.Label(frame, text="Certificados (coma):").grid(row=0, column=2, sticky="w", padx=(10, 0))
        self.inf_certs_var = tk.StringVar(value="")
        ttk.Entry(frame, textvariable=self.inf_certs_var, width=30).grid(row=0, column=3, padx=5)

        ttk.Button(frame, text="Generar informe", command=self._ejecutar_informe).grid(row=0, column=4, padx=5)

        self.inf_status_var = tk.StringVar(value="")
        ttk.Label(frame, textvariable=self.inf_status_var, wraplength=600, justify="left").grid(
            row=1, column=0, columnspan=5, sticky="w", pady=(12, 0)
        )
        self.btn_abrir_informe = ttk.Button(frame, text="Abrir informe en el navegador", command=self._abrir_informe, state="disabled")
        self.btn_abrir_informe.grid(row=2, column=0, sticky="w", pady=(10, 0))
        self._ultima_ruta_informe = None

    def _ejecutar_informe(self):
        subred = self.inf_subred_var.get().strip()
        try:
            ipaddress.ip_network(subred, strict=False)
        except ValueError:
            messagebox.showerror("Subred inválida", f"'{subred}' no es una subred CIDR válida.")
            return
        certs = [h.strip() for h in self.inf_certs_var.get().split(",") if h.strip()]
        self.inf_status_var.set("Generando informe (diagnóstico + comparador + certificados)...")
        self.btn_abrir_informe.config(state="disabled")
        threading.Thread(target=self._hilo_informe, args=(subred, certs), daemon=True).start()

    def _hilo_informe(self, subred, certs):
        diagnostico = netscan.diagnostico_conectividad()
        archivo_base = audit_comparador.ARCHIVO_LINEA_BASE_DEFECTO
        actual = audit_comparador.escanear_estado_actual(subred)

        if os.path.exists(archivo_base):
            base = audit_comparador.cargar_linea_base(archivo_base)
            diff = audit_comparador.comparar(base, actual)
            diff["_actual"] = actual
            diff["_base"] = base
        else:
            audit_comparador.guardar_linea_base(archivo_base, actual)
            diff = {"nuevos": [], "desaparecidos": [], "cambiados_ip": [], "_actual": actual, "_base": {}, "_primera_ejecucion": True}

        certificados = [audit_certificados.comprobar_certificado(h) for h in certs]

        os.makedirs(audit_informe_semanal.CARPETA_INFORMES, exist_ok=True)
        from datetime import datetime
        nombre = f"informe_{datetime.now().strftime('%Y%m%d_%H%M%S')}.html"
        ruta = os.path.join(audit_informe_semanal.CARPETA_INFORMES, nombre)
        contenido = audit_informe_semanal.generar_html(subred, diagnostico, diff, certificados)
        with open(ruta, "w", encoding="utf-8") as f:
            f.write(contenido)

        self.root.after(0, self._informe_listo, ruta)

    def _informe_listo(self, ruta):
        self._ultima_ruta_informe = ruta
        self.inf_status_var.set(f"Informe generado: {ruta}")
        self.btn_abrir_informe.config(state="normal")

    def _abrir_informe(self):
        if self._ultima_ruta_informe:
            webbrowser.open(f"file://{os.path.abspath(self._ultima_ruta_informe)}")

    def _montar_sub_programar(self, tab):
        frame = ttk.Frame(tab, padding=10)
        frame.pack(fill="both", expand=True)

        ttk.Label(frame, text="Subred:").grid(row=0, column=0, sticky="w")
        self.prog_subred_var = tk.StringVar(value="192.168.1.0/24")
        ttk.Entry(frame, textvariable=self.prog_subred_var, width=20).grid(row=0, column=1, padx=5)

        ttk.Label(frame, text="Certificados (coma):").grid(row=0, column=2, sticky="w", padx=(10, 0))
        self.prog_certs_var = tk.StringVar(value="")
        ttk.Entry(frame, textvariable=self.prog_certs_var, width=30).grid(row=0, column=3, padx=5)

        ttk.Label(frame, text="Día:").grid(row=1, column=0, sticky="w", pady=(8, 0))
        self.prog_dia_var = tk.StringVar(value="MON")
        ttk.Combobox(
            frame, textvariable=self.prog_dia_var, width=8, state="readonly",
            values=list(audit_programar_tarea.DIAS_POWERSHELL.keys()),
        ).grid(row=1, column=1, sticky="w", padx=5, pady=(8, 0))

        ttk.Label(frame, text="Hora (HH:MM):").grid(row=1, column=2, sticky="w", padx=(10, 0), pady=(8, 0))
        self.prog_hora_var = tk.StringVar(value="07:00")
        ttk.Entry(frame, textvariable=self.prog_hora_var, width=10).grid(row=1, column=3, sticky="w", padx=5, pady=(8, 0))

        botones = ttk.Frame(frame)
        botones.grid(row=2, column=0, columnspan=4, sticky="w", pady=(14, 0))
        ttk.Button(botones, text="Crear tarea programada", command=self._crear_tarea_programada).pack(side="left")
        ttk.Button(botones, text="Eliminar tarea", command=self._eliminar_tarea_programada).pack(side="left", padx=(8, 0))

        self.prog_status_var = tk.StringVar(value="")
        ttk.Label(frame, textvariable=self.prog_status_var, foreground="#666", wraplength=650, justify="left").grid(
            row=3, column=0, columnspan=4, sticky="w", pady=(12, 0)
        )

        nota = (
            "Crea una tarea en el Programador de tareas de Windows que ejecuta el informe\n"
            "semanal en segundo plano, con recuperación automática si el PC estaba apagado\n"
            "a la hora programada. Solo funciona en Windows."
        )
        ttk.Label(frame, text=nota, foreground="#888").grid(row=4, column=0, columnspan=4, sticky="w", pady=(16, 0))

    def _crear_tarea_programada(self):
        subred = self.prog_subred_var.get().strip()
        try:
            ipaddress.ip_network(subred, strict=False)
        except ValueError:
            messagebox.showerror("Subred inválida", f"'{subred}' no es una subred CIDR válida.")
            return
        certs = [h.strip() for h in self.prog_certs_var.get().split(",") if h.strip()]
        dia = self.prog_dia_var.get()
        hora = self.prog_hora_var.get().strip()

        self.prog_status_var.set("Creando la tarea programada...")
        threading.Thread(
            target=self._hilo_crear_tarea, args=(subred, certs, dia, hora), daemon=True
        ).start()

    def _hilo_crear_tarea(self, subred, certs, dia, hora):
        if platform.system().lower() != "windows":
            self.root.after(0, self.prog_status_var.set,
                             "Esto solo funciona en Windows (usa PowerShell/Task Scheduler). "
                             "En este sistema no se puede crear la tarea real.")
            return
        ok = audit_programar_tarea.crear_tarea(
            audit_programar_tarea.NOMBRE_TAREA_DEFECTO, subred, certs, dia, hora
        )
        mensaje = (
            f"Tarea creada: se ejecutará cada {dia} a las {hora}."
            if ok else "No se pudo crear la tarea. Revisa la consola para más detalle."
        )
        self.root.after(0, self.prog_status_var.set, mensaje)

    def _eliminar_tarea_programada(self):
        self.prog_status_var.set("Eliminando la tarea...")
        threading.Thread(target=self._hilo_eliminar_tarea, daemon=True).start()

    def _hilo_eliminar_tarea(self):
        if platform.system().lower() != "windows":
            self.root.after(0, self.prog_status_var.set, "Esto solo funciona en Windows.")
            return
        ok = audit_programar_tarea.eliminar_tarea(audit_programar_tarea.NOMBRE_TAREA_DEFECTO)
        mensaje = "Tarea eliminada." if ok else "No se pudo eliminar la tarea (¿existía?)."
        self.root.after(0, self.prog_status_var.set, mensaje)


if __name__ == "__main__":
    root = tk.Tk()
    app = NetscanGUI(root)
    root.mainloop()
