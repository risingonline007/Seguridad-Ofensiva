#!/usr/bin/env python

# Importaciones de modulos y librerías de Python

import scapy.all as scapy
import socket
import requests
import argparse
import sys
import json
import os
import logging
import ipaddress
import signal
import sys
import time
from netaddr import IPNetwork
from scapy.layers.inet import IP, ICMP, TCP, UDP
from scapy.layers.l2 import ARP, Ether
#from scapy.all import srp, conf, RandShort, DNS, DNSQR, SNMP, SNMPget, SNMPvarbind, NTP, Raw, BOOTP, TFTP, ASN1_OID
from scapy.all import *
from termcolor import colored

#
# Definición de funciones
#

# URL del archivo OUI de IEEE
URL_OUI = "https://standards-oui.ieee.org/oui/oui.txt"

# Nombre del archivo donde se guardará el OUI
OUI_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "oui.txt")

# Funcion que imprime un banner por pantalla
def mostrar_banner():
    banner = r'''
===========================================================
#                                                         #
#     _____    _____    ____   _____   _   _    _____     #
#    |  __ \  |_   _|  / ___| |_   _| | \ | |  / ____|    #
#    | |__) |   | |   | (___    | |   |  \| | | |  __     #
#    |  _  /    | |    \___ \   | |   |     | | | |_ |    #
#    | | \ \   _| |_    __| |  _| |_  | |\  | | |__| |    #
#    |_|  \_\ |_____| |_____| |_____| |_| \_|  \_____|    #
#                                                         #
#                        PTES Enumeration Scanner v1.0    #
#                                                         #
===========================================================
AUTOR: RAUL ROMERO CABELLO
FECHA: 31/03/2025
    '''
    print(colored(banner, "blue"))


# Deshabilitar mensajes de advertencia de Scapy
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
conf.verb = 0

# Manejar la interrupción de teclada indicada para evitar errores no controlados
def handler(sig, frame):
    print("\n[+] Interrupción detectada (Ctrl+C). Finalizando limpiamente...")
    sys.exit(0)

# Descargar el archivo OUI con los vendors segun las MAC
def descarga_bbdd_vendors(url):
    """
    Args:
    - url: dirección url donde reside el fichero con la parte de identificadores MAC de cada vendor y su title
    """
    try:
        # Intentar descargar el archivo desde la URL
        response = requests.get(url, timeout=10)  # Agregamos un timeout para evitar que se bloquee indefinidamente

        # Comprobar si la solicitud fue exitosa
        if response.status_code == 200:
            data = response.text  # Extraer el contenido de la respuesta (el archivo OUI)

            try:
                # Intentar escribir el archivo en el sistema
                with open(OUI_FILE, "w") as file:
                    file.write(data)
                print(f"Archivo OUI guardado en {OUI_FILE}")
            except IOError as e:
                # Captura errores de escritura en el archivo
                print(f"ERROR: No se pudo escribir en el archivo {OUI_FILE}. Detalles: {e}")
                exit(3)
        else:
            # Si el código de estado HTTP no es 200, se considera un error
            print(f"ERROR: No se pudo descargar el archivo OUI. Código de estado: {response.status_code}")
            exit(3)

    except requests.exceptions.Timeout:
        # Si la solicitud excede el tiempo de espera
        print("ERROR: La solicitud de descarga del archivo OUI ha superado el tiempo de espera.")
        exit(3)

    except requests.exceptions.RequestException as e:
        # Captura cualquier otra excepción relacionada con la solicitud HTTP
        print(f"ERROR: Ocurrió un error durante la descarga del archivo OUI. Detalles: {e}")
        exit(3)

# Carga el archivo oui.txt la bbdd de vendors y la parte de la MAC que lo identifica en un diccionario
def load_oui_data(oui_file_path):
    """
    Args:
    - oui_file_path: Ruta completa del fichero de texto donde están los datos de la parte identificadora de la MAC y el vendor.

    Retorna:
    - Un diccionario para poder trabajar con los IDs de MAC y vendors o None si no ha podido cargar la variable diccionario.
    """
    oui_dict = {}
    try:
        with open(oui_file_path, 'r') as file:
            for line in file:
                if "(hex)" in line:  # Filtra solo las líneas que tienen asignaciones OUI
                    parts = line.split()
                    if len(parts) >= 3:
                        prefix = parts[0].replace("-", ":")  # Convierte XX-XX-XX a XX:XX:XX
                        vendor = " ".join(parts[2:])         # El nombre del vendor está después de los primeros dos elementos
                        oui_dict[prefix] = vendor
        return oui_dict
    except FileNotFoundError:
        print(f"ERROR: El archivo '{oui_file_path}' no existe.")
        return None
    except Exception as e:
        print(f"ERROR: Ocurrió un error al leer el archivo '{oui_file_path}': {e}")
        return None

# Busca los primeros tres primeros octetos de la direccion MAC en una variable tipo diccionario
def get_mac_vendor(mac_address, oui_dict):
    """
    Args:
    - mac_address: Dirección MAC, 6 octeto separados por ":" sin importar mayusculas o minusculas.
    - oui_dict Diccionario que contiene la bbdd de inicios de MAC y title vendor.

    Retorna:
    - Un string con el title vendor si encuentra resultados o "Fabricante no encontrado" en caso contrario.
    """
    mac_prefix = ":".join(mac_address.upper().split(":")[:3])  # Usar los primeros 3 octetos
    return oui_dict.get(mac_prefix, "Desconocido")

# Se calcula dada una subred en formato CIDR cual es la dirección de red y la de broadcast
def calcular_ip_red_y_broadcast(subred_cidr):
    """
    Calcula la IP de red y de broadcast a partir de una subred en formato CIDR.

    Args:
        subred_cidr (str): La subred en formato CIDR (ej: "192.168.1.0/24").

    Retorna:
        Una tupla con la IP de red y la IP de broadcast.
    """
    try:
        network = ipaddress.ip_network(subred_cidr, strict=False)
        return network.network_address, network.broadcast_address
    except ValueError as e:
        return None, f"Error: {e}"

# Calcular el numero de direcciones IP validas de una subred en formato CIDR
def calcular_ips_subred(cidr):
    """
    Calcula el número de direcciones IP disponibles en una subred.

    Args:
        cidr: Notación CIDR de la subred (ej: /24, /28).

    Returns:
        El número de direcciones IP disponibles.
    """
    bits_de_red = int(cidr.split('/')[1])
    bits_de_host = 32 - bits_de_red
    return 2**bits_de_host - 2

# Ping ARP que descubre las IPs que estan activas en la red, con su MAC y el vendor
def arp_ping(network):
    """
    Descubrimiento de hosts en la red usando ARP Ping.

    Args:
        network: Aquí se informa el host o la subred (en formato CIDR)

    Returns:
        Devuelve las direcciones IP que han respondido, la MAC y el texto identificador del vendor
    """
    arp_request = ARP(pdst=network)
    broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast / arp_request
    answered = srp(arp_request_broadcast, timeout=2, verbose=False)[0]
    hosts = [(recv.psrc, recv.hwsrc, get_mac_vendor(recv.hwsrc,oui)) for sent, recv in answered]
    return hosts

# TCP Ping esta función es la encargada de hacer el 
def tcp_ping(host, port=80):
    """
    Realiza un TCP Ping al puerto especificado (por defecto 80), usa el método SYN Stealth.

    Args:
        host: la IP de la máquina a la que se le va a hacer el tcp_ping
        port: aunque viene uno por defecto en realidad puede ser una lista de puertos o uno solo
    Retorna:
        Devuelve un booleano de cierto o falso, si se detecta el host vivo
    """
    packet = IP(dst=host)/TCP(sport=RandShort(), dport=port, flags="S")
    reply = sr1(packet, timeout=1, verbose=False)
    #if reply and reply.haslayer(TCP) and reply.getlayer(TCP).flags == 0x12:
    #if reply is not None: 
    #    if reply.haslayer(TCP) and reply.haslayer(TCP) == "R" or reply.haslayer(TCP) == "SA":
    #        return True
    #return False
    packet = IP(dst=host)/TCP(sport=RandShort(), dport=port, flags="S")
    reply = sr1(packet, timeout=1, verbose=False)
    if reply:
        if reply.haslayer(TCP) and reply.getlayer(TCP).flags == 0x12 or reply.getlayer(TCP).flags == 0x14:
            return True
    return False

#
def udp_ping(host, port=0):
    """
    Realiza un UDP Ping al puerto especificado con payload específico según el puerto.
    
    Args:
        host: la IP de la máquina a la que se le quiere realizar un udp ping
        port: debe ser un puerto 
    Retorna:
        Un booleano indicando si el host esta vivo o no en base a la respuesta o no de los paquetes enviados
    """
    # Usar el payload específico si existe, o un genérico
    pre_payload = udp_payloads.get(str(port))
    if pre_payload is None:
        dst_port = 0
        payload = eval(udp_payloads.get(str(dst_port)))
    else:
        payload = eval(pre_payload)

    packet = IP(dst=host)/UDP(sport=RandShort(), dport=port)/ payload
    try:
        reply = sr1(packet, timeout=2, verbose=False)
        if reply is None:
            return False
        if reply.haslayer(UDP):
            print(f"[+] Respuesta UDP recibida desde {host}:{port}")
            return True
        elif reply.haslayer(ICMP):
            icmp_type = reply.getlayer(ICMP).type
            icmp_code = reply.getlayer(ICMP).code
            if icmp_type == 3 and icmp_code == 3:
                return True  # Consideramos el host vivo aunque el puerto esté cerrado
            return False
        else:
            return False
    except Exception as e:
        print(f"[!] Error al enviar paquete UDP: {e}")
        return False

# Implementa el icmp ping por defecto ya incluye una lista con varios tipos
def icmp_ping(host, types=[8, 13, 17]):
    """
    Realiza un ICMP Ping usando los tipos de paquete especificados.

    Args:
        host: la direccion IP de la maquina que se quiere comprobar
        types: el o los tipos de icmp que se van a enviar para determinar si el host esta vivo
    Retorna:
        Un valor booleano si el host ha respondiendo a algun tipo de icmp
    """
    for icmp_type in types:
        packet = IP(dst=host)/ICMP(type=icmp_type, code=0)
        reply = sr1(packet, timeout=1, verbose=False)
        if reply is not None:
            return True
    return False

# Esta función lanza los diferentes tipos de ping, desgranando la subred en cada una de sus IPs o solo al host target
def ping_hosts(target, method="icmp", pt=8):
    """
    Ping de host o subred usando el método especificado: icmp, tcp o udp.

    Args:
        target: la IP o subred objetivo de para saber que máquinas están vivas
        method: aunque indica por defecto icmp, en realidad es cualquiera de los que tenemos icmp, tcp, udap
    Retorna:
        Todos los hosts revisados a nivel de IP y si están vivos o muertos (han dado la respueta esperada o no)
    """
    results = {}
    dead_count = 0

    # Verificar si el objetivo es una subred (CIDR)
    if "/" in target:
        print(f"[+] Realizando ping en la subred: {target} usando {method}...")
        # Generar la lista de IPs en la subred usando ipaddress
        hosts = [str(ip) for ip in ipaddress.IPv4Network(target, strict=False)]
        ip_red, ip_broadcast = calcular_ip_red_y_broadcast(target)
        size = calcular_ips_subred(target)
        print(f"Escaneando {size} direcciones IP")
        for ip in hosts:
            if str(ip) != str(ip_red) and str(ip) != str(ip_broadcast): 
                is_alive = ping_host_single(ip, method, pt)
                if is_alive:
                    results[ip] = "Vivo"
                else:
                    dead_count += 1
                    results[ip] = "Muerto"
    else:
        # Hacer ping a un único host
        is_alive = ping_host_single(target, method, pt)
        if is_alive:
            results[target] = "Vivo"
        else:
            dead_count += 1
            results[target] = "Muerto"

    print(f"\n[+] Resultados del {method} ping:")
    for ip, status in results.items():
        if status == "Vivo":
            print(f"Host: {ip} - Estado: {status}")
    print(f"\nTotal de hosts muertos: {dead_count}")
    return results

# Lanza las diferentes funciones de ping en función del método
def ping_host_single(target, method, pt):
    """
    Ping de un único host usando el método especificado.

    Args:
        target: es el host (IP) que se quiere comprobar
        method: el método utilizado para la comprobación
        pt: pueden ser el puerto/s o los tipos si fuera icmp
    Retorna:
        Si todo va bien nada, sino un booleando indicado "False" si el método usado no esta previsto (implementado)
    """
    if method == "icmp":
        return icmp_ping(target, pt)
    elif method == "tcp":
        return tcp_ping(target, pt)
    elif method == "udp":
        return udp_ping(target, pt)
    else:
        print(f"[!] Método de ping desconocido: {method}")
        return False

# Realiza el SYN Scan a un host o subred al puerto/s indicados
def syn_scan(target, ports, banner=False):
    """
    Realiza un escaneo SYN en los puertos especificados.

    Args:
        target: la IP del host o subred que se quiere escanear
        ports: el puerto o la lista de puertos
        banner: por defecto a False, pero sirve para saber si tiene que recopilar los banners de los servicios
    Retorna:
        Todos los hosts que están vivos y que el estado de sus puertos en función de las respuetas recibidas
    """
    # Enable filtering: only Ether, IP and ICMP will be dissected
    print(f"Iniciando SYN Scan en {target}...")
    results = {}
    banners = {}

    vivos = arp_ping(target)
    # Verificar si el target es una subred (CIDR)
    if "/" in target:
        print(f"[+] Realizando escaneo en la subred: {target}")
        # Generar la lista de IPs en la subred
        hosts = [str(ip) for ip in ipaddress.IPv4Network(target, strict=False)]
        ip_red, ip_broadcast = calcular_ip_red_y_broadcast(target)
        size = calcular_ips_subred(target)
        print(f"Escaneando {size} direcciones IP")
        for ip in hosts:
            if str(ip) != str(ip_red) and str(ip) != str(ip_broadcast): 
                #print(f"Host: {ip}")
                 alive = ip_is_alive(ip, vivos)
                 if alive or ignore:
                     host_results = syn_scan_host(ip, ports, banner)
                     results[ip] = host_results
    else:
        # Escanear un único host
        alive = ip_is_alive(target, vivos)
        if alive or ignore:
            host_results = syn_scan_host(target, ports, banner)
            results[target] = host_results

    print("\n[+] Resultados del escaneo completo:")
    for host, ports_info in results.items():
        print(f"\nHost: {host}")
        if not banner:
            open_ports = {port: status for port, status in ports_info.items() if status == "Abierto"}
        else:
            open_ports = {port: status for port, status in ports_info.items() if status != "Cerrado" and status != "Filtrado o no respondido"}
        closed_ports_count = sum(1 for status in ports_info.values() if status == "Cerrado")
        filtered_ports_count = sum(1 for status in ports_info.values() if status == "Filtrado o no respondido")
        
        for port, status in open_ports.items():
            print(f"  Puerto {port}: {status}")
        print(f"  Puertos cerrados (rechazados): {closed_ports_count}")
        print(f"  Puertos filtrados (sin respuesta): {filtered_ports_count}")
    return results

# Esta función realiza el SYN scan a una sola máquina
def syn_scan_host(target, ports, banner=False):
    """
    Escaneo SYN de un único host.

    Args:
        target: es la IP de un host
        ports: el puerto o lista de puertos a escanear
        banner: para saber si tiene que recoger información de banner grabbind del puerto o no
    Retorna:
        El estado de cada puerto y si están abiertos y se ha solicitado el banner pues la información que haya obtenido
    """
    results = {}
    banners = {}
    for port in ports:
        src_port=RandShort()
        packet = IP(dst=target)/TCP(sport=src_port, dport=port, flags="S")
        reply = sr1(packet, timeout=0.5, verbose=False)

        if reply is None:
            results[port] = "Filtrado o no respondido"
        elif reply.haslayer(TCP):
            tcp_flags = reply.getlayer(TCP).flags
            if tcp_flags == 0x12:
                if banner:
                    service = banner_grabbing(target, port)
                    results[port] = "Abierto - " + service
                else:
                    results[port] = "Abierto"
                # Enviar un RST para cerrar la conexión
                send(IP(dst=target)/TCP(sport=src_port, dport=port, flags="R"), verbose=False)
            elif tcp_flags == 0x14:
                results[port] = "Cerrado"
        else:
            results[port] = "Desconocido"
    return results

# Implementa el scan TCP Connect al host o subred objetivo
def tcp_scan(target, ports):
    """
    Realiza un escaneo TCP Connect en los puertos especificados.

    Args:
        target: el host o subred objetivo del scan
        ports: el puerto o lista de puertos que se quiere escanear
    Retorna:
        Los hosts que están vivos con la información del estado de sus puertos
    """
    # Enable filtering: only Ether, IP and ICMP will be dissected
    print(f"Iniciando TCP Connect Scan en {target}...")
    results = {}

    vivos = arp_ping(target)
    # Verificar si el target es una subred (CIDR)
    if "/" in target:
        print(f"[+] Realizando escaneo en la subred: {target}")
        # Generar la lista de IPs en la subred
        hosts = [str(ip) for ip in ipaddress.IPv4Network(target, strict=False)]
        ip_red, ip_broadcast = calcular_ip_red_y_broadcast(target)
        size = calcular_ips_subred(target)
        print(f"Escaneando {size} direcciones IP")
        for ip in hosts:
            if str(ip) != str(ip_red) and str(ip) != str(ip_broadcast): 
                #print(f"Host: {ip}")
                 alive = ip_is_alive(ip, vivos)
                 if alive or ignore:
                     host_results = tcp_scan_host(ip, ports)
                     results[ip] = host_results
    else:
        # Escanear un único host
        alive = ip_is_alive(target, vivos)
        if alive or ignore:
            host_results = tcp_scan_host(target, ports)
            results[target] = host_results

    print("\n[+] Resultados del escaneo completo:")
    for host, ports_info in results.items():
        print(f"\nHost: {host}")
        open_ports = {port: status for port, status in ports_info.items() if status == "Abierto"}
        closed_ports_count = sum(1 for status in ports_info.values() if status == "Cerrado")
        filtered_ports_count = sum(1 for status in ports_info.values() if status == "Filtrado o no respondido" or status == "Filtrado")
        for port, status in open_ports.items():
            print(f"  Puerto {port}: {status}")
        print(f"  Puertos cerrados (rechazados): {closed_ports_count}")
        print(f"  Puertos filtrados (sin respuesta): {filtered_ports_count}")
        #print(results)
    return results

# Escanear un solo host con el metodo TCP Connect
def tcp_scan_host(target, ports):
    """
    Escaneo SYN de un único host.

    Args:
        target: la IP del host a escanear
        ports: el puerto o puertos/s que se van a revisar durante el scan
    Retorna:
        Los estados de los puertos de ese host
    """
    results = {}
    for port in ports:
        src_port=RandShort()  # Usamos diferentes puertos origen
        packet = IP(dst=target)/TCP(sport=src_port, dport=port, flags="S")
        reply = sr1(packet, timeout=0.5, verbose=False)

        if reply is None:
            results[port] = "Filtrado o no respondido"
        elif reply.haslayer(TCP):
            tcp_flags = reply.getlayer(TCP).flags
            if tcp_flags == 0x12:
                results[port] = "Abierto"
                # Completar el 3-way handshake con un paquete ACK
                ack_packet = IP(dst=str(target))/TCP(sport=src_port, dport=port, flags="A", seq=reply[TCP].ack, ack=reply[TCP].seq + 1)
                send(ack_packet, verbose=False)
                # Enviar RST para cerrar la conexión
                rst_packet = IP(dst=str(target))/TCP(sport=src_port, dport=port, flags="R", seq=reply[TCP].ack, ack=reply[TCP].seq + 1)
                send(rst_packet, verbose=False)
            elif tcp_flags == 0x14:
                results[port] = "Cerrado"
        elif reply.haslayer(ICMP):
            if int(reply.getlayer(ICMP).type) == 3 and int(reply.getlayer(ICMP).code) in [1, 2, 3, 9, 10, 13]:
                results[port] = "Filtrado"
        else:
            results[port] = "Desconocido"
    return results

# Scan utilizando el método ACK para obtener puertos filtrados y no filtrados
def ack_scan(target, ports):
    """
    Realiza un escaneo ACK en los puertos especificados.

    Args:
        target: el host o subred en formato CIDR objetivo del scan
        ports: el puerto/s que se van a revisar durante el scan
    Retorna:
        Para cada host que esta vivo si los puertos escaneados estan filtrados o no
    """
    # Enable filtering: only Ether, IP and ICMP will be dissected
    print(f"Iniciando ACK Scan en {target}...")
    results = {}

    vivos = arp_ping(target)
    # Verificar si el target es una subred (CIDR)
    if "/" in target:
        print(f"[+] Realizando escaneo en la subred: {target}")
        # Generar la lista de IPs en la subred
        #hosts = [str(ip) for ip in scapy.IPNetwork(target)]
        #hosts = IPNetwork(target)
        hosts = [str(ip) for ip in ipaddress.IPv4Network(target, strict=False)]
        ip_red, ip_broadcast = calcular_ip_red_y_broadcast(target)
        size = calcular_ips_subred(target)
        print(f"Escaneando {size} direcciones IP")
        for ip in hosts:
            if str(ip) != str(ip_red) and str(ip) != str(ip_broadcast): 
                #print(f"Host: {ip}")
                 alive = ip_is_alive(ip, vivos)
                 if alive or ignore:
                     host_results = ack_scan_host(ip, ports)
                     results[ip] = host_results
    else:
        # Escanear un único host
        alive = ip_is_alive(target, vivos)
        if alive or ignore:
            host_results = ack_scan_host(target, ports)
            results[target] = host_results

    print("\n[+] Resultados del escaneo completo:")
    for host, ports_info in results.items():
        print(f"\nHost: {host}")
        unfiltered_ports_count = sum(1 for status in ports_info.values() if status == "No filtrado")
        filtered_ports_count = sum(1 for status in ports_info.values() if status == "Filtrado o no respondido" or status == "Filtrado")
        #for port, status in open_ports.items():
        #    print(f"  Puerto {port}: {status}")
        print(f"  Puertos no filtrados (reset): {unfiltered_ports_count}")
        print(f"  Puertos filtrados (sin respuesta): {filtered_ports_count}")
    return results

# Implementa el ACK Scan para un host concreto
def ack_scan_host(target, ports):
    """
    Escaneo SYN de un único host.

    Args:
        target: la IP del host a escanear
        ports: el puerto/s que se van a escanear para determinar su estado
    Retorna:
        El estado de los puertos de ese host en concreto si esta filtrado o no hay respuesta o si no lo esta
    """
    results = {}
    for port in ports:
        src_port=RandShort()  # Usamos diferentes puertos origen
        packet = IP(dst=target)/TCP(sport=src_port, dport=port, flags="A")
        reply = sr1(packet, timeout=0.5, verbose=False)

        if reply is None:
            results[port] = "Filtrado o no respondido"
        elif reply.haslayer(TCP):
            tcp_flags = reply.getlayer(TCP).flags
            #print(tcp_flags)
            if tcp_flags == "R" or tcp_flags == 0x14:
                results[port] = "No filtrado" # RST or RST-ACK
                #print(results[port])
        elif reply.haslayer(ICMP):
            icmp_type = int(reply.getlayer(ICMP).type)
            icmp_code = int(reply.getlayer(ICMP).code)
            if icmp_type == 3 and icmp_code in [1, 2, 3, 9, 10, 13]:
                results[port] = "Filtrado"
        else:
            results[port] = "Desconocido"
    return results

# Cargar el archivo de cargas útiles UDP
def load_udp_payloads(filepath="udp_payloads.json"):
    """
    Cargar los payloads de un fichero que se utilizan como parte de protocolos UDP

    Args:
        filtepath: la ruta y nombre de fichero donde estan los payloads en formato json
    Retorna:
        El contenido del fichero en formato JSON o vacio si no puede cargarlo
    """
    try:
        with open(filepath, "r") as file:
            return json.load(file)
    except Exception as e:
        print(colored(f"[ERROR] Unable to load payloads: {e}", "red"))
        return {}

# Realiza un UDP Scan al host o subred objetivo informado en formato CIDR
def udp_scan(target, ports):
    """
    Realiza un escaneo UDP en los puertos especificados.

    Args:
        target: el host o la subred objetivo del scan
        ports: el puerto o lista de puertos objetivo del scan
    Retorna:
        Todo los hosts que están vivos con la información del estado del puerto/s que haya podido obtener en el scan
    """
    # Enable filtering: only Ether, IP and ICMP will be dissected
    print(f"Iniciando UDP Scan en {target}...")
    results = {}

    vivos = arp_ping(target)
    # Verificar si el target es una subred (CIDR)
    if "/" in target:
        print(f"[+] Realizando escaneo en la subred: {target}")
        # Generar la lista de IPs en la subred
        hosts = [str(ip) for ip in ipaddress.IPv4Network(target, strict=False)]
        ip_red, ip_broadcast = calcular_ip_red_y_broadcast(target)
        size = calcular_ips_subred(target)
        print(f"Escaneando {size} direcciones IP")
        for ip in hosts:
            if str(ip) != str(ip_red) and str(ip) != str(ip_broadcast): 
                #print(f"Host: {ip}")
                 alive = ip_is_alive(ip, vivos)
                 if alive or ignore:
                     host_results = udp_scan_host(ip, ports)
                     results[ip] = host_results
    else:
        # Escanear un único host
        alive = ip_is_alive(target, vivos)
        if alive or ignore:
            host_results = udp_scan_host(target, ports)
            results[target] = host_results

    print("\n[+] Resultados del escaneo completo:")
    for host, ports_info in results.items():
        print(f"\nHost: {host}")
        open_ports = {port: status for port, status in ports_info.items() if status == "Abierto" or status == "Abierto|Filtrado"}
        closed_ports_count = sum(1 for status in ports_info.values() if status == "Cerrado")
        for port, status in open_ports.items():
            print(f"  Puerto {port}: {status}")
        print(f"  Puertos cerrados (rechazados): {closed_ports_count}")
        #print(results)
    return results

# Realiza un UDP Scan al host y puerto/s indicados
def udp_scan_host(target, ports):
    """
    Escaneo SYN de un único host.

    Args:
        target: el host objetivo del scan, una IP
        ports: el puerto o lista de ellos que se va a escanear
    Retorna:
        Nos devolverá el estado de los puertos revisados para este host segun las condiciones de la funcion
    """
    results = {}
    for port in ports:
        # Cargar el payload específico desde el archivo o usar un payload genérico
        pre_payload = udp_payloads.get(str(port))
        if pre_payload is None:
            dst_port = 0
            payload = eval(udp_payloads.get(str(dst_port)))
        else:
            payload = eval(pre_payload)

        pkt = IP(dst=target) / UDP(sport=RandShort(), dport=port) / payload

        response = sr1(pkt, timeout=1, verbose=False)
        if response is None:
            results[port] = "Abierto|Filtrado"
            #print(colored(f"[+] {ip}:{port}/UDP - Open|Filtered", "green"))
        elif response.haslayer(UDP):
            results[port] = "Abierto"
            #print(colored(f"[+] {ip}:{port}/UDP - Open", "yellow"))
        elif response.haslayer(ICMP):
            icmp_type = response.getlayer(ICMP).type
            icmp_code = response.getlayer(ICMP).code
            if icmp_type == 3 and icmp_code in [1, 2, 3, 9, 10, 13]:
                results[port] = "Cerrado"
                #print(colored(f"[-] {ip}:{port}/UDP - Closed", "red"))
            else:
                results[port] = "Desconocido"
                #print(colored(f"[?] {ip}:{port}/UDP - Unknown ICMP response", "magenta"))
    return results

# Se conecta al puerto e intenta recopilar la informacion de un banner
def banner_grabbing(target, port):
    """
    Obtención de banners de servicios.

    Args:
        target: el host objetivo
        posr: el puerto objetivo
    Retorna:
        El banner si lo ha encontrado o desconocido si no ha recopilado nada
    """
    try:
        s = socket.socket()
        s.settimeout(2)
        s.connect((target, port))
        #s.send('HEAD / HTTP/1.1 \r\n')
        banner = s.recv(1024) 
        s.close()
        svc_banner = banner.decode().strip()
        svc_banner = svc_banner.replace('220 ', '')
        return svc_banner
    except:
        return "Desconocido"

# Scan de cabeceras HTTP 
def http_header_scan(target, ports):
    """
    Scanner de cabeceras HTTP que se puede utilizar para http/s
    
    Args:
        target: el host o la subred objetivo en formado CIDR
        ports: el puerto/s que se van a revisar en el scan
    Retorna:
        Los hosts que están vivos con la información de cabeceras
    """
    open_hosts_ports = syn_scan(target, ports)

    print("\n[+] Resultados del escaneo HTTP Headers:")
    results = {}
    for host, ports_info in open_hosts_ports.items():
        headers = {}
        open_ports = {port: status for port, status in ports_info.items() if status == "Abierto"}
        if open_ports:
            print(f"\nHost: {host}")
        for port, status in open_ports.items():
            cabeceras = http_header_analysis(host, port)
            headers[port] = cabeceras
            if cabeceras:
                #print(f"   Puerto {port}: {headers[port]}")
                print(f"   Puerto {port}:")
                for key in cabeceras:
                    if key == "Server" or key[:2] == "X-" or key == "Via":
                        value = cabeceras[key]
                        print(f"      {key}: {value}")
            else:
                print(f"   Puerto {port}:\n      No se ha podido acceder a cabeceras http")
        if headers != {}:
            results[host] = headers
    return results

# Aquí recopila la información de cabeceras para un solo host
def http_header_analysis(target, port):
    """
    Obtiene cabeceras HTTP y HTTPS para identificar tecnologías en múltiples puertos.

    Args:
        target: el host al que se van a analizar las cabeceras
        port: el puerto que esta abierto y que vamos a intentar recopilar cabeceras http
    Retorna:
        Devuelve todas las cabeceras http que haya encontrado
    """
    requests.packages.urllib3.disable_warnings(requests.packages.urllib3.exceptions.InsecureRequestWarning)
    error = {}
    for use_https in [False, True]:  # Probar tanto HTTP como HTTPS en cada puerto
        try:
            protocol = "https" if use_https else "http"
            if use_https:
                response = requests.get(f"https://{target}:{port}", timeout=3, verify=False)
                return response.headers
            else:
                response = requests.get(f"http://{target}:{port}", timeout=3)
                return response.headers

        except Exception as e:
            #print(colored(f"[!] Error obteniendo cabeceras de {protocol}://{target}:{port} - {e}", "red"))
            #error = {"Error": "Error obteniendo cabeceras de {protocol}://{target}:{port} - {e}"}
            error[protocol] = {"Error": e}

# Intenta detectar el SO del host/s objetivo usando puertos TCP
def detect_os_network(target,ports):
    """
    Detecta el sistema operativo en una red (CIDR) o un host único.

    Args:
        target: el host o la subred en formato CIDR
        ports: el puerto/s que se van a revisar en el scan
    """
    vivos = arp_ping(target)
    # Verificar si el target es una subred (CIDR)
    if "/" in target:
        # Verificar si el target es una subred o una IP individual
        hosts = [str(ip) for ip in ipaddress.IPv4Network(target, strict=False)]
        ip_red, ip_broadcast = calcular_ip_red_y_broadcast(target)
        size = calcular_ips_subred(target)
        print(f"[+] Escaneando la red: {target} para detectar sistemas operativos...")

        print(f"\n[+] Resultados del OS Discover completo:")
        for ip in hosts:
            if str(ip) != str(ip_red) and str(ip) != str(ip_broadcast): 
                alive = ip_is_alive(ip, vivos)
                if alive or ignore:
                    print(f"\nHost: {ip} is alive")
                    detect_os(ip, ports)
    else:
        # Escanear un único host
        alive = ip_is_alive(target, vivos)
        if alive or ignore:
            print(f"\nHost: {target} is alive")
            detect_os(target, ports)
        else:
            print(f"\nHost: {target} is not alive")

# Implementa el descubrimiento de OS para un host
def detect_os(ip, ports=445):
    """
    Implementa un SYN Scan para determiinar si el puerto esta abierto y con las respuestas saber que SO es

    Args:
        ip: la dirección IP del host objetivo
        ports: aunque tiene uno por defecto serán los que se le indiquen, ya se puerto/s para escanear
    """
    tcp_response = False
    host = {}
    for port in ports:
        src_port = RandShort()
        syn_packet = IP(dst=ip) / TCP(sport=src_port, dport=port, flags="S")
        response1 = sr1(syn_packet, timeout=1, verbose=False)

        if response1 is not None:
            if response1.haslayer(TCP) and response1.getlayer(TCP).flags == 0x12 or response1.getlayer(TCP).flags == 0x14:  # SYN-ACK or RST
                ttl = response1.ttl
                window_size = response1.window
                if response1.getlayer(TCP).flags == 0x12:
                    host[port] = "Abierto"
                    print(colored(f"[+] Port {port} open - TTL: {ttl}, Window Size: {window_size}", "green"))
                    tcp_response = True
                    break
                elif response1.getlayer(TCP).flags == 0x14:
                    host[port] = "Cerrado"
                    #print(colored(f"[+] Port {port} closed - TTL: {ttl}, Window Size: {window_size}", "red"))
            tcp_response = True
    if tcp_response and host[port] == "Cerrado":
        print(colored(f"[+] Port {port} closed - TTL: {ttl}, Window Size: {window_size}", "red"))
        

    if not tcp_response:
        icmp_packet = IP(dst=ip) / ICMP(type=icmp_ping_types, code=0)
        response2 = sr1(icmp_packet, timeout=1, verbose=False)
        
        if response2 is not None:
            if response2.haslayer(ICMP):
                ttl = response2.ttl
                window_size = 0
                print(colored(f"[-] No response or port {port} closed", "red"))
    
    # Identificación del Sistema Operativo
    os_info = "Unknown"
    if ttl >= 128:
        os_info = "Windows"
        if window_size == 8192:
            os_info = "Windows XP/Server 2003"
        elif window_size == 65392:
            os_info = "Windows 10/Server 2016 o superior"
        elif window_size == 8192 or window_size == 16384:
            os_info = "Windows 7/8"
    elif ttl >= 64:
        os_info = "Linux"
        if window_size == 5840:
            os_info = "Linux Kernel 2.4-2.6"
        elif window_size == 64240 or window_size == 65535:
            os_info = "Linux Kernel 2.6+"
        elif window_size == 14600:
            os_info = "FreeBSD"
    elif ttl >= 255:
        os_info = "AIX / Solaris / Cisco IOS"
        if window_size == 4128:
            os_info = "Solaris"
        elif windows_size == 16384:
            os_info = "AIX / Cisco IOS"

        
    print(colored(f"[+] Operating System detected: {os_info}", "yellow"))
    if response1 is not None:
        if response1.getlayer(TCP).flags == 0x12:
            # Enviar RST para cerrar la conexión
            rst_packet = IP(dst=ip) / TCP(sport=src_port, dport=port, flags="R")
            send(rst_packet, verbose=False)

# Para saber si pertenece a una lista de hosts que responden, estan activos
def ip_is_alive(ip, hosts):
    """
    Funcion auxiliar que revisa si la IP pertenece a una lista de hosts que están activos

    Args:
        ip: la dirección IP que se quiere consultar
        hosts: es la salida de un ARP Ping que contiene una lista de tuplas
    Retorna:
        Un booleano si la máquina esta vivo o no, si esta en la lista o no
    """
    is_alive = False
    for host, mac, vendor in hosts:
         if str(ip) == str(host):
             is_alive = True
    return is_alive

# Informa si una IP no pertenece a alguna red local de nuestra máquina
def is_not_local_network(target):
    """
    Es una funcion auxiliar que revisa si el target indicado pertenece a la red local

    Args:
        target: IP a revisar
    Retorna:
        Un valor booleano, será True si no pertenece a la red local y False si pertenece
    """
    try:
        # Obtener la lista de interfaces IP de la máquina local
        local_ips = [ip for ip in ipaddress.IPv4Network('127.0.0.0/8').hosts()]  # Loopback

        # Añadir interfaces de red activas
        import psutil
        for iface, addrs in psutil.net_if_addrs().items():
            for addr in addrs:
                if addr.family == 2:  # IPv4
                    local_ips.append(ipaddress.IPv4Address(addr.address))

        # Verificar si el target es una red o un host
        try:
            network = ipaddress.ip_network(target, strict=False)
        except ValueError:
            network = ipaddress.ip_network(f"{target}/32")

        # Verificar si la red objetivo coincide con alguna interfaz local
        for local_ip in local_ips:
            if local_ip in network:
                return False
        return True
    except Exception as e:
        print(colored(f"[ERROR] Unable to determine local network: {e}", "red"))
        return True

#
# Programa principal
#

# Preparar lectura de parametros
parser = argparse.ArgumentParser(description="Escáner de red avanzado utilizando Scapy")
parser.add_argument("-t", "--target", required=True, help="Dirección IP o red objetivo (Ejemplo: 192.168.1.1 o 192.168.1.0/24)")
parser.add_argument("-p", "--ports", type=str, help="Lista de puertos separados por comas (Ejemplo: 22,80,443), 'all' para escanear 1-65535, 'fast' para los 100 más usados, o por defecto los 1000 más usados", default="default")
parser.add_argument("-s", "--scan", choices=["arp_ping", "icmp_ping", "tcp_ping", "udp_ping", "syn", "tcp", "ack", "udp", "banner", "http", "os"], required=True, help="Tipo de escaneo a realizar")
parser.add_argument("-u", "--update", action="store_true", help="Actualizar BBDD de identificadores MAC for vendors")
parser.add_argument("-n", "--out", action="store_true", help="Indica que la IP o subred \"target\" no es de la red local")

# Algunas definiciones de puertos
common_ports_100 = [25, 443, 1720, 22, 1723, 1025, 8888, 111, 23, 3306, 80, 995, 3389, 993, 53, 139, 135, 554, 110, 199, 5900, 21, 445, 143, 113, 587, 8080, 514, 990, 49156, 2000, 6646, 8009, 5009, 389, 49157, 88, 8000, 13, 465, 37, 5051, 144, 1900, 548, 7070, 444, 10000, 5190, 1029, 631, 8443, 1026, 2121, 1755, 9999, 2049, 6001, 106, 2717, 515, 5800, 1028, 513, 26, 49152, 9100, 6000, 4899, 5060, 5666, 1110, 49155, 544, 8008, 7, 5432, 2001, 5631, 5357, 543, 81, 119, 1433, 1027, 49154, 5000, 646, 3128, 5101, 873, 32768, 427, 8081, 49153, 3000, 9, 3986, 79, 179]  # Top 100 ports nmap

common_ports_1000 = [3306, 3389, 443, 22, 113, 587, 1720, 143, 80, 445, 1025, 199, 111, 21, 1723, 993, 5900, 25, 995, 23, 135, 53, 110, 256, 554, 8080, 139, 8888, 63331, 8402, 9999, 1068, 2126, 3372, 2135, 5877, 2065, 9071, 15742, 9003, 34573, 2043, 903, 8194, 5801, 9944, 458, 7025, 1091, 2717, 5298, 2047, 65000, 32783, 10024, 843, 9011, 3737, 5060, 7496, 8089, 1141, 4446, 1175, 8045, 9103, 49161, 3998, 9, 1352, 34572, 16018, 7100, 43, 5989, 30718, 8084, 1131, 14441, 8099, 3826, 5001, 1166, 4899, 45100, 1105, 31337, 765, 16113, 8200, 32778, 5432, 3880, 8192, 1064, 6001, 32, 20031, 10243, 7741, 15003, 3370, 1021, 8500, 1600, 84, 2701, 49156, 17, 6059, 1524, 20828, 4111, 5811, 6779, 1165, 99, 1501, 1217, 20221, 1218, 55555, 10025, 6004, 1058, 306, 3052, 5903, 9503, 9050, 5100, 62078, 1026, 1717, 4567, 9080, 9110, 2602, 900, 6566, 16012, 5985, 15002, 5560, 2121, 8800, 2100, 9898, 1039, 4002, 1093, 5962, 8994, 1089, 5950, 617, 12174, 5221, 3168, 57294, 5986, 2251, 8291, 808, 26, 544, 7938, 1082, 44442, 7001, 1658, 2200, 12000, 65129, 19, 3851, 33354, 2003, 1719, 16001, 726, 5730, 50000, 5002, 1031, 60020, 1875, 2968, 9575, 15004, 6543, 119, 1755, 3333, 8093, 2800, 18101, 1271, 1151, 8088, 9900, 2049, 2021, 1417, 5810, 65389, 524, 1007, 1433, 6667, 1147, 9878, 1040, 3920, 10778, 55055, 1009, 3580, 2068, 5280, 4006, 1083, 9666, 32769, 2099, 1972, 49155, 543, 3800, 3369, 1114, 2119, 5550, 5915, 19315, 4126, 6901, 417, 54045, 912, 301, 56737, 6969, 5822, 6789, 27356, 1069, 49400, 10003, 1122, 1051, 1864, 44501, 9876, 1119, 3001, 1085, 8300, 7778, 11110, 444, 5003, 2144, 3, 212, 3006, 4003, 49153, 5555, 1102, 648, 26214, 1002, 2394, 1037, 3476, 1287, 5566, 9102, 990, 50800, 7911, 9593, 3889, 1461, 1309, 9929, 8042, 1100, 9200, 1010, 8652, 10012, 1839, 1234, 254, 19842, 3546, 6123, 34571, 7625, 49160, 9415, 1076, 465, 144, 2492, 100, 1334, 1099, 1556, 2020, 16016, 5214, 1272, 60443, 1805, 9040, 7002, 6668, 18040, 8085, 19801, 5987, 416, 20000, 2161, 4000, 5440, 1097, 2041, 2366, 691, 999, 32770, 667, 6006, 5862, 3945, 2811, 16993, 1117, 6839, 10215, 13722, 6389, 515, 211, 3005, 7000, 8193, 1084, 3493, 1079, 563, 50003, 6567, 3260, 5226, 2004, 1055, 646, 8007, 5061, 22939, 3221, 3828, 2038, 2869, 79, 1048, 2998, 5679, 1094, 801, 1311, 2000, 163, 90, 666, 14000, 5080, 777, 6129, 1060, 1072, 2008, 1126, 1132, 2910, 5087, 3030, 2301, 24, 3011, 27715, 49167, 1533, 15660, 4005, 1049, 1322, 5800, 24444, 5998, 3971, 49159, 5269, 2875, 19780, 49, 464, 5666, 3801, 389, 1086, 1095, 2909, 6580, 28201, 3324, 6101, 5718, 1236, 3325, 1059, 9111, 11967, 32784, 9001, 2034, 2399, 16992, 481, 2393, 24800, 1052, 1503, 1046, 1721, 52673, 8292, 10616, 4449, 1862, 3003, 3703, 981, 1066, 7443, 1914, 8031, 1812, 1, 5009, 2105, 4445, 6565, 1494, 6510, 49158, 5033, 1174, 17877, 2048, 4848, 85, 1062, 5500, 1078, 5906, 1247, 1043, 6100, 32775, 5925, 6646, 5102, 8010, 49163, 5633, 4443, 9081, 2607, 3659, 2190, 1761, 10009, 1700, 1185, 32768, 2725, 38292, 2111, 4662, 2170, 787, 44176, 3077, 5631, 636, 27353, 14238, 55600, 5901, 50636, 1594, 4550, 720, 4224, 3128, 20222, 5050, 9207, 2702, 2718, 161, 83, 4279, 61532, 1081, 1033, 5911, 2288, 2381, 50001, 1187, 6346, 9917, 1301, 9618, 8290, 49154, 6112, 9002, 5414, 1199, 3261, 6000, 9010, 8011, 30000, 5952, 32776, 6025, 1098, 8400, 1801, 8181, 17988, 264, 6547, 3914, 1900, 9091, 1783, 1080, 9968, 2500, 27352, 1186, 27355, 3322, 2103, 1063, 2260, 902, 3551, 1042, 2191, 35500, 311, 50300, 13783, 366, 340, 5850, 1984, 1310, 1030, 631, 1666, 3527, 625, 3071, 4045, 1216, 6689, 8180, 5190, 425, 1840, 2179, 2046, 50389, 5988, 7921, 2001, 9220, 4125, 1113, 1073, 7920, 2035, 54328, 9090, 6009, 541, 6881, 10010, 4343, 3871, 11111, 1108, 9998, 5510, 3814, 8383, 9502, 19283, 109, 1045, 6666, 6699, 2002, 1455, 32779, 21571, 2160, 30, 40193, 1107, 1152, 593, 2045, 3878, 179, 8009, 2196, 1053, 3995, 2106, 1688, 9595, 992, 2809, 64623, 1233, 5963, 5961, 2222, 13456, 1070, 1183, 49176, 2557, 5678, 3809, 1087, 705, 9009, 1935, 280, 14442, 1110, 1248, 50002, 7200, 4900, 3905, 1027, 8000, 6669, 911, 1092, 5960, 6792, 8082, 1148, 4129, 3986, 1056, 20005, 1028, 8254, 10628, 3300, 1149, 7937, 27000, 3404, 3268, 5225, 1041, 1123, 3827, 16080, 1065, 427, 146, 407, 31038, 1074, 7512, 6692, 9000, 1001, 2601, 616, 1164, 8090, 19101, 1022, 4444, 1138, 5030, 1521, 1641, 3031, 2030, 3301, 1111, 5825, 880, 1032, 32777, 20, 1061, 2522, 16000, 7402, 18988, 2382, 2323, 5101, 2009, 42, 40911, 10566, 1443, 55056, 1782, 512, 1213, 9535, 1121, 82, 5859, 8899, 49152, 555, 6003, 1163, 1054, 8081, 1023, 901, 1077, 5902, 8083, 749, 7070, 23502, 5054, 2005, 4242, 687, 1259, 10000, 8649, 873, 33, 1974, 3351, 406, 2920, 1071, 1106, 13, 81, 8600, 64680, 500, 1328, 1687, 9485, 1434, 5200, 51103, 1112, 42510, 6502, 5431, 7019, 2383, 30951, 514, 7435, 10629, 2638, 6156, 4, 9877, 9594, 32785, 12265, 10001, 10082, 9101, 2710, 52822, 714, 1130, 5910, 6002, 1863, 8654, 2042, 9290, 1035, 1137, 7201, 6788, 2033, 5959, 1047, 8001, 255, 8100, 1029, 1050, 497, 683, 1296, 49165, 987, 5907, 3766, 10002, 49157, 2007, 3367, 25734, 545, 2006, 32773, 10621, 50006, 1124, 70, 5802, 57797, 1244, 48080, 125, 2605, 2040, 4321, 89, 548, 1104, 1580, 888, 1999, 58080, 4001, 9099, 1718, 5544, 2013, 8022, 3918, 13782, 32780, 8008, 7, 1300, 5000, 9500, 10004, 25735, 3390, 5222, 1044, 4998, 2022, 3690, 106, 51493, 32782, 7004, 7007, 52848, 3211, 259, 1096, 2010, 2608, 9100, 1947, 1024, 5357, 6, 32772, 1000, 5004, 6106, 783, 1011, 1169, 1067, 2604, 49999, 5120, 3371, 7106, 7999, 56738, 1998, 5904, 5999, 668, 1198, 32781, 5405, 1971, 44443, 12345, 7103, 1145, 8873, 8087, 5922, 1154, 3269, 41511, 7627, 2401, 88, 700, 33899, 2107, 61900, 8333, 52869, 722, 5051, 49175, 15000, 9943, 1036, 222, 19350, 32774, 8021, 1088, 37, 8701, 7800, 10626, 1277, 8002, 1500, 1090, 6005, 3323, 1034, 3517, 7676, 10617, 8443, 3017, 7777, 9418, 711, 6007, 800, 50500, 10180, 8222, 513, 3689, 3869, 1201, 1057, 1192, 8086, 3283, 1075, 4004, 2967, 1038, 3784, 5815, 32771, 1583, 898, 8651, 3000, 2525] # Top 1000 más usados

tcp_ping_ports = [21, 22, 25, 53, 80, 110, 135, 139, 443, 445, 3389] # Some common tcp ports (Linux and Windows)

udp_ping_ports = [53, 67, 123, 137, 161, 500, 1900, 4500] # Some common udp ports (Linux and Windows)

icmp_ping_types = [8, 13, 17]

args = parser.parse_args()
target = args.target

if args.ports == "all":
    ports = list(range(1, 65535))
    text_ports = "All Ports"
elif args.ports == "fast":
    ports = common_ports_100
    text_ports = "Top 100 Ports"
elif args.ports == "default":
    ports = common_ports_1000
    text_ports = "Top 1000 Ports"
else:
    ports = list(map(int, args.ports.split(",")))
    text_ports = ports

scan_type = args.scan

# Mostrar Banner del Programador
mostrar_banner()

# Asociar la señal SIGINT (Ctrl+C) con el handler
signal.signal(signal.SIGINT, handler)

# Cargar el archivo OUI en una variable diccionario, si no pudiera informa del error
oui = load_oui_data(OUI_FILE)
if oui is None:
    print("No se pudo cargar el archivo OUI. Verifique que el archivo existe y vuelva a intentarlo.")
    print("Si el archivo no existe, es posible descargarlo con: -u | --update")
    descarga_bbdd_vendors(URL_OUI)
    oui = load_oui_data(OUI_FILE)

# Si se ha indicado el parametro update se intenta descargar el fichero actualizado
if args.update:
    descarga_bbdd_vendors(URL_OUI)

# Determinar si el target es de nuestra red local o no
#ignore = is_not_local_network(target)
if args.out:
    ignore = True
else:
    ignore = False

# Determinar que tipo de scan se ha solicitado y ejecutarlo
match scan_type:
    case "arp_ping":
        print("\n[+] Descubrimiento de hosts en la red LAN usando ARP Ping...")
        live_hosts = arp_ping(target)
        for ip, mac, vendor in live_hosts:
            print(f"Host: {ip}, MAC: {mac}, Fabricante: {vendor}")
    case "tcp_ping":
        print("\n[+] Descubrimiento de hosts en la red LAN usando TCP Ping...")
        ping_hosts(target, method="tcp", pt=tcp_ping_ports)
    case "udp_ping":
        print("\n[+] Descubrimiento de hosts en la red LAN usando UDP Ping...")
        udp_payloads = load_udp_payloads()
        ping_hosts(target, method="udp", pt=0)
    case "icmp_ping":
        print("\n[+] Descubrimiento de hosts en la red LAN usando ICMP Ping...")
        ping_hosts(target, method="icmp", pt=icmp_ping_types)
    case "syn":
        print(f"\n[+] Escaneo SYN de puertos ({text_ports})...")
        port_results = syn_scan(target, ports)
    case "tcp":
        print(f"\n[+] Escaneo TCP Connect de puertos ({text_ports})...")
        port_results = tcp_scan(target, ports)
    case "ack":
        print(f"\n[+] Escaneo ACK de puertos ({text_ports})...")
        port_results = ack_scan(target, ports)
    case "udp":
        # Cargar los payloads desde el archivo externo
        print(f"\n[+] Escaneo UDP de puertos ({text_ports})...")
        udp_payloads = load_udp_payloads()
        port_results = udp_scan(target, ports)
    case "banner":
        print(f"\n[+] Escaneo SYN de puertos con banner service ({text_ports})...")
        port_results = syn_scan(target, ports, True)
    case "http":
        print("\n[+] Análisis de cabeceras HTTP...")
        headers = http_header_scan(target, ports)
    case "os":
        print("\n[+] Detección del sistema operativo...")
        detect_os_network(target,ports)
