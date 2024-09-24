import os
import subprocess
from scapy.all import ARP, Ether, srp
from colorama import init, Fore
import platform
import subprocess

# Inicializar colorama
init(autoreset=True)

def print_banner():
    try:
        # Ejecutar figlet para mostrar el banner
        banner = subprocess.run(["figlet", "ETHER _ SWEEP"], stdout=subprocess.PIPE, text=True, check=True)
        print(Fore.YELLOW + banner.stdout)
    except subprocess.CalledProcessError as e:
        print(Fore.RED + f"Error ejecutando figlet: {e}")
    except FileNotFoundError:
        print(Fore.RED + "figlet no está instalado. Ejecuta 'sudo apt install figlet' para instalarlo.")
    except Exception as e:
        print(Fore.RED + f"Error inesperado: {e}")

def scan_network(interface):
    # Detectar el rango de IP en la interfaz seleccionada
    ip_range = detect_ip_range(interface)
    
    if not ip_range:
        print(Fore.RED + "Error: No se pudo detectar el rango de IP")
        return
    
    # Crear el paquete ARP para escanear
    arp = ARP(pdst=ip_range)
    ether = Ether(dst="ff:ff:ff:ff:ff:ff")
    packet = ether/arp

    # Enviar el paquete y recibir las respuestas
    result = srp(packet, timeout=3, verbose=0)[0]

    devices = []
    for sent, received in result:
        devices.append({'ip': received.psrc, 'mac': received.hwsrc})

    # Mostrar los resultados
    print(Fore.YELLOW + "Dispositivos detectados:")
    for device in devices:
        os_type = detect_os_by_ttl(device['ip'])
        color = Fore.GREEN if os_type == "Linux" else Fore.CYAN if os_type == "Windows" else Fore.MAGENTA
        print(color + f"IP: {device['ip']}, MAC: {device['mac']}, SO: {os_type}")

def detect_ip_range(interface):
    try:
        # Ejecutar el comando para obtener la IP de la interfaz
        ip_output = subprocess.check_output(f"ip -4 addr show {interface}", shell=True).decode()
        # Buscar el rango de IP (por ejemplo, 192.168.1.0/24)
        for line in ip_output.splitlines():
            if "inet" in line:
                return line.split()[1]
    except Exception as e:
        print(Fore.RED + f"Error obteniendo rango IP: {e}")
        return None

def detect_os_by_ttl(ip):
    # Enviar un solo ping para obtener el TTL
    try:
        ttl = get_ttl(ip)
        if ttl:
            if ttl <= 64:
                return "Linux"
            elif ttl <= 128:
                return "Windows"
            else:
                return "Otro"
        else:
            return "Desconocido"
    except:
        return "Desconocido"

def get_ttl(ip):
    try:
        # Enviar un solo ping y capturar la salida
        ping_proc = subprocess.Popen(["ping", "-c", "1", "-W", "1", ip], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        out, _ = ping_proc.communicate()

        # Buscar la línea que contiene el TTL en la respuesta
        for line in out.decode().splitlines():
            if "ttl" in line:
                ttl = int(line.split("ttl=")[1].split()[0])
                return ttl
    except:
        return None

def main():
    print_banner() # Mostrar el banner al inicio
    interface = input("Introduce la interfaz de red (e.g., eth0, wlan0): ")
    scan_network(interface)

if __name__ == "__main__":
    main()
