##Herramienta creada por: Geuz2248
#https://github.com/Geuz2248/hostDiscovery

import subprocess
import sys

# Verificar e instalar dependencias si es necesario
try:
    from tqdm import tqdm
except ImportError:
    print("Instalando dependencia requerida: tqdm")
    subprocess.run([sys.executable, "-m", "pip", "install", "tqdm"])
    from tqdm import tqdm

try:
    import requests
except ImportError:
    print("Instalando dependencia requerida: requests")
    subprocess.run([sys.executable, "-m", "pip", "install", "requests"])
    import requests

import ipaddress
import socket
import re
import json
import csv
import os
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime

# Configuración
MAX_HILOS = 50

def obtener_fabricante_por_mac(mac_address):
    """Intenta obtener el fabricante por la dirección MAC"""
    oui_db = {
        '00:1A:11': 'D-Link', '00:1B:FC': 'Nintendo', '00:1C:B3': 'LG Electronics',
        '00:1D:60': 'Samsung', '00:1E:8C': 'Texas Instruments', '00:1F:3A': 'Cisco',
        '00:21:5A': 'Intel', '00:22:5F': 'Microsoft', '00:23:12': 'Apple',
        '00:24:2B': 'HTC', '00:25:00': 'Dell', '00:26:5A': 'Netgear',
        '00:50:F2': 'Microsoft', '00:90:4C': 'Sony', '08:00:27': 'Oracle VirtualBox',
        '0C:84:DC': 'TP-Link', '10:FE:ED': 'TP-Link', '14:CC:20': 'TP-Link',
        '18:A6:F7': 'TP-Link', '1C:FA:68': 'TP-Link', '20:4E:7F': 'Apple',
        '24:A2:E1': 'Apple', '28:CF:E9': 'Apple', '30:F7:C5': 'Apple',
        '34:12:98': 'Apple', '38:F9:D3': 'Apple', '3C:15:C2': 'Apple',
        '40:30:04': 'Apple', '44:D8:84': 'Huawei', '48:60:BC': 'Huawei',
        '4C:60:DE': 'Huawei', '54:BE:F7': 'Huawei', '5C:EA:1D': 'Huawei',
        '6C:59:40': 'Huawei', '80:19:34': 'Huawei', '84:A8:E4': 'Huawei',
        '90:03:B7': 'Samsung', '94:51:03': 'Samsung', 'A0:F4:50': 'Samsung',
        'AC:7B:A1': 'Xiaomi', 'B0:41:1D': 'Xiaomi', 'BC:54:51': 'Shenzhen TINNO',
        'C0:CC:F8': 'Hon Hai Precision', 'D0:57:7C': 'Samsung', 'DC:A6:32': 'Huawei',
        'E4:46:DA': 'Huawei', 'EC:8C:A2': 'Huawei', 'F0:79:60': 'Apple',
        'F4:F5:D8': 'Google', 'FC:F1:36': 'Samsung', '00:18:4D': 'Netgear',
        '00:1E:2A': 'Cisco', '00:1F:33': 'Cisco', '00:21:91': 'Cisco',
        '00:23:5E': 'Cisco', '00:24:14': 'Cisco', '00:26:0B': 'Cisco',
        '00:26:5D': 'Belkin', '00:50:7F': 'Linksys', '00:13:10': 'Linksys',
        '00:14:BF': 'Linksys', '00:18:F8': 'Linksys', '00:1A:70': 'Linksys',
        '00:1C:10': 'Linksys', '00:1D:7E': 'Linksys', '00:1F:33': 'Linksys',
        '00:21:29': 'Linksys', '00:23:08': 'Linksys', '00:24:B2': 'Linksys'
    }
    
    if not mac_address or mac_address in ["No encontrada", "Error"]:
        return "Desconocido"
    
    mac_upper = mac_address.upper().replace('-', ':')
    prefijo = mac_upper[:8]
    
    for oui, fabricante in oui_db.items():
        if prefijo.startswith(oui):
            return fabricante
    
    return "Desconocido"

def identificar_so_por_ttl(ttl):
    """Intenta identificar el SO por el valor TTL"""
    try:
        ttl_val = int(ttl)
        if ttl_val <= 64:
            return "Linux/Unix/Android/macOS"
        elif 65 <= ttl_val <= 128:
            return "Windows"
        elif ttl_val == 255:
            return "Router/Network Device"
        elif ttl_val >= 129:
            return "BSD/Unix antiguo"
        else:
            return "Desconocido"
    except:
        return "Desconocido"

def obtener_ttl(ip):
    """Obtiene el TTL de un host mediante ping"""
    try:
        param = '-n' if subprocess.os.name == 'nt' else '-c'
        result = subprocess.run(
            ['ping', param, '1', ip],
            capture_output=True,
            text=True,
            timeout=2
        )
        
        lines = result.stdout.split('\n')
        for line in lines:
            if 'ttl=' in line.lower():
                match = re.search(r'ttl=(\d+)', line.lower())
                if match:
                    return match.group(1)
        return "N/A"
    except:
        return "N/A"

def obtener_mac_por_ip(ip):
    """Obtiene la dirección MAC por IP usando la tabla ARP"""
    try:
        if subprocess.os.name == 'nt':  # Windows
            result = subprocess.run(['arp', '-a', ip], capture_output=True, text=True)
            lines = result.stdout.split('\n')
            for line in lines:
                if ip in line:
                    parts = line.split()
                    if len(parts) >= 2:
                        mac = parts[1].replace('-', ':')
                        if re.match(r'([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})', mac):
                            return mac
        else:  # Linux/Mac
            result = subprocess.run(['arp', '-n', ip], capture_output=True, text=True)
            lines = result.stdout.split('\n')
            for line in lines:
                if ip in line:
                    parts = line.split()
                    if len(parts) >= 3:
                        mac = parts[2]
                        if re.match(r'([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})', mac):
                            return mac
        return "No encontrada"
    except:
        return "Error"

def es_dispositivo_red(mac, fabricante, ttl, ip):
    """Determina si es un dispositivo de red (módem/router)"""
    fabricantes_red = ['Cisco', 'Netgear', 'TP-Link', 'D-Link', 'Linksys', 'Huawei']
    if any(fab in fabricante for fab in fabricantes_red):
        return True
    
    if ttl != "N/A" and int(ttl) == 255:
        return True
    
    if ip.endswith('.1') or ip.endswith('.254'):
        return True
    
    return False

def obtener_info_detallada_host(ip):
    """Obtiene información detallada de un host"""
    ttl = obtener_ttl(ip)
    so_estimado = identificar_so_por_ttl(ttl) if ttl != "N/A" else "Desconocido"
    
    mac = obtener_mac_por_ip(ip)
    fabricante = obtener_fabricante_por_mac(mac)
    
    es_router = es_dispositivo_red(mac, fabricante, ttl, ip)
    
    return {
        'ip': ip,
        'mac': mac,
        'fabricante': fabricante,
        'ttl': ttl,
        'so_estimado': so_estimado,
        'es_router': es_router,
        'timestamp': datetime.now().isoformat(),
        'estado': 'Active'
    }

def obtener_info_ipv6_completa():
    """Obtiene información detallada de IPv6"""
    info = {
        'ipv6_publica': 'No detectada',
        'ipv6_locales': [],
        'tiene_ipv6': False
    }
    
    try:
        respuesta = requests.get('https://api6.ipify.org', timeout=10)
        if respuesta.status_code == 200:
            ip = respuesta.text.strip()
            if ':' in ip:
                info['ipv6_publica'] = ip
                info['tiene_ipv6'] = True
    except:
        pass
    
    try:
        hostname = socket.gethostname()
        direcciones = socket.getaddrinfo(hostname, None, socket.AF_INET6)
        for addr in direcciones:
            ip = addr[4][0]
            if ip not in info['ipv6_locales']:
                info['ipv6_locales'].append(ip)
    except:
        pass
    
    return info

def obtener_ip_publica_v4():
    """Obtiene la dirección IPv4 pública"""
    servicios = ['https://api.ipify.org', 'https://ident.me', 'https://checkip.amazonaws.com']
    for servicio in servicios:
        try:
            respuesta = requests.get(servicio, timeout=10)
            if respuesta.status_code == 200:
                ip = respuesta.text.strip()
                if '.' in ip and ':' not in ip:
                    return ip
        except:
            continue
    return 'No detectada'

def obtener_puerta_enlace():
    """Obtienehttps://github.com/Geuz2248/hostDiscovery la puerta de enlace predeterminada"""
    try:
        if subprocess.os.name == 'nt':  # Windows
            result = subprocess.run(['ipconfig'], capture_output=True, text=True)
            lines = result.stdout.split('\n')
            for line in lines:
                if 'Puerta de enlace predeterminada' in line or 'Default Gateway' in line:
                    gateway = line.split(':')[-1].strip()
                    if gateway and gateway != '':
                        return gateway
        else:  # Linux/Mac
            result = subprocess.run(['ip', 'route'], capture_output=True, text=True)
            lines = result.stdout.split('\n')
            for line in lines:
                if 'default via' in line:
                    parts = line.split()
                    if len(parts) >= 3:
                        return parts[2]
    except:
        return "No detectada"
    
    return "No detectada"

def ping_host(ip):
    """Realiza ping a un host y devuelve True si está activo"""
    try:
        param = '-n' if subprocess.os.name == 'nt' else '-c'
        timeout_param = '-w' if subprocess.os.name == 'nt' else '-W'
        result = subprocess.run(
            ['ping', param, '1', timeout_param, '1', ip],
            capture_output=True,
            text=True,
            timeout=2
        )
        return result.returncode == 0
    except:
        return False

def escanear_red(ip_base, inicio=1, fin=254, max_hilos=MAX_HILOS):
    """Escanea un rango de direcciones IP y obtiene información detallada"""
    ip_base = ip_base.rstrip('.')
    hosts_activos = []
    info_detallada = []
    
    print(f"Escaneando: {ip_base}.{inicio} a {ip_base}.{fin}")
    
    # Primera fase: descubrir hosts activos
    with tqdm(total=fin-inicio+1, desc="Descubriendo hosts") as pbar:
        with ThreadPoolExecutor(max_workers=max_hilos) as executor:
            futuros = {executor.submit(ping_host, f"{ip_base}.{i}"): i for i in range(inicio, fin+1)}
            
            for futuro in as_completed(futuros):
                i = futuros[futuro]
                ip = f"{ip_base}.{i}"
                try:
                    if futuro.result():
                        hosts_activos.append(ip)
                        print(f"✓ {ip} - Active")
                except:
                    pass
                finally:
                    pbar.update(1)
    
    # Segunda fase: obtener información detallada de hosts activos
    if hosts_activos:
        print("\nObteniendo información detallada de hosts...")
        with tqdm(total=len(hosts_activos), desc="Analizando hosts") as pbar:
            with ThreadPoolExecutor(max_workers=20) as executor:
                futuros_detalle = {executor.submit(obtener_info_detallada_host, ip): ip for ip in hosts_activos}
                
                for futuro in as_completed(futuros_detalle):
                    try:
                        info = futuro.result()
                        info_detallada.append(info)
                    except:
                        pass
                    finally:
                        pbar.update(1)
    
    return info_detallada

def generar_mapa_red(hosts_info):
    """Genera un mapa visual simple de la red"""
    print("\n" + "="*60)
    print("🗺️  MAPA VISUAL DE LA RED")
    print("="*60)
    
    # Ordenar hosts por IP
    hosts_ordenados = sorted(hosts_info, key=lambda x: [int(i) for i in x['ip'].split('.')])
    
    for host in hosts_ordenados:
        icono = "🌐" if host['es_router'] else "💻"
        if "Android" in host['so_estimado']:
            icono = "📱"
        elif "Windows" in host['so_estimado']:
            icono = "🖥️"
        elif "Apple" in host['fabricante']:
            icono = "🍎"
        
        print(f"{icono} {host['ip']} ({host['fabricante']}) - {host['so_estimado']}")

def exportar_resultados(hosts_info, formato="json"):
    """Exporta resultados en múltiples formatos"""
    fecha = datetime.now().strftime("%Y%m%d_%H%M%S")
    
    if formato == "json":
        nombre_archivo = f"escaner_red_{fecha}.json"
        with open(nombre_archivo, 'w') as f:
            json.dump(hosts_info, f, indent=2)
    
    elif formato == "csv":
        nombre_archivo = f"escaner_red_{fecha}.csv"
        with open(nombre_archivo, 'w', newline='', encoding='utf-8') as f:
            campos = ['ip', 'mac', 'fabricante', 'ttl', 'so_estimado', 'es_router', 'timestamp']
            writer = csv.DictWriter(f, fieldnames=campos)
            writer.writeheader()
            for host in hosts_info:
                writer.writerow({k: host[k] for k in campos})
    
    elif formato == "html":
        nombre_archivo = f"escaner_red_{fecha}.html"
        with open(nombre_archivo, 'w', encoding='utf-8') as f:
            f.write("""
            <html>
            <head>
                <title>Escaneo de Red</title>
                <style>
                    body { font-family: Arial, sans-serif; margin: 20px; }
                    table { border-collapse: collapse; width: 100%; }
                    th, td { border: 1px solid #ddd; padding: 8px; text-align: left; }
                    th { background-color: #f2f2f2; }
                    tr:nth-child(even) { background-color: #f9f9f9; }
                </style>
            </head>
            <body>
                <h1>Resultados del Escaneo de Red</h1>
                <table>
                    <tr>
                        <th>IP</th><th>Fabricante</th><th>SO</th><th>MAC</th><th>Es Router</th>
                    </tr>
            """)
            
            for host in hosts_info:
                f.write(f"""
                    <tr>
                        <td>{host['ip']}</td>
                        <td>{host['fabricante']}</td>
                        <td>{host['so_estimado']}</td>
                        <td>{host['mac']}</td>
                        <td>{'Sí' if host['es_router'] else 'No'}</td>
                    </tr>
                """)
            
            f.write("</table></body></html>")
    
    return nombre_archivo

def comparar_escaneos(escaneo_anterior, escaneo_actual):
    """Compara dos escaneos y detecta cambios"""
    try:
        anteriores = {host['ip']: host for host in escaneo_anterior}
        actuales = {host['ip']: host for host in escaneo_actual}
        
        nuevos = [ip for ip in actuales if ip not in anteriores]
        desaparecidos = [ip for ip in anteriores if ip not in actuales]
        
        print("\n" + "="*50)
        print("🔄 CAMBIOS EN LA RED")
        print("="*50)
        
        if nuevos:
            print("📈 Dispositivos nuevos:")
            for ip in nuevos:
                print(f"  + {ip} ({actuales[ip]['fabricante']})")
        
        if desaparecidos:
            print("📉 Dispositivos desaparecidos:")
            for ip in desaparecidos:
                print(f"  - {ip} ({anteriores[ip]['fabricante']})")
        
        if not nuevos and not desaparecidos:
            print("No se detectaron cambios en la red")
            
        return nuevos, desaparecidos
    except Exception as e:
        print(f"Error al comparar escaneos: {e}")
        return [], []

def cargar_ultimo_escaneo():
    """Carga el último escaneo desde el archivo JSON"""
    try:
        archivos = [f for f in os.listdir('.') if f.startswith('escaner_red_') and f.endswith('.json')]
        if not archivos:
            return None
        
        archivos.sort(reverse=True)
        with open(archivos[0], 'r') as f:
            return json.load(f)
    except:
        return None

def ejecutar_escaneo():
    """Ejecuta un escaneo de red"""
    ip_base = input("Ingresa los primeros tres octetos de la dirección IP (ej: 192.168.1): ")
    ip_base = ip_base.rstrip('.')
    
    try:
        ipaddress.ip_address(ip_base + '.1')
    except ValueError:
        print("Error: Dirección IP inválida")
        return None
    
    print("\n🔍 Opciones de escaneo:")
    print("1. Escaneo completo (1-254)")
    print("2. Escaneo personalizado")
    
    opcion = input("Selecciona una opción (1/2): ")
    
    if opcion == "2":
        try:
            inicio = int(input("Dirección inicial (ej: 1): "))
            fin = int(input("Dirección final (ej: 254): "))
            if inicio < 1 or fin > 254 or inicio > fin:
                inicio, fin = 1, 254
        except:
            inicio, fin = 1, 254
    else:
        inicio, fin = 1, 254
    
    print(f"\n🔎 Iniciando escaneo...")
    hosts_info = escanear_red(ip_base, inicio, fin)
    
    if not hosts_info:
        print("No se encontraron hosts activos")
        return None
    
    # Separar routers de dispositivos normales
    routers = [host for host in hosts_info if host['es_router']]
    dispositivos = [host for host in hosts_info if not host['es_router']]
    
    # Mostrar resultados
    print("\n" + "="*80)
    print("🌐 DISPOSITIVOS DE RED (ROUTERS/MÓDEMS)")
    print("="*80)
    if routers:
        for router in routers:
            print(f"📍 {router['ip']} - {router['fabricante']} - {router['so_estimado']}")
            print(f"   MAC: {router['mac']} - TTL: {router['ttl']}")
            print()
    else:
        print("No se detectaron dispositivos de red")
    
    print("\n" + "="*80)
    print("💻 DISPOSITIVOS CONECTADOS")
    print("="*80)
    if dispositivos:
        for disp in sorted(dispositivos, key=lambda x: [int(i) for i in x['ip'].split('.')]):
            print(f"📱 {disp['ip']} - {disp['fabricante']} - {disp['so_estimado']}")
            print(f"   MAC: {disp['mac']} - TTL: {disp['ttl']}")
    else:
        print("No se encontraron dispositivos conectados")
    
    # Obtener información de conectividad
    ipv4_publica = obtener_ip_publica_v4()
    info_ipv6 = obtener_info_ipv6_completa()
    puerta_enlace = obtener_puerta_enlace()
    
    print("\n" + "="*50)
    print("🌍 INFORMACIÓN DE CONECTIVIDAD")
    print("="*50)
    print(f"📡 IPv4 Pública: {ipv4_publica}")
    print(f"🔗 IPv6 Pública: {info_ipv6['ipv6_publica']}")
    print(f"🔄 Puerta de enlace: {puerta_enlace}")
    print(f"📊 Total de hosts activos: {len(hosts_info)}")
    
    # Guardar en JSON
    archivo = exportar_resultados(hosts_info, "json")
    print(f"✅ Resultados guardados en: {archivo}")
    
    return hosts_info

def exportar_menu():
    """Menú para exportar resultados"""
    try:
        archivos = [f for f in os.listdir('.') if f.startswith('escaner_red_') and f.endswith('.json')]
        if not archivos:
            print("No hay escaneos previos para exportar")
            return
        
        print("\n📊 Escaneos disponibles:")
        for i, archivo in enumerate(archivos, 1):
            print(f"{i}. {archivo}")
        
        seleccion = int(input("Selecciona el número del escaneo a exportar: ")) - 1
        if seleccion < 0 or seleccion >= len(archivos):
            print("Selección inválida")
            return
        
        with open(archivos[seleccion], 'r') as f:
            hosts_info = json.load(f)
        
        print("\n📁 Formatos de exportación:")
        print("1. JSON")
        print("2. CSV")
        print("3. HTML")
        
        formato = input("Selecciona el formato (1/2/3): ")
        
        if formato == "1":
            archivo = exportar_resultados(hosts_info, "json")
        elif formato == "2":
            archivo = exportar_resultados(hosts_info, "csv")
        elif formato == "3":
            archivo = exportar_resultados(hosts_info, "html")
        else:
            print("Opción inválida")
            return
        
        print(f"✅ Resultados exportados to: {archivo}")
        
    except Exception as e:
        print(f"Error al exportar: {e}")

def comparar_escaneos_menu():
    """Menú para comparar escaneos"""
    try:
        archivos = [f for f in os.listdir('.') if f.startswith('escaner_red_') and f.endswith('.json')]
        if len(archivos) < 2:
            print("Se necesitan al menos 2 escaneos para comparar")
            return
        
        print("\n📊 Escaneos disponibles:")
        for i, archivo in enumerate(archivos, 1):
            print(f"{i}. {archivo}")
        
        print("Selecciona dos escaneos para comparar")
        seleccion1 = int(input("Primer escaneo: ")) - 1
        seleccion2 = int(input("Segundo escaneo: ")) - 1
        
        if seleccion1 < 0 or seleccion1 >= len(archivos) or seleccion2 < 0 or seleccion2 >= len(archivos):
            print("Selección inválida")
            return
        
        with open(archivos[seleccion1], 'r') as f:
            escaneo1 = json.load(f)
        
        with open(archivos[seleccion2], 'r') as f:
            escaneo2 = json.load(f)
        
        comparar_escaneos(escaneo1, escaneo2)
        
    except Exception as e:
        print(f"Error al comparar escaneos: {e}")

def ver_mapa_red():
    """Muestra el mapa de red del último escaneo"""
    try:
        archivos = [f for f in os.listdir('.') if f.startswith('escaner_red_') and f.endswith('.json')]
        if not archivos:
            print("No hay escaneos previos para mostrar")
            return
        
        archivos.sort(reverse=True)
        with open(archivos[0], 'r') as f:
            hosts_info = json.load(f)
        
        generar_mapa_red(hosts_info)
        
    except Exception as e:
        print(f"Error al cargar el mapa de red: {e}")

def mostrar_menu_principal():
    """Muestra un menú interactivo al usuario"""
    while True:
        print("\n" + "="*50)
        print(" ██░ ██  ▒█████    ██████ ▄▄▄█████▓▓█████▄  ██▓  ██████  ▄████▄   ▒█████   ██▒   █▓▓█████  ██▀███ ▓██   ██▓")
        print("▓██░ ██▒▒██▒  ██▒▒██    ▒ ▓  ██▒ ▓▒▒██▀ ██▌▓██▒▒██    ▒ ▒██▀ ▀█  ▒██▒  ██▒▓██░   █▒▓█   ▀ ▓██ ▒ ██▒▒██  ██▒")
        print("▒██▀▀██░▒██░  ██▒░ ▓██▄   ▒ ▓██░ ▒░░██   █▌▒██▒░ ▓██▄   ▒▓█    ▄ ▒██░  ██▒ ▓██  █▒░▒███   ▓██ ░▄█ ▒ ▒██ ██░")
        print("░▓█ ░██ ▒██   ██░  ▒   ██▒░ ▓██▓ ░ ░▓█▄   ▌░██░  ▒   ██▒▒▓▓▄ ▄██▒▒██   ██░  ▒██ █░░▒▓█  ▄ ▒██▀▀█▄   ░ ▐██▓░")
        print("░▓█▒░██▓░ ████▓▒░▒██████▒▒  ▒██▒ ░ ░▒████▓ ░██░▒██████▒▒▒ ▓███▀ ░░ ████▓▒░   ▒▀█░  ░▒████▒░██▓ ▒██▒ ░ ██▒▓░")
        print(" ▒ ░░▒░▒░ ▒░▒░▒░ ▒ ▒▓▒ ▒ ░  ▒ ░░    ▒▒▓  ▒ ░▓  ▒ ▒▓▒ ▒ ░░ ░▒ ▒  ░░ ▒░▒░▒░    ░ ▐░  ░░ ▒░ ░░ ▒▓ ░▒▓░  ██▒▒▒ ")
        print(" ▒ ░▒░ ░  ░ ▒ ▒░ ░ ░▒  ░ ░    ░     ░ ▒  ▒  ▒ ░░ ░▒  ░ ░  ░  ▒     ░ ▒ ▒░    ░ ░░   ░ ░  ░  ░▒ ░ ▒░▓██ ░▒░ ")
        print(" ░  ░░ ░░ ░ ░ ▒  ░  ░  ░    ░       ░ ░  ░  ▒ ░░  ░  ░  ░        ░ ░ ░ ▒       ░░     ░     ░░   ░ ▒ ▒ ░░  ")
        print(" ░  ░  ░    ░ ░        ░              ░     ░        ░  ░ ░          ░ ░        ░     ░  ░   ░     ░ ░     ")
        print("                                    ░                   ░                      ░                   ░ ░      ")
        print("🛠️  HERRAMIENTA AVANZADA DE ESCANEO DE RED")
        print("="*50)
        print("Elaborada por: Geuz2248")
        print("https://github.com/Geuz2248/hostDiscovery")
        print("="*50)
        print("1. Escaneo de red")
        print("2. Exportar resultados")
        print("3. Comparar con escaneo anterior")
        print("4. Ver mapa de red")
        print("5. Salir")
        
        opcion = input("\nSelecciona una opción: ")
        
        if opcion == "1":
            ejecutar_escaneo()
        elif opcion == "2":
            exportar_menu()
        elif opcion == "3":
            comparar_escaneos_menu()
        elif opcion == "4":
            ver_mapa_red()
        elif opcion == "5":
            print("¡Hasta luego!")
            break
        else:
            print("Opción no válida")

if __name__ == "__main__":
    mostrar_menu_principal()
