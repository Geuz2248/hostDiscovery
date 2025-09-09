# 🛠️ Herramienta Avanzada de Escaneo de Red

Este proyecto es un script en **Python** que permite realizar un análisis avanzado de dispositivos en una red local, identificando hosts activos, fabricantes, sistemas operativos estimados y generando reportes en diferentes formatos.

## 🚀 Características principales

- 🔍 Escaneo de Hosts: Descubre dispositivos activos en la red local
- 📊 Información Detallada: Obtén dirección MAC, fabricante, TTL y SO estimado
- 🌐 Información de Red: Muestra tu IP pública (IPv4 e IPv6) y puerta de enlace
- 📁 Exportación de Resultados: Guarda en formatos JSON, CSV y HTML
- 🗺️ Mapa Visual: Representación gráfica de los dispositivos en la red
- 🔄 Comparación de Escaneos: Detecta cambios entre escaneos
- 📈 Barras de Progreso: Visualización del progreso del escaneo

## 📦 Requisitos

El script instalará automáticamente las dependencias si no están presentes:

- `tqdm`
- `requests`

## Instalación Automática

El script instalará automáticamente las dependencias necesarias al ejecutarse por primera vez:

```
git clone https://github.com/Geuz2248/hostDiscovery
cd hostDiscovery
```

## ⚙️ Uso

Ejecuta el script en tu terminal:

```bash
python3 hostDiscovery.py
```

Aparecerá un menú interactivo con las siguientes opciones:

1. Escaneo de red: Descubre hosts activos en la red
2. Exportar resultados: Exporta escaneos previos a diferentes formatos
3. Comparar con escaneo anterior: Detecta cambios en la red
4. Ver mapa de red: Muestra una representación visual de la red
5. Salir: Finaliza la aplicación


### Ejemplo de uso

```bash
$ python3 hostDiscovery.py

🛠️  HERRAMIENTA AVANZADA DE ESCANEO DE RED
==================================================
1. Escaneo de red
2. Exportar resultados
3. Comparar con escaneo anterior
4. Ver mapa de red
5. Salir
```

## 📂 Resultados

Los resultados se guardan automáticamente en archivos con el formato:

- `escaner_red_YYYYMMDD_HHMMSS.json`
- `escaner_red_YYYYMMDD_HHMMSS.csv`
- `escaner_red_YYYYMMDD_HHMMSS.html`

## ⚠️ Notas importantes

- Requiere permisos adecuados para ejecutar comandos como `ping` y `arp`.
- Puede que algunos sistemas operativos necesiten ejecutar el script con privilegios de administrador para obtener direcciones MAC.
- El escaneo intensivo puede afectar el rendimiento de la red
- Asegúrate de tener permiso para escanear la red objetivo
- La detección de MAC depende de la tabla ARP del sistema

## Disclaimer: 

Esta herramienta está diseñada para fines educativos y de administración de redes legítimas. Asegúrate de tener el permiso adecuado antes de escanear cualquier red.
---

✍️ Autor: Geuz2248
