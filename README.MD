# 🛡️ Net Report Generator

Herramienta de ciberseguridad en Python que escanea la red local y genera un reporte PDF con los dispositivos encontrados, sus MACs, hostnames y puertos abiertos.

## ⚡ ¿Qué hace?

- 🔍 Descubre dispositivos en la red local usando el protocolo ARP
- 🚪 Escanea puertos comunes de cada dispositivo (22, 80, 443, 3389, 8080)
- 💻 Obtiene el hostname de cada dispositivo
- 📄 Genera un reporte PDF con toda la información

## 📋 Requisitos

- Python 3.x
- Windows: instalar Npcap en modo de compatibilidad con WinPcap

## 🔧 Instalación

git clone https://github.com/gussyk/net-report-generator
cd net-report-generator
pip install -r requirements.txt

## 🚀 Uso

Ejecutar con permisos de administrador:

python main.py

Ingresar el rango de red cuando se solicite:

INGRESE LA IP: 192.168.1.0/24

El reporte se genera como reporte.pdf en la misma carpeta.
## ⚠️ Uso ético
Esta herramienta es solo para uso educativo y en redes propias.
## 🌐 ¿Cómo saber mi rango de red?

En Windows ejecutar ipconfig y buscar la Dirección IPv4.
Si tu IP es 192.168.1.4 tu rango es 192.168.1.0/24.

## 📦 Dependencias

scapy
fpdf2

## 👤 Autor

gussyk
