# Net Report Generator

Escáner de red simple hecho en Python. Recorre la red local, detecta qué dispositivos están conectados (IP, MAC, hostname y puertos abiertos) y arma un PDF con todo eso. Lo hice para tener una forma rápida de auditar mi propia red sin depender de herramientas más pesadas tipo Nmap + un montón de flags.

## Qué hace exactamente

1. Manda peticiones ARP al rango de red que le indiques para descubrir qué IPs están activas.
2. A cada IP encontrada le escanea un set fijo de puertos comunes: 22, 80, 443, 3389 y 8080.
3. Intenta resolver el hostname de cada equipo (si no lo consigue, lo marca como "Desconocido").
4. Junta todo en un PDF (`reporte.pdf`) con fecha y hora de la corrida.

No es un scanner exhaustivo ni reemplaza a Nmap — es un script chico para tener un pantallazo rápido de quién está en la red.

## Requisitos

- Python 3.8 o superior
- En Windows: [Npcap](https://npcap.com/) instalado en modo compatible con WinPcap (lo necesita scapy para mandar paquetes ARP)
- Permisos de administrador/root (el escaneo ARP no funciona sin esto)

Dependencias de Python:

```
scapy
fpdf2
```

## Instalación

```bash
git clone https://github.com/gussyk/net-report-generator
cd net-report-generator
pip install scapy fpdf2
```

## Uso

Correr con permisos de administrador (en Windows, PowerShell/CMD "como administrador"; en Linux/Mac, con `sudo`):

```bash
sudo python main.py
```

El script va a pedir el rango de red:

```
INGRESE LA IP: 192.168.1.0/24
```

Al terminar, se genera `reporte.pdf` en la misma carpeta, con la lista de dispositivos encontrados.

### ¿No sabés tu rango de red?

- **Windows:** abrí una consola y corré `ipconfig`, fijate en "Dirección IPv4".
- **Linux/Mac:** corré `ip addr` o `ifconfig`.

Si tu IP es `192.168.1.4`, tu rango normalmente es `192.168.1.0/24`.

## Limitaciones conocidas

- Los puertos que escanea están fijos en el código (22, 80, 443, 3389, 8080). Si necesitás otros, por ahora hay que editar `main.py` directamente.
- El escaneo de puertos es secuencial por dispositivo, así que con redes grandes puede tardar bastante.
- No guarda historial de escaneos anteriores para comparar cambios en la red.

Son cosas que me gustaría mejorar más adelante (parámetros por línea de comandos, escaneo en paralelo, elegir el nombre del PDF de salida).

## Uso responsable

Esta herramienta es para redes propias o donde tengas autorización explícita para escanear. Usarla sobre redes ajenas sin permiso puede ser ilegal según la jurisdicción. El objetivo del proyecto es educativo y de auditoría personal.

## Autor

gussyk