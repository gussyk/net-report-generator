import scapy.all as scapy
import socket
import datetime
from fpdf import FPDF


print("""
╔══════════════════════════════════════════════╗
║                                              ║
║        NET REPORT GENERATOR v1.0             ║ 
║        ─────────────────────────             ║
║        Escáner de Red  →  PDF                ║
║                                              ║
║        by: gussyk                            ║
║                                              ║
╚══════════════════════════════════════════════╝
""")

def escanear_red(ip_rango):
   solicitud =  scapy.ARP(pdst=ip_rango)
   broadcast =  scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
   paquete = broadcast / solicitud
   respuestas = scapy.srp(paquete, timeout=2, verbose=False)[0]
   listaipmc = []
   for r in respuestas:
      ips = r[1].psrc
      macs = r[1].hwsrc
      listaipmc.append({"ip": ips, "mac": macs})
   return listaipmc
def escanear_puertos(ip):
   puertos = [22, 80, 443, 3389, 8080]
   puertos_abiertos = []
   for puerto in puertos:
       s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
       s.settimeout(0.5)
       resultado =  s.connect_ex((ip, puerto))
       if resultado == 0:
            puertos_abiertos.append(puerto)
       s.close()
   return puertos_abiertos
      

def obtener_hostnames(ip):
    try:
        hostname = socket.gethostbyaddr(ip)[0]
    except:
         hostname = "Desconocido"
    return hostname





def generar_pdf(dispositivos):
    pdf = FPDF()
    pdf.add_page()
    pdf.set_auto_page_break(auto=True, margin=15)#si se llena la pagina agrega otra
    pdf.set_font("Arial", "B", 16)
    pdf.cell(0, 10, txt="NET REPORT GENERATOR", ln=True, align='C')
    pdf.set_font("Arial", size=12)
    pdf.cell(0, 10, txt=str(datetime.datetime.now()), ln=True, align='C')
    for d in dispositivos:
        dip = d["ip"]
        dmac = d["mac"]
        pt = escanear_puertos(dip)
        host = obtener_hostnames(dip)
        pdf.set_font("Arial", size=12)
        pdf.cell(0, 10, txt=f"IP: {dip}  |  MAC: {dmac}  | HOSTNAME: {host}", ln=True)
        pdf.set_font("Arial", size=12)
        pdf.cell(0, 10, txt=f" puertos: {pt}", ln=True)
    pdf.output("reporte.pdf")


ip_rangoo = input("INGRESE LA IP: ")
dispositivos = escanear_red(ip_rangoo)
for d in dispositivos:
    puertos = escanear_puertos(d["ip"])
generar_pdf(dispositivos)
print("PDF GENERADO CON EXITO")


