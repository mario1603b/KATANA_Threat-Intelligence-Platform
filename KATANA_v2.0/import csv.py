import csv
import random
from datetime import datetime, timedelta

def generar_csv_prueba():
    archivo_salida = 'ataques_simulados_katana.csv'
    
    # Pools de IPs simuladas por regiones para que el mapa se ilumine bien
    redes_atacantes = [
        ("Moldavia", "93.152.221.", 200),  # Basado en tu caso real
        ("Rusia", "95.173.136.", 250),
        ("China", "220.181.38.", 200),
        ("Brasil", "177.43.21.", 150),
        ("EEUU", "104.243.250.", 100),
        ("Corea del Norte", "175.45.176.", 50),
        ("España (Proxy)", "80.58.61.", 50)
    ]
    
    usuarios = ['administrator', 'admin', 'root', 'test', 'usuario1', 'https', 'backup', 'vpnuser']
    pesos_usuarios = [0.35, 0.20, 0.15, 0.10, 0.05, 0.05, 0.05, 0.05] # administrator es el más atacado
    
    # Cabeceras estilo Sophos
    cabeceras = ['Time', 'Log comp', 'Status', 'Username', 'Src IP', 'Auth client', 'Auth mechanism', 'Message', 'Message ID', 'Live PCAP']
    
    fecha_base = datetime(2026, 3, 10, 2, 0, 0)
    
    print(f"Generando {sum([r[2] for r in redes_atacantes])} registros de ataque...")
    
    with open(archivo_salida, mode='w', newline='', encoding='utf-8') as file:
        writer = csv.writer(file)
        writer.writerow(cabeceras)
        
        for region, subred, cantidad in redes_atacantes:
            for _ in range(cantidad):
                # Avanzamos el tiempo entre 1 y 15 segundos por intento
                fecha_base += timedelta(seconds=random.randint(1, 15))
                time_str = fecha_base.strftime('%Y-%m-%d %H:%M:%S')
                
                # Generar IP y usuario
                ip = f"{subred}{random.randint(1, 254)}"
                user = random.choices(usuarios, weights=pesos_usuarios)[0]
                
                # Simular mensaje de Sophos
                if random.random() > 0.5:
                    msg = f"User {user} failed to login to VPN portal through AD. Local authentication mechanism because of wrong credentials"
                else:
                    msg = f"Access from IP address '{ip}' is blocked for '5' minutes after '5' unsuccessful login attempts"
                
                # Fila de datos
                fila = [
                    time_str, 
                    "VPN Portal Authentication", 
                    "Failed", 
                    user, 
                    ip, 
                    "N/A", 
                    "AD", 
                    msg, 
                    "17719", 
                    "Open PCAP"
                ]
                writer.writerow(fila)
                
    print(f"¡Listo! Archivo '{archivo_salida}' generado con éxito.")

if __name__ == '__main__':
    generar_csv_prueba()