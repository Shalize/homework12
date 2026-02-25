import pyshark
import pandas as pd

cap = pyshark.FileCapture('/Users/marii/Downloads/dhcp.pcapng')

packets_data = []

for packet in cap:
    try:
        # 1. Извлекаем общие данные (IP и Время)
        timestamp = packet.sniff_time
        src_ip = packet.ip.src
        dst_ip = packet.ip.dst
        
        # 2. Проверяем наличие DNS
        dns_query = None
        if 'DNS' in packet:
            # qry_name — это запрашиваемый домен (например, google.com)
            if hasattr(packet.dns, 'qry_name'):
                dns_query = packet.dns.qry_name
        
        packets_data.append({
            'timestamp': timestamp,
            'src_ip': src_ip,
            'dst_ip': dst_ip,
            'dns_query': dns_query
        })
        
        # Вывод в консоль для наглядности
        if dns_query:
            print(f"[{timestamp}] DNS Запрос: {dns_query} от {src_ip}")

    except AttributeError:
        # Пропускаем пакеты без IP слоя (например, ARP)
        continue

# Создаем таблицу
df = pd.DataFrame(packets_data)
print(df.head())

