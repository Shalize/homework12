import pyshark
import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns

# Используем фильтр 'dns || http', чтобы попытаться найти следы "процессов" в HTTP User-Agent, ибо в pcap нет процессов как таковых
cap = pyshark.FileCapture('/Users/marii/Downloads/exercise.pcap', display_filter='dns || http')

packets_data = []
print("Анализ запущен...")

for packet in cap:
    try:
        timestamp = packet.sniff_time
        src_ip = packet.ip.src
        dst_ip = packet.ip.dst
        
        dns_query = None
        process_name = "Unknown Process" # В pcap нет имен процессов, ищем User-Agent

        # 1. Извлекаем DNS
        if 'DNS' in packet and hasattr(packet.dns, 'qry_name'):
            dns_query = packet.dns.qry_name
        
        # 2. Пытаемся найти "имя процесса" через HTTP User-Agent (если есть)
        if 'HTTP' in packet and hasattr(packet.http, 'user_agent'):
            process_name = packet.http.user_agent.split('/')[0] # Примерное извлечение

        if dns_query:
            packets_data.append({
                'timestamp': timestamp,
                'src_ip': src_ip,
                'dst_ip': dst_ip,
                'query': dns_query,
                'process': process_name
            })

    except AttributeError:
        continue

cap.close()

# Создаем DataFrame
df = pd.DataFrame(packets_data)
df['timestamp'] = pd.to_datetime(df['timestamp'])

# Список подозрительных IP и доменов (содержат "wpad", странные зоны (.xyz, .top) или не входят в белый список) 
whitelist = ['google.com', 'microsoft.com', 'mshome.net']
suspicious_df = df[~df['query'].str.contains('|'.join(whitelist), na=False)]

print("\n[!] Подозрительные DNS-запросы и IP:")
print(suspicious_df[['timestamp', 'src_ip', 'query']].drop_duplicates().head(10))

# Эмуляция списка процессов (на основе User-Agent или уникальных запросов)
print("\n[!] Активность, приписываемая условным 'процессам' (User-Agents):")
print(df[['timestamp', 'process', 'src_ip']].drop_duplicates(subset=['process']).head(5))

# Визуализация: График количества запросов по времени
plt.figure(figsize=(12, 6))
# Группируем по 10-секундным интервалам для детальности
df.set_index('timestamp').resample('10s').count()['query'].plot(color='crimson', lw=2)

plt.title('Частота DNS-запросов (Поиск аномальных всплесков)', fontsize=14)
plt.xlabel('Время события')
plt.ylabel('Количество запросов')
plt.grid(True, linestyle='--', alpha=0.7)
plt.tight_layout()

plt.show()