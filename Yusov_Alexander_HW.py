from scapy.all import sniff, IP, TCP, Raw, wrpcap
import re

# Флаг для остановки
stop_sniffing = False

def process_packet(packet):
    global stop_sniffing
    
    if packet.haslayer(TCP) and packet.haslayer(Raw):
        raw_data = packet[Raw].load
        
        try:
            payload_text = raw_data.decode('utf-8', errors='ignore')
            
            # Ищем HTTP-запрос
            if 'GET ' in payload_text or 'POST ' in payload_text:
                first_line = payload_text.split('\r\n')[0]
                print(f"\n[+] ПЕРЕХВАЧЕН ЗАПРОС: {first_line}")
                
                # Проверяем на XSS (и сырой, и закодированный)
                xss_patterns = [r'<script>', r'%3Cscript%3E', r'%3cscript%3e', r'onerror=', r'alert\(']
                
                if any(re.search(p, payload_text, re.IGNORECASE) for p in xss_patterns):
                    print("    [!] ОБНАРУЖЕН XSS PAYLOAD В ЗАПРОСЕ!")
                    # ВЫСТАВЛЯЕМ ФЛАГ ОСТАНОВКИ
                    stop_sniffing = True
                    
        except Exception:
            pass

# Функция-обертка для остановки
def stop_filter(packet):
    return stop_sniffing

print("[*] Запуск перехвата...")
print("[*] Теперь можно написать во второй консоли запрос через curl к google-gruyere")
gruyere_ip = "142.251.143.148"
my_interface = "eth0"

# Запускаем сниффер с stop_filter
packets = sniff(
    iface=my_interface, 
    filter=f"tcp port 80 and host {gruyere_ip}", 
    prn=process_packet, 
    stop_filter=stop_filter,  # Автоостановка при найденной уязвимости
    store=True
)

# Сохраняем в файл
if packets:
    filename = "Yusov_Alexander_HW_traffic.pcap"
    wrpcap(filename, packets)
    print(f"\n[*] УСПЕХ! Найден XSS. Дамп сохранен: {filename}")
else:
    print("\n[-] Захват завершен, но пакетов нет!")

# Для перехвата во второй консоли вводим
# curl "http://142.251.143.148/343687846836929813505771718580803786545/%3Cscript%3Ealert('XSS')%3C/script%3E?test=123" -H "Host: google-gruyere.appspot.com"
# Ну и профит ) 
