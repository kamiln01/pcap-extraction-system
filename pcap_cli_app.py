import os
import sqlite3
from scapy.all import rdpcap, IP, TCP, UDP, DNS

# Jeżeli chcesz korzystać z archiwizacji z hasłem,
# zainstaluj 'pyminizip' (lub 'pyminizip-ng').
# import pyminizip

##############################
#  Ustawienia / konfiguracja #
##############################

# Jeżeli chcesz zmienić regułę rozpoznawania IP lokalnych, 
# zmodyfikuj tę funkcję. Tu używamy "naiwnej" reguły:
def is_local_ip(ip):
    """Bardzo uproszczone sprawdzenie, czy IP jest w prywatnym zakresie."""
    private_prefixes = (
        "192.168.",
        "10.",
        "172.16.",  # w rzeczywistości aż do 172.31.
        "127.",     # localhost
    )
    return any(ip.startswith(prefix) for prefix in private_prefixes)

def create_db(db_name: str):
    """Tworzy (jeśli nie istnieje) strukturę bazy danych SQLite."""
    conn = sqlite3.connect(db_name)
    cursor = conn.cursor()
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS packets (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp REAL,
            src_ip TEXT,
            dst_ip TEXT,
            src_port INTEGER,
            dst_port INTEGER,
            protocol TEXT,
            tag TEXT,
            length INTEGER
        )
    """)
    conn.commit()
    conn.close()

def insert_packet(db_name: str, packet_info: dict):
    """Wstawia rekord do bazy."""
    conn = sqlite3.connect(db_name)
    cursor = conn.cursor()
    cursor.execute("""
        INSERT INTO packets 
        (timestamp, src_ip, dst_ip, src_port, dst_port, protocol, tag, length)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    """, (
        packet_info['timestamp'],
        packet_info['src_ip'],
        packet_info['dst_ip'],
        packet_info['src_port'],
        packet_info['dst_port'],
        packet_info['protocol'],
        packet_info['tag'],
        packet_info['length']
    ))
    conn.commit()
    conn.close()

def extract_data_from_pcap(pcap_file: str, filter_options=None, db_name="packets.db"):
    """
    Wczytuje pakiety z pliku pcap, filtruje je według podanych opcji (DNS, TCP, HTTP)
    i zapisuje do bazy SQLite. 
    Jeśli filter_options jest pustą listą lub None -> brak filtra (wszystko).
    """
    packets = rdpcap(pcap_file)
    
    for pkt in packets:
        # Czy pakiet ma warstwę IP?
        if IP in pkt:
            src_ip = pkt[IP].src
            dst_ip = pkt[IP].dst
            protocol = None
            src_port = None
            dst_port = None
            tag_list = []
            
            # Określamy protokół warstwy transportu i tag ruchu
            if TCP in pkt:
                protocol = 'TCP'
                src_port = pkt[TCP].sport
                dst_port = pkt[TCP].dport
                # HTTP
                if (pkt[TCP].sport == 80 or pkt[TCP].dport == 80):
                    tag_list.append("HTTP_traffic")
            elif UDP in pkt:
                protocol = 'UDP'
                src_port = pkt[UDP].sport
                dst_port = pkt[UDP].dport
                # DNS
                if DNS in pkt:
                    tag_list.append("DNS_traffic")
            else:
                # Inne protokoły: np. ICMP (proto=1), itp.
                protocol = pkt[IP].proto  
                tag_list.append("OTHER_IP")
            
            # Sprawdzamy kierunek (incoming/outgoing) – prosta reguła
            # In/out określamy TYLKO jeśli jedna strona jest "lokalna", a druga "nielokalna".
            src_local = is_local_ip(src_ip)
            dst_local = is_local_ip(dst_ip)
            if src_local and not dst_local:
                tag_list.append("outgoing")
            elif not src_local and dst_local:
                tag_list.append("incoming")
            else:
                # W razie potrzeby można tu wstawić "internal", "external" itd.
                # tag_list.append("internal") lub cokolwiek innego
                pass
            
            # Filtry. Jeśli user wybrał np. ["dns","http"], to pakiet musi 
            # pasować do przynajmniej jednego z tych tagów, aby się załapał.
            if filter_options and len(filter_options) > 0:
                # "dns" -> czy w tag_list jest "DNS_traffic" 
                # "tcp" -> czy protocol == 'TCP'
                # "http" -> czy w tag_list jest "HTTP_traffic"
                
                pass_filters = False
                if "dns" in filter_options and "DNS_traffic" in tag_list:
                    pass_filters = True
                if "tcp" in filter_options and protocol == 'TCP':
                    pass_filters = True
                if "http" in filter_options and "HTTP_traffic" in tag_list:
                    pass_filters = True
                
                # Jeśli pakiet nie pasuje do ŻADNEGO z wybranych filtrów -> pomijamy
                if not pass_filters:
                    continue
            
            # Tworzymy zapis do bazy
            packet_info = {
                'timestamp': float(pkt.time),  # rzutowanie na float (unikamy typu Decimal)
                'src_ip': src_ip,
                'dst_ip': dst_ip,
                'src_port': src_port if src_port else 0,
                'dst_port': dst_port if dst_port else 0,
                'protocol': protocol,
                'tag': ", ".join(tag_list) if tag_list else "",
                'length': len(pkt)
            }
            
            insert_packet(db_name, packet_info)

def list_pcap_files_in_directory(directory='.'):
    """Zwraca listę nazw plików .pcap w podanym katalogu (domyślnie bieżącym)."""
    files = [f for f in os.listdir(directory) if f.lower().endswith('.pcap')]
    return files

import os
import pyzipper

def archive_db_file(db_name: str, archive_password: str) -> str:
    """
    Archiwizuje wskazany plik (np. bazę .db) do pliku ZIP z hasłem (AES).
    Zwraca nazwę utworzonego archiwum (np. 'nazwa.db.zip').

    Wymaga zainstalowanej biblioteki: pip install pyzipper
    """
    archive_name = db_name + ".zip"
    
    # Używamy AESZipFile z szyfrowaniem AES (WZ_AES)
    # Kompresja np. ZIP_DEFLATED (można wybrać ZIP_LZMA lub inny)
    with pyzipper.AESZipFile(archive_name,
                             mode='w',
                             compression=pyzipper.ZIP_DEFLATED,
                             encryption=pyzipper.WZ_AES) as zf:
        # Hasło musi być bajtowe:
        zf.setpassword(archive_password.encode('utf-8'))
        # Dodajemy plik do archiwum (arcname = nazwa wewnątrz zipa)
        zf.write(db_name, arcname=os.path.basename(db_name))
    
    return archive_name

def main():
    print("Witaj w systemie ekstrakcji danych z plików pcap!\n")

    while True:  # pętla główna -> umożliwiamy wielokrotne analizy
        # 1. Wylistowanie plików pcap
        pcap_files = list_pcap_files_in_directory('.')
        if not pcap_files:
            print("Brak plików .pcap w bieżącym katalogu! Kończę działanie.")
            break
        
        print("Dostępne pliki .pcap w bieżącym katalogu:")
        for i, filename in enumerate(pcap_files, start=1):
            print(f"  [{i}] {filename}")
        
        # 2. Wybór jednego lub kilku plików
        print("\nWybierz pliki (np. '1' lub '1,2' albo '1 2'): ")
        chosen_raw = input(">> ").replace(',', ' ').split()
        
        # Odfiltrowujemy poprawne numery
        indices = []
        for x in chosen_raw:
            if x.isdigit():
                idx = int(x)
                if 1 <= idx <= len(pcap_files):
                    indices.append(idx)
        
        if not indices:
            print("\nNie wybrano żadnych plików lub błędne numery. Wracam do menu...\n")
            continue
        
        chosen_files = [pcap_files[i-1] for i in indices]
        print(f"\nWybrane pliki: {', '.join(chosen_files)}\n")
        
        # 3. Wybór typów ruchu do ekstrakcji (możemy wybrać wiele)
        print("Jakie dane chcesz wyekstrahować? (możesz wybrać kilka, np. '1 3')")
        print("  [1] DNS")
        print("  [2] TCP")
        print("  [3] HTTP")
        print("  [4] Wszystko (brak filtra)")
        
        choice_raw = input(">> ").replace(',', ' ').split()
        choice_nums = [x.strip() for x in choice_raw if x.strip().isdigit()]
        
        filter_map = {
            "1": "dns",
            "2": "tcp",
            "3": "http",
            "4": "all"
        }
        
        chosen_filters = set()
        for num in choice_nums:
            if num in filter_map:
                chosen_filters.add(filter_map[num])
        
        # Jeśli jest 'all', ignorujemy resztę -> brak filtra
        if "all" in chosen_filters:
            filter_options = []
        else:
            filter_options = list(chosen_filters)
        
        # 4. Dla każdego wybranego pliku .pcap generujemy domyślną nazwę .db
        #    Chyba że użytkownik woli samą nazwę (można to zmodyfikować).
        for pcap_file in chosen_files:
            # Domyślna nazwa bazy = nazwa pcap, tylko z .db zamiast .pcap
            base, ext = os.path.splitext(pcap_file)
            db_name = base + ".db"
            
            print(f"\n===== Przetwarzanie pliku: {pcap_file} =====")
            print(f"Domyślna nazwa bazy: {db_name}")
            custom_db = input("Jeśli chcesz zmienić nazwę bazy, wpisz nową. Jeśli nie, wciśnij Enter: ").strip()
            if custom_db:
                db_name = custom_db
            
            # Tworzymy / otwieramy bazę
            create_db(db_name)
            print(f"Rozpoczynam analizę i zapis do bazy '{db_name}'...")
            
            # Ekstrakcja
            extract_data_from_pcap(pcap_file, filter_options=filter_options, db_name=db_name)
            
            # Podsumowanie
            conn = sqlite3.connect(db_name)
            cursor = conn.cursor()
            cursor.execute("SELECT COUNT(*) FROM packets")
            total_packets = cursor.fetchone()[0]
            conn.close()
            
            print(f"Zapisano {total_packets} pakietów w bazie '{db_name}'.")
            
        # 5. Zapytanie o hasło
        choice = input("\nCzy chcesz zarchiwizować bazę ZIP z hasłem? [t/n]: ").strip().lower()
        if choice in ["t", "tak", "y", "yes"]:
            pwd = input("Podaj hasło do zabezpieczenia archiwum: ").strip()
            if pwd:
                archive_name = archive_db_file(db_name, pwd)
                print(f"Utworzono archiwum '{archive_name}' z hasłem AES.\n")
            else:
                print("Nie podano hasła. Pomijam archiwizację.\n")
                
        # 6. Czy kontynuować?
        choice_end = input("Czy chcesz przeprowadzić kolejną ekstrakcję? [t/n]: ").strip().lower()
        if choice_end not in ["t", "tak", "y", "yes"]:
            print("\nKoniec pracy. Do widzenia!")
            break
        else:
            print("\n===========================================\n")


if __name__ == "__main__":
    main()
