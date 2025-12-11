import socket
import threading
import sys
import os

# "Hacker" renkleri
GREEN = "\033[92m"
RED = "\033[91m"
RESET = "\033[0m"
BOLD = "\033[1m"

def clear_screen():
    os.system('cls' if os.name == 'nt' else 'clear')

def receive_messages(sock, user_type):
    while True:
        try:
            msg = sock.recv(1024).decode('utf-8')
            if msg:
                # Gelen mesajı göster, sonra kendi input satırını tekrar yaz
                sys.stdout.write(f"\r{RESET}{RED}Arkadaş: {msg}{RESET}\n")
                sys.stdout.write(f"{GREEN}Sen: {RESET}")
                sys.stdout.flush()
            else:
                print(f"\n{RED}Bağlantı koptu.{RESET}")
                sock.close()
                os._exit(0)
        except:
            print(f"\n{RED}Bir hata oluştu veya bağlantı kesildi.{RESET}")
            sock.close()
            os._exit(0)

def start_server():
    host = '0.0.0.0'
    port = 5555
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        server.bind((host, port))
    except OSError as e:
        print(f"{RED}Pot hatası: {e}{RESET}")
        return

    server.listen(1)
    print(f"{BOLD}{GREEN}[*] Bağlantı bekleniyor (Port {port})...{RESET}")
    print(f"{GREEN}[*] Arkadaşına IP adresini ver. IP adresini 'ipconfig' komutu ile öğrenebilirsin.{RESET}")
    
    client, addr = server.accept()
    print(f"\n{BOLD}{GREEN}[+] {addr[0]} bağlandı! Sohbet başladı.{RESET}\n")
    print("-" * 50)
    
    threading.Thread(target=receive_messages, args=(client, "Host"), daemon=True).start()
    
    while True:
        try:
            msg = input(f"{GREEN}Sen: {RESET}")
            client.send(msg.encode('utf-8'))
        except KeyboardInterrupt:
            print("\nÇıkış yapılıyor...")
            client.close()
            break

def start_client(target_ip):
    port = 5555
    client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    
    print(f"{GREEN}[*] {target_ip} adresine bağlanılıyor...{RESET}")
    
    try:
        client.connect((target_ip, port))
    except Exception as e:
        print(f"{RED}[!] Bağlanılamadı: {e}{RESET}")
        return

    print(f"\n{BOLD}{GREEN}[+] Bağlantı başarılı! Sohbet başladı.{RESET}\n")
    print("-" * 50)
    
    threading.Thread(target=receive_messages, args=(client, "Client"), daemon=True).start()
    
    while True:
        try:
            msg = input(f"{GREEN}Sen: {RESET}")
            client.send(msg.encode('utf-8'))
        except KeyboardInterrupt:
            print("\nÇıkış yapılıyor...")
            client.close()
            break


def get_local_ip():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        # Dış internete bağlı gibi yaparak yerel IP'yi bul
        s.connect(('8.8.8.8', 80))
        IP = s.getsockname()[0]
    except Exception:
        IP = '127.0.0.1'
    finally:
        s.close()
    return IP

def print_instructions():
    print(f"\n{BOLD}{GREEN}=== NASIL KULLANILIR? (ADIM ADIM) ==={RESET}")
    print(f"{GREEN}Bu program ile arkadaşınla terminal üzerinden şifreli gibi görünen havalı bir sohbet yapabilirsin.{RESET}")
    print(f"{GREEN}Bağlantı kurmak için şu adımları takip edin:{RESET}\n")
    
    print(f"{BOLD}1. ADIM: Aynı Ağda Olun{RESET}")
    print("   - Arkadaşınla aynı Wi-Fi ağında (modemde) olmalısınız.")
    print("   - Veya Hamachi, Radmin VPN gibi bir programla aynı sanal ağda olmalısınız.\n")
    
    print(f"{BOLD}2. ADIM: Roller (Sunucu ve İstemci){RESET}")
    print("   - BİRİNİZ '1'i seçip Sunucu (Host) olmalı.")
    print("   - DİĞERİNİZ '2'yi seçip İstemci (Client) olmalı.")
    print("   - İki taraf da aynı modu seçerse ÇALIŞMAZ.\n")
    
    print(f"{BOLD}3. ADIM: IP Adresi{RESET}")
    print("   - Sunucu olan kişi (1'i seçen), terminalde çıkan IP adresini arkadaşına söylemeli.")
    print("   - İstemci olan kişi (2'yi seçen), bu IP adresini girmeli.\n")
    print("-" * 50 + "\n")

if __name__ == "__main__":
    clear_screen()
    print_instructions()
    print(f"{BOLD}{GREEN}=== TERMINAL SOHBET SİSTEMİ ==={RESET}")
    print("1. Bağlantı Bekle (Sunucu Ol - Şifreyi Sen Ver)")
    print("2. Arkadaşına Bağlan (İstemci Ol - Şifreyi Gir)")
    
    choice = input("\nSeçiminiz (1/2): ")
    
    if choice == '1':
        print(f"\n{GREEN}[*] IP Adresin: {BOLD}{get_local_ip()}{RESET}{GREEN} (Bunu arkadaşına ver){RESET}")
        start_server()
    elif choice == '2':
        ip = input(f"Arkadaşının IP Adresi (Örn: {get_local_ip()}): ")
        start_client(ip)
    else:
        print("Geçersiz seçim.")
