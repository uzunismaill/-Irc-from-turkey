import sys
import time
import random
import os
import socket
import threading

# Renk Kodları (ANSI)
class Colors:
    HEADER = '\033[95m'
    BLUE = '\033[94m'
    CYAN = '\033[96m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    RED = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'

# ASCII Art Logo - Yeşil Hacker Teması
ASCII_LOGO = Colors.GREEN + r"""
  __  __           _____                        _ 
 |  \/  |         / ____|                      | |
 | \  / |_ __    | (___ __      _____  _ __ __| |
 | |\/| | '__|    \___ \\ \ /\ / / _ \| '__/ _` |
 | |  | | |       ____) |\ V  V / (_) | | | (_| |
 |_|  |_|_|      |_____/  \_/\_/ \___/|_|  \__,_|
                                                 
          -- BitchX REBORN 2025 -- 
       -- Mr.Sword Özel Sürümü v1.0 --
""" + Colors.ENDC

# State
is_connected = False
current_channel = None
username = "MrSwordUser"

def clear_screen():
    os.system('cls' if os.name == 'nt' else 'clear')
    print(ASCII_LOGO)

def type_print(text, delay=0.03, color=Colors.GREEN):
    """Prints text with a typewriter effect and color."""
    sys.stdout.write(color)
    for char in text:
        sys.stdout.write(char)
        sys.stdout.flush()
        time.sleep(delay)
    sys.stdout.write(Colors.ENDC + '\n')

def print_line(text, prefix="[*]", color=Colors.CYAN):
    print(f"{color}{prefix} {text}{Colors.ENDC}")

def print_error(text):
    print(f"{Colors.RED}[!] {text}{Colors.ENDC}")

def print_success(text):
    print(f"{Colors.GREEN}[+] {text}{Colors.ENDC}")

def print_help():
    print(f"\n{Colors.YELLOW}--- KOMUT LISTESI ---{Colors.ENDC}")
    print(f"{Colors.BOLD}baglan [sunucu]{Colors.ENDC} : Bir sunucuya bağlanır (Simülasyon)")
    print(f"{Colors.BOLD}katil [kanal]{Colors.ENDC}   : Bir sohbet kanalına girer")
    print(f"{Colors.BOLD}temizle{Colors.ENDC}         : Ekranı temizler")
    print(f"{Colors.BOLD}cikis{Colors.ENDC}           : Uygulamadan çıkar")
    print(f"{Colors.BOLD}sohbet{Colors.ENDC}          : P2P Mesajlaşma (Gerçek)")
    print(f"{Colors.YELLOW}---------------------\n{Colors.ENDC}")

def connect_server(args):
    global is_connected
    if is_connected:
        print_error("Zaten bağlısınız!")
        return

    server = args[0] if args else "irc.mrsword.net"
    print_line(f"{server} sunucusuna bağlanılıyor...", prefix="[SYSTEM]", color=Colors.BLUE)
    time.sleep(1)

    steps = [
        "DNS Çözümleniyor...",
        "IP Adresi Bulundu: 192.168.1.1",
        "Sunucuya el sıkışılıyor... [SYN]",
        "Sunucudan yanıt alındı... [ACK]",
        "Şifreleme anahtarları değiştiriliyor... [RSA-4096]",
        "Mr.Sword Güvenlik Protokolü Aktif...",
        "ROOT Erişimi Sağlandı...",
        "BAĞLANTI BAŞARILI!"
    ]

    for step in steps:
        prefix = random.choice([">", ">>", "#", "*"])
        type_print(f"{prefix} {step}", 0.03, Colors.GREEN)
        time.sleep(0.3)
    
    is_connected = True
    print_success("Hoşgeldiniz! Bir kanala girmek için 'katil # sohbet' yazın.")

def join_channel(args):
    global current_channel
    if not is_connected:
        print_error("Önce bir sunucuya bağlanmalısınız! 'baglan' yazın.")
        return

    channel = args[0] if args else "#genel"
    print_line(f"{channel} kanalına giriliyor...", prefix="[SYSTEM]", color=Colors.BLUE)
    time.sleep(1)
    
    current_channel = channel
    print(f"{Colors.YELLOW}---> {username} {channel} kanalına katıldı{Colors.ENDC}")
    print(f"{Colors.BOLD}Konu:{Colors.ENDC} {Colors.CYAN}Mr.Sword'un Mekanı - Keyifli Sohbetler{Colors.ENDC}")
    print(f"{Colors.BOLD}Kullanıcılar:{Colors.ENDC} {Colors.RED}@MrSword{Colors.ENDC},{Colors.ENDC}, Misafir")

# --- P2P Sohbet Fonksiyonları ---
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

def hacker_decryption_effect(text, color=Colors.GREEN):
    """Metni 'şifresi çözülüyormuş' gibi gösterir."""
    chars = "01010101010101"
    # Kısa bir efekt
    sys.stdout.write(color)
    for _ in range(3):
        sys.stdout.write(f"\r[{''.join(random.choice(chars) for _ in range(10))}] Şifreli Veri Çözülüyor...")
        sys.stdout.flush()
        time.sleep(0.1)
    
    # Gerçek mesajı göster
    sys.stdout.write(f"\r{Colors.ENDC}{Colors.RED}[✓] Arkadaş: {text}{Colors.ENDC}\n")
    sys.stdout.flush()

def receive_messages_p2p(sock, user_type):
    while True:
        try:
            msg = sock.recv(1024).decode('utf-8')
            if msg:
                # Gelen mesaj için efekt yap, sonra kendi input satırını tekrar yaz
                # not: input() bloğu varken stdout yazmak bazen satırı bozar, ama basit çözüm bu.
                sys.stdout.write("\r" + " " * 50 + "\r") # Satırı temizle
                hacker_decryption_effect(msg)
                
                sys.stdout.write(f"{Colors.GREEN}root@terminal:~$ {Colors.ENDC}")
                sys.stdout.flush()
            else:
                print(f"\n{Colors.RED}Bağlantı koptu.{Colors.ENDC}")
                sock.close()
                os._exit(0)
        except:
            # Bağlantı kesilirse sessizce çık veya uyar
            os._exit(0)

def start_p2p_server():
    host = '0.0.0.0'
    port = 5555
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    
    try:
        server.bind((host, port))
    except OSError as e:
        print(f"{Colors.RED}Port hatası (Belki zaten açık?): {e}{Colors.ENDC}")
        return

    server.listen(1)
    server.settimeout(1.0) # 1 saniyelik timeout ekle ki Ctrl+C yakalayabilelim

    print(f"{Colors.BOLD}{Colors.GREEN}[*] Güvenli Soket Oluşturuldu (Port {port})...{Colors.ENDC}")
    print(f"{Colors.GREEN}[*] Dinleme Modu Aktif. Arkadaşının IP'si bekleniyor...{Colors.ENDC}")
    print(f"{Colors.YELLOW}[INFO] Senin IP Adresin: {Colors.BOLD}{get_local_ip()}{Colors.ENDC}")
    print(f"{Colors.RED}[!] İptal etmek için CTRL+C tuşlarına bas.{Colors.ENDC}")

    client = None
    addr = None
    
    while True:
        try:
            client, addr = server.accept()
            break # Bağlantı geldi, döngüden çık
        except socket.timeout:
            continue # Timeout oldu, döngüye devam et (Ctrl+C kontrolü için)
        except KeyboardInterrupt:
             print(f"\n{Colors.RED}[!] Sunucu kapatıldı.{Colors.ENDC}")
             server.close()
             return

    print(f"\n{Colors.BOLD}{Colors.GREEN}[+] BAĞLANTI SAPTANDI: {addr[0]} sisteme girdi!{Colors.ENDC}")
    print(f"{Colors.BLUE}[*] Güvenli tünel kuruluyor... [OK]{Colors.ENDC}")
    print("-" * 50)
    
    threading.Thread(target=receive_messages_p2p, args=(client, "Host"), daemon=True).start()
    
    while True:
        try:
            msg = input(f"{Colors.GREEN}root@terminal:~$ {Colors.ENDC}")
            client.send(msg.encode('utf-8'))
        except KeyboardInterrupt:
            print("\nÇıkış yapılıyor...")
            client.close()
            server.close()
            break
        except Exception:
            break

def start_p2p_client(target_ip):
    port = 5555
    client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    
    print(f"{Colors.GREEN}[*] Hedef sisteme sızılıyor ({target_ip})...{Colors.ENDC}")
    time.sleep(1)
    print(f"{Colors.CYAN}[*] Port taraması... AÇIK{Colors.ENDC}")
    
    try:
        client.connect((target_ip, port))
    except Exception as e:
        print(f"{Colors.RED}[!] Bağlantı reddedildi: {e}{Colors.ENDC}")
        return

    print(f"\n{Colors.BOLD}{Colors.GREEN}[+] SİSTEME ERİŞİM SAĞLANDI!{Colors.ENDC}")
    print(f"{Colors.BLUE}[*] Loglar temizleniyor... [OK]{Colors.ENDC}")
    print("-" * 50)
    
    threading.Thread(target=receive_messages_p2p, args=(client, "Client"), daemon=True).start()
    
    while True:
        try:
            msg = input(f"{Colors.GREEN}root@terminal:~$ {Colors.ENDC}")
            client.send(msg.encode('utf-8'))
        except KeyboardInterrupt:
            print("\nBağlantı sonlandırılıyor...")
            client.close()
            break
        except Exception:
            break

def process_command(cmd_line):
    if not cmd_line.strip():
        return

    parts = cmd_line.strip().split()
    cmd = parts[0].lower()
    args = parts[1:]

    if cmd in ['yardim', 'help']:
        print_help()
    elif cmd in ['temizle', 'clear']:
        clear_screen()
    elif cmd in ['baglan', 'connect']:
        connect_server(args)
    elif cmd in ['katil', 'join']:
        join_channel(args)
    elif cmd in ['sohbet', 'chat']:
        print(f"\n{Colors.YELLOW}--- GERÇEK ZAMANLI CHAT (P2P) ---{Colors.ENDC}")
        print("1. Bağlantı Bekle (Sunucu Ol)")
        print("2. Arkadaşına Bağlan (İstemci Ol)")
        print("3. İptal")
        
        sub_choice = input(f"\n{Colors.GREEN}Seçiminiz (1/2/3): {Colors.ENDC}")
        if sub_choice == '1':
             start_p2p_server()
        elif sub_choice == '2':
             target = input(f"Arkadaşının IP Adresi (Örn: {get_local_ip()}): ")
             start_p2p_client(target)
        else:
             print("İptal edildi.")
    elif cmd in ['cikis', 'exit', 'quit']:
        print(f"{Colors.RED}Sistemden çıkılıyor...{Colors.ENDC}")
        time.sleep(1)
        sys.exit()
    else:
        if is_connected and current_channel:
            timestamp = time.strftime("%H:%M")
            print(f"{Colors.BLUE}[{timestamp}]{Colors.ENDC} <{Colors.GREEN}{username}{Colors.ENDC}> {cmd_line}")
            # Random bot response
            if random.random() > 0.7:
                time.sleep(1)
                print(f"{Colors.BLUE}[{timestamp}]{Colors.ENDC} <{Colors.RED}Bot{Colors.ENDC}> \"{cmd_line}\" dedin ama burası hacker bölgesi, dikkatli ol.")
        else:
            print_error("Bilinmeyen komut. 'yardim' yazarak listeyi görebilirsiniz.")

def main():
    clear_screen()
    type_print("Sistem Başlatılıyor...", 0.05, Colors.GREEN)
    time.sleep(0.5)
    print_line("Çekirdek Yükleniyor... [OK]", prefix="[init]", color=Colors.CYAN)
    print_line("BitchX Modülleri Entegre Edildi... [OK]", prefix="[init]", color=Colors.CYAN)
    print_line("Arayüz: TERMINAL MODU", prefix="[config]", color=Colors.YELLOW)
    print_line("Dil: Türkçe", prefix="[config]", color=Colors.YELLOW)
    print(Colors.GREEN + "----------------------------------------" + Colors.ENDC)
    print("Hazır. Komut girmek için bekliyor.")
    print(f"Yardım için '{Colors.BOLD}yardim{Colors.ENDC}' yazın.")

    while True:
        try:
            prompt_user = f"{Colors.GREEN}{username}{Colors.ENDC}"
            prompt_host = f"{Colors.BLUE}IRC{Colors.ENDC}"
            
            if is_connected:
                prompt_host = f"{Colors.BLUE}{current_channel or 'Sunucu'}{Colors.ENDC}"
            
            prompt = f"{prompt_user}@{prompt_host}> "
            
            cmd_line = input(prompt)
            process_command(cmd_line)
        except KeyboardInterrupt:
            print(f"\n{Colors.RED}Çıkış yapılıyor...{Colors.ENDC}")
            break

if __name__ == "__main__":
    main()



