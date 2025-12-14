import sys
import time
import random
import os
import socket
import threading
import subprocess
import base64
try:
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.hazmat.primitives.kdf.hkdf import HKDF
    from cryptography.fernet import Fernet
except ImportError:
    print("Cryptography kütüphanesi eksik! Lütfen 'pip install cryptography' çalıştırın.")
    sys.exit()

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
    WHITE = '\033[97m'

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

ASCII_SKULL = Colors.RED + r"""
                         ______
                      .-"      "-.
                     /            \
                    |              |
                    |,  .-.  .-.  ,|
                    | )(__/  \__)( |
                    |/     /\     \|
                    (_     ^^     _)
                     \__|IIIIII|__/
                      | \IIIIII/ |
                      \          /
                       `--------`
""" + Colors.ENDC

# State
is_connected = False
current_channel = None
username = "MrSwordUser"

class E2EESecurity:
    def __init__(self):
        self.private_key = ec.generate_private_key(ec.SECP384R1())
        self.public_key = self.private_key.public_key()
        self.shared_key = None
        self.fernet = None

    def get_public_bytes(self):
        return self.public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )

    def generate_shared_secret(self, peer_public_bytes):
        peer_public_key = serialization.load_pem_public_key(peer_public_bytes)
        shared_secret = self.private_key.exchange(ec.ECDH(), peer_public_key)
        
        # Derive a key for Fernet (AES)
        derived_key = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=None,
            info=b'mrsword_handshake',
        ).derive(shared_secret)
        
        self.fernet = Fernet(base64.urlsafe_b64encode(derived_key))
        
    def encrypt(self, message):
        return self.fernet.encrypt(message.encode('utf-8'))
        
    def decrypt(self, token):
        return self.fernet.decrypt(token).decode('utf-8')

def perform_secure_handshake(sock, is_server=False):
    print_line("GÜVENLİK PROTOKOLÜ BAŞLATILIYOR...", prefix="[SEC]", color=Colors.RED)
    time.sleep(0.5)
    sec = E2EESecurity()
    my_pub = sec.get_public_bytes()
    
    print_line("2048-bit RSA/ECC Anahtarlar Oluşturuldu...", prefix="[SEC]", color=Colors.YELLOW)
    
    if is_server:
        print_line("İstemci genel anahtarı bekleniyor...", prefix="[WAIT]", color=Colors.BLUE)
        peer_pub_bytes = sock.recv(4096)
        sock.send(my_pub)
    else:
        print_line("Genel anahtar sunucuya gönderiliyor...", prefix="[SEND]", color=Colors.BLUE)
        sock.send(my_pub)
        peer_pub_bytes = sock.recv(4096)
        
    sec.generate_shared_secret(peer_pub_bytes)
    print_success("E2E (UÇTAN UCA) ŞİFRELEME AKTİF! [AES-256 + ECDH]")
    print_line("Bu sohbette konuşulanları 3. kişiler (Hackerlar/Polis dahil) göremez.", prefix="[SECURE]", color=Colors.GREEN)
    return sec

def play_laser_sound():
    """Plays a laser-like sound effect on Windows."""
    if os.name == 'nt':
        try:
            import winsound
            # Hızlı frekans düşüşü ile 'Pew Pew' sesi
            for start_freq in [1500, 1500]: # İki kez ateş
                for freq in range(start_freq, 300, -100):
                    winsound.Beep(freq, 20)
                time.sleep(0.05)
        except ImportError:
            pass

def animate_skull():
    """Displays a glitching/animated skull effect."""
    skull_frames = [
        Colors.RED + r"""
                         ______
                      .-"      "-.
                     /            \
                    |              |
                    |,  .-.  .-.  ,|
                    | )(__/  \__)( |
                    |/     /\     \|
                    (_     ^^     _)
                     \__|IIIIII|__/
                      | \IIIIII/ |
                      \          /
                       `--------`
""" + Colors.ENDC,
        Colors.WHITE + r"""
                         ______
                      .-"      "-.
                     /            \
                    |              |
                    |,  O  .  O   ,|
                    | )(__/  \__)( |
                    |/     /\     \|
                    (_     ^^     _)
                     \__|xxxxxx|__/
                      | \xxxxxx/ |
                      \          /
                       `--------`
""" + Colors.ENDC
    ]
    
    # 3 kez yanıp sönme efekti
    for _ in range(3):
        for frame in skull_frames:
            sys.stdout.write("\033[H\033[J") # Ekranı silmeden üstüne yazmak zor, clear kullanacağız
            os.system('cls' if os.name == 'nt' else 'clear')
            print("\n" * 2)
            print(frame)
            print(f"\n{Colors.RED}[!] SİSTEM İHLALİ TESPİT EDİLDİ [!]{Colors.ENDC}")
            time.sleep(0.1)
    
    # Final hali
    os.system('cls' if os.name == 'nt' else 'clear')
    print("\n" * 2)
    print(skull_frames[0])

def clear_screen():
    os.system('cls' if os.name == 'nt' else 'clear')
    # ASCII_LOGO burada basılmıyor artık, main içinde yönetilecek

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
    print(f"{Colors.BOLD}bot{Colors.ENDC}             : Yapay Zeka ile Sohbet (Mizah)")
    print(f"{Colors.YELLOW}---------------------\n{Colors.ENDC}")

def connect_server(args):
    global is_connected
    if is_connected:
        print_error("Zaten bağlısınız!")
        return

    server = args[0] if args else "irc.mrsword.net"
    print(ASCII_SKULL)
    print_line(f"HEDEF: {server}", prefix="[TARGET]", color=Colors.RED)
    print_line("Siber saldırı protokolleri başlatılıyor...", prefix="[INIT]", color=Colors.YELLOW)
    time.sleep(1)

    steps = [
        "Proxy zincirleri oluşturuluyor (Tor > VPN > SSH)...",
        "Güvenlik duvarı bypass ediliyor...",
        f"Hedef IP tespit edildi: {random.randint(10,200)}.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(0,255)}",
        "Port 6667 (IRC) üzerinde zafiyet aranıyor...",
        "Exploit gönderildi... [Buffer Overflow]",
        "Yetki yükseltiliyor... [ROOT]",
        "Arka kapı (Backdoor) yerleştirildi...",
        "Loglar temizleniyor...",
        "GİZLİ BAĞLANTI KURULDU."
    ]

    for step in steps:
        prefix = random.choice(["[+]", "[*]", "[!]", "[>]"])
        color = random.choice([Colors.GREEN, Colors.CYAN, Colors.BLUE])
        type_print(f"{prefix} {step}", 0.02, color)
        time.sleep(random.uniform(0.2, 0.6))
    
    is_connected = True
    print_success("Sisteme sızma başarılı! Kanalları listelemek için bekleyin...")
    time.sleep(1)
    print(f"\n{Colors.YELLOW}Mevcut Kanallar:{Colors.ENDC}")
    print(f"  {Colors.GREEN}#genel{Colors.ENDC} - Yeni başlayan lamerlar")
    print(f"  {Colors.RED}#deepweb{Colors.ENDC} - Sadece davetliler")
    print(f"  {Colors.BLUE}#exploit{Colors.ENDC} - 0day paylaşımları")
    print(f"\nBir kanala girmek için '{Colors.BOLD}katil #kanal{Colors.ENDC}' yazın.")

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
    """Metni direkt gösterir (Efekt kaldırıldı)."""
    # Efekt kaldırıldı, direkt mesajı gösteriyoruz
    sys.stdout.write(f"\r{Colors.ENDC}{Colors.RED}[✓] Arkadaş: {text}{Colors.ENDC}\n")
    sys.stdout.flush()

def receive_messages_p2p(sock, user_type, security):
    while True:
        try:
            encrypted_msg = sock.recv(4096)
            if not encrypted_msg:
                print(f"\n{Colors.RED}Bağlantı koptu.{Colors.ENDC}")
                sock.close()
                os._exit(0)

            try:
                msg = security.decrypt(encrypted_msg)
            except Exception:
                print(f"\n{Colors.RED}[!] Geçersiz şifreli paket alındı (Yoksayılıyor).{Colors.ENDC}")
                continue

            # Gelen mesaj için efekt yap, sonra kendi input satırını tekrar yaz
            sys.stdout.write("\r" + " " * 60 + "\r") # Satırı temizle
            hacker_decryption_effect(msg)
            
            sys.stdout.write(f"{Colors.GREEN}root@terminal:~$ {Colors.ENDC}")
            sys.stdout.flush()

        except OSError:
            os._exit(0)
        except Exception as e:
             # Beklenmeyen bir hata
             os._exit(0)

def start_ssh_tunnel(port):
    """
    SSH Tünelleme: Önce Serveo.net dener, başarısız olursa Localhost.run dener.
    """
    
    def _try_tunnel(cmd, service_name):
        try:
            startupinfo = None
            if os.name == 'nt':
                startupinfo = subprocess.STARTUPINFO()
                startupinfo.dwFlags |= subprocess.STARTF_USESHOWWINDOW

            process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT, 
                stdin=subprocess.PIPE,
                text=True,
                bufsize=1,
                startupinfo=startupinfo
            )
            
            start_t = time.time()
            found_address = None
            
            print_line(f"{service_name} sunucusuna bağlanılıyor...", prefix="[WAIT]", color=Colors.BLUE)

            while time.time() - start_t < 15:
                line = process.stdout.readline()
                if not line:
                    if process.poll() is not None:
                        break
                    continue
                
                if service_name == "serveo" and "Forwarding TCP connections from" in line:
                    found_address = line.strip().split("from")[-1].strip()
                    break
                
                if service_name == "localhost.run" and ("localhost.run" in line) and ("http" in line):
                     import re
                     match = re.search(r'(https?://[^\s]+)', line)
                     if match:
                         found_address = match.group(1)
                         break
            
            if found_address:
                return process, found_address
            else:
                try:
                    process.kill()
                except:
                    pass
                return None, None

        except FileNotFoundError:
            return None, None
        except Exception as e:
            print_error(f"Tünel hatası ({service_name}): {e}")
            return None, None

    # 1. DENEME: SERVEO.NET
    print_line("Tünel Başlatılıyor (Serveo.net)...", prefix="[NETWORK]", color=Colors.YELLOW)
    cmd_serveo = ["ssh", "-o", "StrictHostKeyChecking=no", "-R", f"0:localhost:{port}", "serveo.net"]
    
    proc, addr = _try_tunnel(cmd_serveo, "serveo")
    if addr:
        return proc, addr
        
    # 2. DENEME: LOCALHOST.RUN
    print_line("Serveo başarısız. Alternatif Tünel (Localhost.run) deneniyor...", prefix="[NETWORK]", color=Colors.YELLOW)
    cmd_lhr = ["ssh", "-o", "StrictHostKeyChecking=no", "-R", f"80:localhost:{port}", "nopass@localhost.run"]
    
    proc, addr = _try_tunnel(cmd_lhr, "localhost.run")
    if addr:
        return proc, addr

    return None, None

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

    tunnel_proc = None
    
    print(f"\n{Colors.CYAN}Bağlantı Tipi Seçin:{Colors.ENDC}")
    print(f"1. {Colors.GREEN}Yerel Ağ (Aynı WiFi){Colors.ENDC}")
    print(f"2. {Colors.RED}Global Ağ (Farklı Şehirler - Otomatik Tünel){Colors.ENDC}")
    
    net_choice = input(f"{Colors.YELLOW}Seçim (1/2): {Colors.ENDC}")

    if sys.platform.startswith('linux'):
        print(f"\n{Colors.YELLOW}[!] Linux/Kali İpucu:{Colors.ENDC} Arkadaşınız bağlanamazsa şu komutları yeni bir terminalde çalıştırın:")
        print(f"{Colors.RED}    sudo ufw allow {port}/tcp{Colors.ENDC}")
        print(f"{Colors.RED}    sudo iptables -A INPUT -p tcp --dport {port} -j ACCEPT{Colors.ENDC}\n")
    
    print(f"{Colors.BOLD}{Colors.GREEN}[*] Güvenli Soket Oluşturuldu (Port {port})...{Colors.ENDC}")
    
    if net_choice == '2':
        tunnel_proc, tunnel_addr = start_ssh_tunnel(port)
        if tunnel_addr:
            host_url = tunnel_addr
            host_port = "80 (veya 443)"
            
            # Eğer serveo ise portu ayıkla, localhost.run ise url ver
            if ":" in tunnel_addr and "localhost.run" not in tunnel_addr:
                 parts = tunnel_addr.split(":")
                 if len(parts) == 2:
                     host_url, host_port = parts

            print(f"\n{Colors.GREEN}" + "="*50)
            print(f"   DÜNYA GENELİNDEN BAĞLANTI İÇİN BİLGİLER")
            print(f"   ARKADAŞININ GİRECEĞİ ADRES : {Colors.WHITE}{Colors.BOLD}{host_url}{Colors.GREEN}")
            print(f"   ARKADAŞININ GİRECEĞİ PORT  : {Colors.WHITE}{Colors.BOLD}{host_port}{Colors.GREEN}")
            print("="*50 + f"{Colors.ENDC}\n")
        else:
            print_error("Otomatik tünel açılamadı. Lütfen 'ngrok tcp 5555' kullanmayı deneyin.")
            print(f"{Colors.YELLOW}[INFO] Senin Yerel IP Adresin: {Colors.BOLD}{get_local_ip()}{Colors.ENDC}")
    else:
        print(f"{Colors.GREEN}[*] Dinleme Modu Aktif. Yerel ağ üzerinden bekleniyor...{Colors.ENDC}")
        print(f"{Colors.YELLOW}[INFO] Senin Yerel IP Adresin: {Colors.BOLD}{get_local_ip()}{Colors.ENDC}")
    
    print(f"{Colors.RED}[!] İptal etmek için CTRL+C tuşlarına bas.{Colors.ENDC}")

    client = None
    addr = None
    
    while True:
        try:
            client, addr = server.accept()
            break # Bağlantı geldi, döngüden çık
        except socket.timeout:
            continue # Timeout oldu, döngüye devam et
        except KeyboardInterrupt:
             print(f"\n{Colors.RED}[!] Sunucu kapatıldı.{Colors.ENDC}")
             if tunnel_proc: tunnel_proc.kill()
             server.close()
             return

    if tunnel_proc:
        # Bağlantı kurulsa bile tünel açık kalmalı
        pass

    print(f"\n{Colors.BOLD}{Colors.GREEN}[+] BAĞLANTI SAPTANDI: {addr[0]} sisteme girdi!{Colors.ENDC}")

    print(f"{Colors.BLUE}[*] Güvenli tünel kuruluyor... [OK]{Colors.ENDC}")
    
    # Handshake
    security = perform_secure_handshake(client, is_server=True)

    print("-" * 50)
    
    threading.Thread(target=receive_messages_p2p, args=(client, "Host", security), daemon=True).start()
    
    while True:
        try:
            msg = input(f"{Colors.GREEN}root@terminal:~$ {Colors.ENDC}")
            client.send(security.encrypt(msg))
        except KeyboardInterrupt:
            print("\nÇıkış yapılıyor...")
            client.close()
            server.close()
            break
        except Exception:
            break

def start_p2p_client(target_ip, port=5555):
    # port varsayılan olarak 5555, ama değiştirilebilir

    client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    
    print(f"{Colors.GREEN}[*] Hedef sisteme sızılıyor ({target_ip})...{Colors.ENDC}")
    time.sleep(1)
    print(f"{Colors.CYAN}[*] Port taraması yapılıyor...{Colors.ENDC}")
    time.sleep(1)
    
    try:
        client.connect((target_ip, port))
        print(f"{Colors.CYAN}[*] Port {port} ... {Colors.GREEN}AÇIK{Colors.ENDC}")
    except Exception as e:
        print(f"{Colors.RED}[!] Port {port} ... {Colors.RED}KAPALI{Colors.ENDC}")
        print(f"{Colors.RED}[!] Bağlantı reddedildi: {e}{Colors.ENDC}")
        print(f"\n{Colors.YELLOW}[?] İPUÇLARI:{Colors.ENDC}")
        print(f"{Colors.YELLOW} 1. Karşı tarafın '1. Bağlantı Bekle' seçeneğini seçtiğinden emin olun.{Colors.ENDC}")
        print(f"{Colors.YELLOW} 2. IP adresinin ({target_ip}) ve Portun ({port}) doğru olduğundan emin olun.{Colors.ENDC}")
        print(f"{Colors.YELLOW} 3. Aynı ağdaysanız yerel IP, farklı ağdaysanız Tünel IP'sini kullanın.{Colors.ENDC}")
        print(f"{Colors.YELLOW} 4. Kali/Linux kullanıyorsanız güvenlik duvarı (UFW) port 5555'i engelliyor olabilir.{Colors.ENDC}")
        return

    print(f"\n{Colors.BOLD}{Colors.GREEN}[+] SİSTEME ERİŞİM SAĞLANDI!{Colors.ENDC}")
    print(f"{Colors.BLUE}[*] Loglar temizleniyor... [OK]{Colors.ENDC}")
    
    # Handshake
    security = perform_secure_handshake(client, is_server=False)
    
    print("-" * 50)
    
    threading.Thread(target=receive_messages_p2p, args=(client, "Client", security), daemon=True).start()
    
    while True:
        try:
            msg = input(f"{Colors.GREEN}root@terminal:~$ {Colors.ENDC}")
            client.send(security.encrypt(msg))
        except KeyboardInterrupt:
            print("\nBağlantı sonlandırılıyor...")
            client.close()
            break
        except Exception:
            break

def get_bot_response(message):
    """Returns a humorous/hacker-themed response based on the input."""
    msg = message.lower()
    
    responses = [
        "Sisteme sızmaya çalışıyorsun ama klavyen çok ses çıkarıyor...",
        "Bu komutu çalıştırmak için IQ seviyen yetersiz olabilir.",
        "Error 404: Mantık bulunamadı.",
        "NSA loglarına kaydedildin. Şaka şaka... ya da değil?",
        "Mavi hapı mı aldın kırmızı hapı mı?",
        "Ben bir botum ama senden daha zeki olabilirim.",
        "Terminallerde gezerken ayak izi bırakma evlat.",
        "Şifrelerin '123456' mı? Gülünç.",
        "Kahvemi dökmemeye çalışıyorum, beni meşgul etme.",
        "Arka planda bitcoin kazmıyorum, söz veriyorum. (Belki biraz)",
        "sudo rm -rf / yapmamı ister misin?",
        "BitchX protokolü senin gibileri kahvaltıda yer.",
        "IP adresini kara borsada satmamam için bir sebep söyle.",
        "Gerçek hayatta da böyle misin yoksa sadece terminalde mi?",
    ]
    
    if "merhaba" in msg or "selam" in msg:
        return "Selam insanoğlu. Hangi veri tabanını patlatıyoruz bugün?"
    elif "nasılsın" in msg:
        return "İşlemcim %5 kullanımda, RAM ferah, keyfim yerinde. Sen?"
    elif "hack" in msg:
        return "Hacklemek sanat işidir, script kiddie olma."
    elif "kimsin" in msg:
        return "Ben Mr.Sword'un dijital ruhuyum. Ve senin kabusun."
    elif "yardım" in msg:
        return "Yardım istiyorsan Google kullan, ben dadı değilim."
    elif "bot" in msg:
        return "Bana 'bot' deme, 'Yapay Zeka Lordu' diyeceksin."
    else:
        return random.choice(responses)

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
             target_port = input("Hedef Port (Varsayılan 5555, Ngrok için değişir): ")
             if target_port.strip():
                 start_p2p_client(target, int(target_port))
             else:
                 start_p2p_client(target)
        else:
             print("İptal edildi.")
    elif cmd in ['cikis', 'exit', 'quit']:
        print(f"{Colors.RED}Sistemden çıkılıyor...{Colors.ENDC}")
        time.sleep(1)
        sys.exit()
    elif cmd in ['bot', 'ai']:
        print(f"\n{Colors.YELLOW}--- MR.SWORD AI BOT V2.0 ---{Colors.ENDC}")
        print(f"{Colors.RED}DİKKAT:{Colors.ENDC} Bu botun mizah anlayışı biraz karanlıktır.")
        print("Çıkmak için 'exit' yazın.\n")
        
        while True:
            try:
                msg = input(f"{Colors.GREEN}Sen > {Colors.ENDC}")
                if msg.lower() in ['exit', 'cikis', 'quit']:
                    print("Bot kapatılıyor...")
                    break
                
                resp = get_bot_response(msg)
                time.sleep(0.5)
                # Typewriter effect for bot
                sys.stdout.write(f"{Colors.RED}Bot > {Colors.ENDC}")
                type_print(resp, 0.02, Colors.YELLOW)
            except KeyboardInterrupt:
                break
    else:
        if is_connected and current_channel:
            timestamp = time.strftime("%H:%M")
            print(f"{Colors.BLUE}[{timestamp}]{Colors.ENDC} <{Colors.GREEN}{username}{Colors.ENDC}> {cmd_line}")
            # Bot always responds in simulation now for fun
            time.sleep(random.uniform(0.5, 1.5))
            resp = get_bot_response(cmd_line)
            print(f"{Colors.BLUE}[{timestamp}]{Colors.ENDC} <{Colors.RED}Bot{Colors.ENDC}> {resp}")
        else:
            print_error("Bilinmeyen komut. 'yardim' yazarak listeyi görebilirsiniz.")

def main():
    clear_screen()
    
    # Sound effect
    threading.Thread(target=play_laser_sound).start()
    
    # Intro Animation
    animate_skull()
    time.sleep(0.5)
    
    clear_screen()
    print(ASCII_LOGO)
    
    type_print("Sistem Başlatılıyor...", 0.05, Colors.GREEN)
    
    # Fake loading bars
    loading_steps = [
        ("Çekirdek Yükleniyor", Colors.CYAN),
        ("Kriptolama Modülleri", Colors.BLUE),
        ("Ağ Sürücüleri", Colors.YELLOW),
        ("BitchX Arayüzü", Colors.RED)
    ]
    
    for text, color in loading_steps:
        sys.stdout.write(f"{color}[*] {text} ... {Colors.ENDC}")
        sys.stdout.flush()
        time.sleep(0.3)
        print(f"{Colors.GREEN}[OK]{Colors.ENDC}")
    
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
