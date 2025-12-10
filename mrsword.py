import sys
import time
import random
import os

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

