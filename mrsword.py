import sys
import time
import random
import os

# ASCII Art Logo
ASCII_LOGO = r"""
  __  __           _____                        _ 
 |  \/  |         / ____|                      | |
 | \  / |_ __    | (___ __      _____  _ __ __| |
 | |\/| | '__|    \___ \\ \ /\ / / _ \| '__/ _` |
 | |  | | |       ____) |\ V  V / (_) | | | (_| |
 |_|  |_|_|      |_____/  \_/\_/ \___/|_|  \__,_|
                                                 
          -- BitchX REBORN 2025 -- 
       -- Mr.Sword Özel Sürümü v1.0 --
"""

# State
is_connected = False
current_channel = None
username = "MrSwordUser"

def clear_screen():
    os.system('cls' if os.name == 'nt' else 'clear')
    print(ASCII_LOGO)

def type_print(text, delay=0.03):
    """Prints text with a typewriter effect."""
    for char in text:
        sys.stdout.write(char)
        sys.stdout.flush()
        time.sleep(delay)
    print()

def print_line(text, prefix="[*]"):
    print(f"{prefix} {text}")

def print_help():
    print("\n--- KOMUT LISTESI ---")
    print("baglan [sunucu] : Bir sunucuya bağlanır (Simülasyon)")
    print("katil [kanal]   : Bir sohbet kanalına girer")
    print("temizle         : Ekranı temizler")
    print("cikis           : Uygulamadan çıkar")
    print("---------------------\n")

def connect_server(args):
    global is_connected
    if is_connected:
        print("(!) Zaten bağlısınız!")
        return

    server = args[0] if args else "irc.mrsword.net"
    print(f"[SYSTEM] {server} sunucusuna bağlanılıyor...")
    time.sleep(1)

    steps = [
        "DNS Çözümleniyor...",
        "IP Adresi Bulundu: 192.168.1.1",
        "Sunucuya el sıkışılıyor...",
        "Şifreleme anahtarları değiştiriliyor...",
        "Mr.Sword Güvenlik Protokolü Aktif...",
        "BAĞLANTI BAŞARILI!"
    ]

    for step in steps:
        type_print(f"> {step}", 0.05)
        time.sleep(0.5)
    
    is_connected = True
    print("\n[INFO] Hoşgeldiniz! Bir kanala girmek için 'katil # sohbet' yazın.")

def join_channel(args):
    global current_channel
    if not is_connected:
        print("(!) Önce bir sunucuya bağlanmalısınız! 'baglan' yazın.")
        return

    channel = args[0] if args else "#genel"
    print(f"[SYSTEM] {channel} kanalına giriliyor...")
    time.sleep(1)
    
    current_channel = channel
    print(f"---> {username} {channel} kanalına katıldı")
    print("Konu: Mr.Sword'un Mekanı - Keyifli Sohbetler")
    print("Kullanıcılar: @MrSword, +Antigravity, Misafir")

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
        print("Sistemden çıkılıyor...")
        time.sleep(1)
        sys.exit()
    else:
        if is_connected and current_channel:
            print(f"<{username}> {cmd_line}")
            # Random bot response
            if random.random() > 0.7:
                time.sleep(1)
                print(f"<Bot> \"{cmd_line}\" dedin ama ne demek istedin?")
        else:
            print("(!) Bilinmeyen komut. 'yardim' yazarak listeyi görebilirsiniz.")

def main():
    clear_screen()
    print("Sistem Başlatılıyor...")
    time.sleep(1)
    print("Çekirdek Yükleniyor... [OK]")
    print("BitchX Modülleri Entegre Edildi... [OK]")
    print("Arayüz: TERMINAL MODU")
    print("Dil: Türkçe")
    print("----------------------------------------")
    print("Hazır. Komut girmek için bekliyor.")
    print("Yardım için 'yardim' yazın.")

    while True:
        try:
            prompt = f"{username}@IRC> "
            if is_connected:
                prompt = f"{username}@{current_channel or 'Sunucu'}> "
            
            cmd_line = input(prompt)
            process_command(cmd_line)
        except KeyboardInterrupt:
            print("\nÇıkış yapılıyor...")
            break

if __name__ == "__main__":
    main()
