#!/bin/bash

# Renkler
GREEN='\033[0;32m'
BLUE='\033[0;34m'
RED='\033[0;31m'
NC='\033[0m'

echo -e "${BLUE}[*] Mr.Sword Kali Linux Kurulum ve Başlatma Scripti${NC}"

# Python kontrolü
if ! command -v python3 &> /dev/null; then
    echo -e "${RED}[!] Python3 bulunamadı! Yükleniyor...${NC}"
    sudo apt-get update
    sudo apt-get install -y python3 python3-pip python3-venv openssh-client net-tools
fi

# Sanal ortam kontrolü
if [ ! -d "venv" ]; then
    echo -e "${BLUE}[*] Sanal ortam (venv) oluşturuluyor...${NC}"
    python3 -m venv venv
fi

# Sanal ortamı aktive et
source venv/bin/activate

# Bağımlılıkları yükle
echo -e "${BLUE}[*] Gerekli kütüphaneler kontrol ediliyor...${NC}"
pip install -r requirements.txt --quiet

# Çalıştırma izni ver (eğer yoksa)
chmod +x mrsword.py

# Uygulamayı başlat
echo -e "${GREEN}[+] Başlatılıyor...${NC}"
python3 mrsword.py
