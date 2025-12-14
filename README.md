# Mr.Sword IRC Client - Terminal Sürümü (2025)
<img width="550" height="510" alt="image" src="https://github.com/user-attachments/assets/773848e7-ec55-408f-8852-ca0d3ed4d2f5" />

Bu proje, terminal (komut satırı) üzerinden çalışan, hacker/matrix temalı bir IRC istemcisi simülasyonu ve P2P sohbet aracıdır. Web tarayıcısı gerektirmez, doğrudan terminalinizde çalışır.


## Öncelikle Bilmen Gereken
⚠️ Arkadaşınla konuşabilmen için VirtualBox ağ ayarları köprü bağdaştırıcısını etkinleştirmelisin.⚠️

## 🌟 Özellikler

- **Gerçek Terminal Deneyimi:** Tamamen komut satırı tabanlı arayüz.
- **Hacker Teması:** Matrix tarzı akış, renkli çıktılar ve ASCII sanatları.
- **E2EE Şifreleme:** Uçtan uca şifreli (AES-256 + ECDH) güvenli mesajlaşma.
- **Türkçe Komutlar:** Kullanımı kolay Türkçe komut seti (`baglan`, `katil`, `sohbet` vb.).
- **P2P Sohbet:** Yerel ağ veya internet üzerinden arkadaşlarınızla güvenli sohbet imkanı.
- **SSH Tünelleme:** Farklı ağlardaki arkadaşlarınızla bağlantı kurabilmek için otomatik SSH tünelleme desteği (Serveo/Localhost.run).

## 📋 Gereksinimler

Projenin çalışması için bilgisayarınızda **Python 3.x** ve aşağıdaki kütüphanelerin yüklü olması gerekmektedir.

- Python 3.6 veya üzeri
- `cryptography` kütüphanesi

Gerekli kütüphaneleri yüklemek için:

```bash
pip install -r requirements.txt
```

Eğer `requirements.txt` dosyasını kullanmak istemezseniz manuel olarak da yükleyebilirsiniz:

```bash
pip install cryptography
```

## 🚀 Kurulum ve Çalıştırma

1. **Projeyi İndirin:** Bu klasörü bilgisayarınıza indirin.
2. **Terminali Açın:** Klasörün içinde bir terminal veya komut satırı penceresi açın.
3. **Bağımlılıkları Yükleyin:** Yukarıdaki *Gereksinimler* bölümündeki komutu çalıştırın.
4. **Türkçe Karakter Desteği (Windows için):**
   Windows terminalinde Türkçe karakterlerin düzgün görünmesi için önce şu komutu çalıştırmanız önerilir:
   ```bash
   chcp 65001
   ```
5. **Uygulamayı Başlatın:**
   Aşağıdaki komutu yazarak uygulamayı çalıştırın:
   ```bash
   python mrsword.py
   ```

## 📖 Kullanım Kılavuzu

Uygulama açıldığında `help` veya `yardim` yazarak komut listesini görebilirsiniz.

- **`baglan`**: Simüle edilmiş bir sunucuya bağlanır.
- **`katil <kanal>`**: Bir sohbet kanalına girer (Örn: `katil #sohbet`).
- **`sohbet`**: Gerçek P2P sohbeti başlatır (Sunucu veya İstemci modunda).
- **`temizle`**: Ekranı temizler.
- **`cikis`**: Uygulamadan çıkar.

### P2P Sohbet (Gerçek Mesajlaşma)
`sohbet` komutunu kullandığınızda iki seçenek sunulur:
1. **Bağlantı Bekle (Sunucu Ol):** Arkadaşınızın size bağlanmasını beklersiniz. Size verilen IP veya Tünel adresini arkadaşınızla paylaşın.
2. **Arkadaşına Bağlan (İstemci Ol):** Arkadaşınızın size verdiği IP adresini ve portu girerek ona bağlanırsınız.

## ⚠️ Yasal Uyarı
Bu yazılım eğitim ve eğlence amaçlı hazırlanmıştır. Kötü amaçlı kullanımlardan geliştirici sorumlu değildir.

---
*İyi eğlenceler!*


