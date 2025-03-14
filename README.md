# 🔒 OpenVPN Kurulum ve Yönetim Aracı

[![Version](https://img.shields.io/badge/version-1.0-blue.svg)](https://github.com/seyitahmettanriver/openvpn-install)
[![Platform](https://img.shields.io/badge/platform-AlmaLinux%208+-red.svg)](https://almalinux.org/)
[![Plesk](https://img.shields.io/badge/Plesk-Supported-green.svg)](https://www.plesk.com/)

AlmaLinux 8+ ve Plesk Panel için optimize edilmiş, kullanıcı dostu OpenVPN kurulum ve yönetim betiği.

## 🌟 Özellikler

- 📱 Kullanıcı dostu, renkli ve interaktif arayüz
- 🔐 Güçlü şifreleme seçenekleri (AES-256-GCM, AES-128-GCM, CHACHA20-POLY1305)
- 🌐 Çoklu DNS seçenekleri:
  - Google DNS
  - Cloudflare DNS
  - OpenDNS
  - Quad9
  - AdGuard DNS
  - Sistem DNS
- 🛡️ Plesk Panel ile uyumlu iptables yapılandırması
- 📊 Kolay client yönetimi
- 🔄 Otomatik sertifika yönetimi
- ⚡ Optimize edilmiş performans ayarları

## 📋 Gereksinimler

- AlmaLinux 8+
- Plesk Panel
- Root yetkisi

## 🚀 Kurulum

1. Betiği indirin:
```bash
wget https://raw.githubusercontent.com/seyitahmettanriver/openvpn-install/main/openvpn-install.sh
```

2. Çalıştırma izni verin:
```bash
chmod +x openvpn-install.sh
```

3. Betiği çalıştırın:
```bash
./openvpn-install.sh
```

## 💻 Kullanım

### İlk Kurulum
- Betiği çalıştırdığınızda size aşağıdaki seçenekler sunulacaktır:
  1. IP adresi seçimi
  2. Protokol seçimi (UDP/TCP)
  3. Port seçimi
  4. DNS sunucu seçimi
  5. Şifreleme algoritması seçimi
  6. Maksimum client sayısı
  7. İlk client ismi

### Mevcut Kurulum Yönetimi
- Betik tekrar çalıştırıldığında şu seçenekler sunulur:
  1. Yeni client ekle
  2. Client sertifikası iptal et
  3. OpenVPN'i kaldır
  4. Çıkış

## 🔧 Güvenlik Özellikleri

- TLS 1.2 minimum versiyon
- Güçlü şifreleme algoritmaları
- Client sertifika doğrulama
- IP forwarding güvenliği
- Plesk uyumlu firewall kuralları

## 📝 Log Dosyaları

- Server log: `/var/log/openvpn/openvpn.log`
- Status log: `/var/log/openvpn/openvpn-status.log`

## ⚠️ Sorun Giderme

1. Servis durumunu kontrol edin:
```bash
systemctl status openvpn-server@server
```

2. Log dosyasını kontrol edin:
```bash
tail -f /var/log/openvpn/openvpn.log
```

## 📞 İletişim

- GitHub: [seyitahmettanriver](https://github.com/seyitahmettanriver)

## 📜 Lisans

Bu proje MIT lisansı altında lisanslanmıştır. Detaylar için [LICENSE](LICENSE) dosyasına bakın.

## 👥 Katkıda Bulunma

1. Bu depoyu fork edin
2. Yeni bir özellik dalı oluşturun (`git checkout -b yeni-ozellik`)
3. Değişikliklerinizi commit edin (`git commit -am 'Yeni özellik eklendi'`)
4. Dalınıza push yapın (`git push origin yeni-ozellik`)
5. Bir Pull Request oluşturun

---
⭐️ Bu projeyi beğendiyseniz yıldız vermeyi unutmayın! 
