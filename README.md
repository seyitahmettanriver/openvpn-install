# 🔒 AlmaLinux OpenVPN Kurulum Betiği

Bu betik, AlmaLinux 8.x sistemlerde OpenVPN sunucusunu otomatik olarak kuran ve yöneten, kullanıcı dostu bir araçtır. Özellikle Plesk Panel ile entegre çalışmak üzere tasarlanmıştır.

![Version](https://img.shields.io/badge/version-1.0-blue)
![Platform](https://img.shields.io/badge/platform-AlmaLinux%208.x-red)
![License](https://img.shields.io/badge/license-MIT-green)

## 🌟 Özellikler

- ✨ Görsel ve kullanıcı dostu arayüz
- 🔐 Güçlü güvenlik yapılandırması
- 🚀 Otomatik kurulum ve yapılandırma
- 📝 Detaylı kurulum günlüğü
- 🛡️ Firewall otomatik yapılandırması
- 👥 Kolay client yönetimi
- 🎨 Renkli ve anlaşılır çıktılar
- 🔄 Plesk Panel uyumluluğu

## 📋 Gereksinimler

- AlmaLinux 8.x
- Root yetkileri
- Plesk Panel (opsiyonel)
- İnternet bağlantısı

## 🚀 Kurulum

1. Betiği indirin:
```bash
wget https://raw.githubusercontent.com/seyitahmettanriver/openvpn-install/refs/heads/main/openvpn-install.sh
```

2. Çalıştırma izni verin:
```bash
chmod +x openvpn-install.sh
```

3. Betiği çalıştırın:
```bash
./openvpn-install.sh
```

## 💡 Kullanım

Betik interaktif bir menü sunar ve aşağıdaki işlemleri yapmanıza olanak tanır:

- 🆕 Yeni OpenVPN sunucusu kurulumu
- 👤 Yeni client ekleme
- ❌ Client sertifikası iptal etme
- 🗑️ OpenVPN'i kaldırma

### İlk Kurulum

İlk kurulum sırasında aşağıdaki seçenekleri yapılandırabilirsiniz:

- 🌐 IP adresi seçimi
- 🔌 Protokol seçimi (UDP/TCP)
- 🚪 Port numarası
- 🔍 DNS sunucusu
- 📝 İlk client ismi

## ⚙️ Yapılandırma

Betik otomatik olarak aşağıdaki yapılandırmaları gerçekleştirir:

- Güvenli sertifika oluşturma
- Firewall kuralları
- IP forwarding
- DNS yapılandırması
- Client yapılandırması

## 🛡️ Güvenlik

Bu betik şu güvenlik özelliklerini içerir:

- AES-256-GCM şifreleme
- SHA256 kimlik doğrulama
- TLS 1.2 minimum versiyon
- Güçlü TLS şifreleme paketi
- Otomatik sertifika yönetimi

## 📝 Client Yapılandırması

Client yapılandırma dosyaları (.ovpn) otomatik olarak oluşturulur ve aşağıdaki özellikleri içerir:

- Özel sertifikalar
- Optimize edilmiş ağ ayarları
- Güvenli şifreleme parametreleri
- DNS yapılandırması

## 🔧 Sorun Giderme

Sık karşılaşılan sorunlar ve çözümleri:

1. Port erişim sorunu:
```bash
sudo firewall-cmd --zone=public --add-port=<port>/udp --permanent
sudo firewall-cmd --reload
```

2. OpenVPN servisi başlatma sorunu:
```bash
sudo systemctl status openvpn-server@server.service
```

3. Sertifika hataları:
```bash
sudo ./openvpn-install.sh  # Seçenek 2'yi kullanarak sertifikayı yeniden oluşturun
```

## 📚 Lisans

Bu proje MIT lisansı altında lisanslanmıştır. Detaylar için [LICENSE](LICENSE) dosyasına bakın.

## 🤝 Katkıda Bulunma

1. Bu projeyi fork edin
2. Feature branch'inizi oluşturun (`git checkout -b feature/AmazingFeature`)
3. Değişikliklerinizi commit edin (`git commit -m 'Add some AmazingFeature'`)
4. Branch'inizi push edin (`git push origin feature/AmazingFeature`)
5. Bir Pull Request oluşturun

## 📮 İletişim

GitHub Issues üzerinden soru sorabilir ve önerilerde bulunabilirsiniz.

## ⭐ Projeyi Destekleyin

Eğer bu proje işinize yaradıysa, ⭐ vermeyi unutmayın! 
