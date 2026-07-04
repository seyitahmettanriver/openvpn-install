<div align="center">
  <h1>🚀 Gelişmiş OpenVPN Kurulum Sihirbazı</h1>
  <p><b>AlmaLinux 8/9 ve Plesk Panel Sistemler İçin Optimize Edilmiş Özel Sürüm</b></p>
  
  [![AlmaLinux](https://img.shields.io/badge/AlmaLinux-8%20%7C%209-blue?style=flat-square&logo=almalinux)](https://almalinux.org/)
  [![Plesk Compatible](https://img.shields.io/badge/Plesk-Uyumlu-green?style=flat-square&logo=plesk)](https://www.plesk.com/)
  [![Bash](https://img.shields.io/badge/Language-Bash-4EAA25?style=flat-square&logo=gnu-bash)](https://www.gnu.org/software/bash/)
</div>

<br/>
<img width="1377" height="569" alt="image" src="https://github.com/user-attachments/assets/ce92fb60-4a2d-41ee-ae97-334e3b131a6d" />

Standart OpenVPN kurulum betiklerinin **Plesk Panel** sunucularında yarattığı güvenlik duvarı (firewall) çakışmalarını ve internet erişim kopmalarını önlemek amacıyla baştan aşağı yeniden yazılmış, son derece güvenli ve profesyonel bir OpenVPN kurulum aracıdır.

Canlı web sitelerinizin barındığı (production) sunucularda kendi kişisel VPN'inizi barındırmak istiyor ancak "sitelerime zarar gelir mi?" endişesi taşıyorsanız, bu betik tam size göre.




## ✨ Öne Çıkan Özellikler

- 🌍 **Çoklu Dil Desteği (i18n):** Kurulum sihirbazı global kullanım için tasarlanmıştır. İlk açılışta **Türkçe, İngilizce ve İspanyolca** dillerinden birini seçmenize olanak tanır.
- 🛡️ **Plesk & Web Sunucusu Dostu:** Standart betikler `firewalld` servisini tamamen kapatıp Plesk'in mevcut Fail2Ban ve Docker kural yapılarını bozar. Bu betik ise mevcut güvenlik duvarınızı (Firewalld veya IPTables) tespit eder ve ona saygı duyarak sadece gereken ufak eklemeleri yapar.
- 🌐 **Dinamik Ağ Arabirimi (NIC) Tespiti:** Sunucunuzun dışa bakan ağ arayüzünü (`eth0`, `ens192`, `venet0` vb.) otomatik bulur. VPN'e bağlandığınızda "internete çıkamama" sorununu ortadan kaldırır.
- 🎯 **Akıllı IP Algılama:** NAT arkasındaki sunucularda veya sanal IP karmaşasında kaybolmamak için, gerçek dış IP'nizi global IP servisleri üzerinden doğrular.
- 🎨 **Modern ve Temiz Arayüz:** Terminali gereksiz loglarla doldurmayan, renkli, yönlendirici ve göze hitap eden (ASCII sanatı barındıran) profesyonel bir kurulum sihirbazına sahiptir.
- 🔒 **Yüksek Şifreleme Standartları:** Modern güvenlik için varsayılan olarak `AES-256-GCM`, `TLS 1.2+` ve `SHA256` şifrelemelerini kullanır.

## 📋 Sistem Gereksinimleri

- **İşletim Sistemi:** AlmaLinux 8 veya AlmaLinux 9 (RHEL tabanlı sistemlerle uyumludur)
- **Yetki:** `root` yetkisi
- **Bağımlılıklar:** Kurulum esnasında gerekli paketler (epel-release, openvpn, easy-rsa vb.) otomatik yüklenir.

## 🚀 Kurulum & Kullanım

Sunucunuza SSH üzerinden `root` yetkisiyle giriş yaptıktan sonra aşağıdaki adımları izleyin:

```bash
# 1. Dosyayı sunucuya indirin
wget https://raw.githubusercontent.com/seyitahmettanriver/openvpn-install/main/openvpn-install.sh -O openvpn-install.sh

# 2. Çalıştırma izni verin
chmod +x openvpn-install.sh

# 3. Betiği çalıştırın
./openvpn-install.sh
```

Kurulum sihirbazı size şu basit soruları soracaktır:
1. Dış IP Doğrulaması (Otomatik bulur, onaylarsınız)
2. Protokol Seçimi (Önerilen: `UDP`)
3. Port Numarası (Önerilen: `1194`)
4. DNS Seçimi (Örn: `Sistem DNS`, `Google`, `Cloudflare` vb.)
5. Şifreleme Tipi (Önerilen: `AES-256-GCM`)
6. İlk VPN kullanıcısı için bir isim (Örn: `kullanici1`)

Kurulum bittiğinde, seçtiğiniz kullanıcı adıyla (örn. `kullanici1.ovpn`) `/root/` dizininde bir dosya oluşacaktır. Bu dosyayı bilgisayarınıza/telefonunuza indirerek **OpenVPN Connect** uygulamasıyla hemen bağlanabilirsiniz.

## ⚙️ Yönetim Paneli

Betiği bir kez kurduktan sonra tekrar çalıştırdığınızda sizi **Yönetim Paneli** karşılar:

```bash
./openvpn-install.sh
```

**Menü Seçenekleri:**
1. 👤 **Yeni Kullanıcı (Client) Ekle:** Farklı cihazlar veya arkadaşlarınız için yeni `.ovpn` profilleri oluşturun.
2. 🚫 **Kullanıcı İptal Et (Revoke):** Kaybettiğiniz bir cihazın veya erişimini kesmek istediğiniz birinin sertifikasını geçersiz kılın.
3. 🗑️ **OpenVPN'i Sistemden Tamamen Kaldır:** Tek tuşla OpenVPN'i ve tüm ayarlarını (firewall kuralları dahil) sunucudan iz bırakmadan silin.
4. 🚪 **Çıkış**

## ⚠️ Güvenlik ve Uyumluluk Notu

Bu araç mevcut SSL/TLS sertifikalarınızla (Let's Encrypt vs.) çakışmaz. Sitelerin kullandığı 80/443 portlarından tamamen bağımsız, ayrı bir tünel portundan çalışır. Canlı (production) sunucularda dahi web servislerinizi kesintiye uğratmaz.

---
**Lisans:** MIT License - Geliştirmeye ve özelleştirmeye açıktır.
