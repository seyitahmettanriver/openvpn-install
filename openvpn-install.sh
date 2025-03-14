#!/bin/bash
#
# Görsel ve Kullanıcı Dostu OpenVPN Kurulum Betiği
# AlmaLinux 8.10 ve Plesk Panel için optimize edilmiştir
#

# Renk Kodları
RED='\033[1;31m'          # Parlak Kırmızı
GREEN='\033[1;32m'        # Parlak Yeşil
YELLOW='\033[1;33m'       # Parlak Sarı
BLUE='\033[1;34m'         # Parlak Mavi
PURPLE='\033[1;35m'       # Parlak Mor
CYAN='\033[1;36m'         # Parlak Cyan
WHITE='\033[1;37m'        # Parlak Beyaz
ORANGE='\033[38;5;208m'   # Turuncu
NC='\033[0m'              # Renk Sıfırlama

# Logo ve Banner
print_banner() {
    clear
    echo -e "${CYAN}"
    echo "╔═══════════════════════════════════════════╗"
    echo -e "║${WHITE}           OpenVPN Kurulum Aracı           ${CYAN}║"
    echo -e "║${ORANGE}         AlmaLinux 8.10 + Plesk           ${CYAN}║"
    echo "╚═══════════════════════════════════════════╝"
    echo -e "${NC}"
    sleep 1
}

# Mesaj Fonksiyonları
info() {
    echo -e "${CYAN}[${WHITE}BİLGİ${CYAN}]${NC} $1"
    sleep 0.5
}

success() {
    echo -e "${GREEN}[${WHITE}BAŞARILI${GREEN}]${NC} $1"
    sleep 0.5
}

warning() {
    echo -e "${ORANGE}[${WHITE}UYARI${ORANGE}]${NC} $1"
    sleep 0.5
}

error() {
    echo -e "${RED}[${WHITE}HATA${RED}]${NC} $1"
    sleep 1
}

# Yükleme Kontrolü
check_root() {
    if [[ "$EUID" -ne 0 ]]; then
        error "Bu betik root yetkileri gerektirir."
        exit 1
    fi
}

check_os() {
    if ! grep -q "AlmaLinux release 8" /etc/redhat-release; then
        error "Bu betik AlmaLinux 8.x sistemler için tasarlanmıştır."
        exit 1
    fi
}

check_plesk() {
    if ! command -v plesk &> /dev/null; then
        error "Plesk Panel sistemde bulunamadı."
        exit 1
    fi
}

# Bağımlılıkları Yükleme
install_dependencies() {
    info "Gerekli paketler yükleniyor..."
    {
        dnf install -y epel-release
        dnf install -y openvpn openssl ca-certificates tar wget curl iptables-services
        # firewalld'yi kaldır ve iptables'i etkinleştir
        systemctl disable --now firewalld
        systemctl mask firewalld
        systemctl enable --now iptables
    } &> /dev/null
    success "Paketler başarıyla yüklendi."
}

# Firewall Yapılandırması (iptables)
configure_firewall() {
    local port=$1
    local protocol=$2
    
    info "IPTables yapılandırılıyor..."
    {
        # Mevcut kuralları yedekle
        iptables-save > /root/iptables-backup-$(date +%Y%m%d-%H%M%S)
        
        # NAT ayarları (mevcut kuralları koruyarak)
        iptables -t nat -C POSTROUTING -s 10.8.0.0/24 ! -d 10.8.0.0/24 -j MASQUERADE &>/dev/null || \
        iptables -t nat -A POSTROUTING -s 10.8.0.0/24 ! -d 10.8.0.0/24 -j MASQUERADE
        
        # OpenVPN kurallarını ekle (eğer yoksa)
        iptables -C INPUT -i tun+ -j ACCEPT &>/dev/null || \
        iptables -A INPUT -i tun+ -j ACCEPT
        
        iptables -C FORWARD -i tun+ -j ACCEPT &>/dev/null || \
        iptables -A FORWARD -i tun+ -j ACCEPT
        
        iptables -C INPUT -i eth0 -p $protocol --dport $port -j ACCEPT &>/dev/null || \
        iptables -A INPUT -i eth0 -p $protocol --dport $port -j ACCEPT
        
        iptables -C FORWARD -i tun+ -o eth0 -j ACCEPT &>/dev/null || \
        iptables -A FORWARD -i tun+ -o eth0 -j ACCEPT
        
        iptables -C FORWARD -i eth0 -o tun+ -j ACCEPT &>/dev/null || \
        iptables -A FORWARD -i eth0 -o tun+ -j ACCEPT
        
        # Kuralları kaydet
        service iptables save
    } &> /dev/null
    success "IPTables başarıyla yapılandırıldı."
}

# Kaldırma işlemi için firewall temizleme
cleanup_firewall() {
    local port=$1
    local protocol=$2
    
    info "IPTables kuralları kaldırılıyor..."
    {
        # Sadece OpenVPN kurallarını kaldır
        iptables -t nat -D POSTROUTING -s 10.8.0.0/24 ! -d 10.8.0.0/24 -j MASQUERADE &>/dev/null
        iptables -D INPUT -i tun+ -j ACCEPT &>/dev/null
        iptables -D FORWARD -i tun+ -j ACCEPT &>/dev/null
        iptables -D INPUT -i eth0 -p $protocol --dport $port -j ACCEPT &>/dev/null
        iptables -D FORWARD -i tun+ -o eth0 -j ACCEPT &>/dev/null
        iptables -D FORWARD -i eth0 -o tun+ -j ACCEPT &>/dev/null
        
        # Kuralları kaydet
        service iptables save
    } &> /dev/null
    success "OpenVPN IPTables kuralları kaldırıldı."
}

# Client Yapılandırması Oluşturma
generate_client_config() {
    local client=$1
    local ip=$2
    local port=$3
    local protocol=$4
    
    info "Client sertifikası oluşturuluyor: $client"
    cd /etc/openvpn/easy-rsa/
    ./easyrsa --batch --days=3650 build-client-full "$client" nopass
    
    info "Client yapılandırması oluşturuluyor..."
    {
        cat /etc/openvpn/client-common.txt
        echo "<ca>"
        cat /etc/openvpn/easy-rsa/pki/ca.crt
        echo "</ca>"
        echo "<cert>"
        sed -ne '/BEGIN CERTIFICATE/,$ p' /etc/openvpn/easy-rsa/pki/issued/"$client".crt
        echo "</cert>"
        echo "<key>"
        cat /etc/openvpn/easy-rsa/pki/private/"$client".key
        echo "</key>"
    } > ~/"$client".ovpn
    
    success "Client yapılandırması oluşturuldu: ~/$client.ovpn"
    
    # Dosya içeriğini kontrol et
    if [ ! -s ~/"$client".ovpn ]; then
        error "Client yapılandırma dosyası boş oluşturuldu!"
        info "Dosya içeriği kontrol ediliyor..."
        ls -l /etc/openvpn/easy-rsa/pki/{ca.crt,issued/"$client".crt,private/"$client".key}
    fi
}

# Ana Kurulum Fonksiyonu
main_installation() {
    print_banner
    
    # Sistem Kontrolleri
    info "Sistem kontrolleri yapılıyor..."
    check_root
    check_os
    check_plesk
    success "Sistem kontrolleri tamamlandı."
    
    # Kurulu olup olmadığını kontrol et
    if [[ ! -e /etc/openvpn/server.conf ]]; then
        # Yeni Kurulum
        info "Yeni OpenVPN kurulumu başlatılıyor..."
        
        # IP Adresi Seçimi
        info "IP adresi belirleniyor..."
        if [[ $(ip -4 addr | grep inet | grep -vEc '127(\.[0-9]{1,3}){3}') -eq 1 ]]; then
            ip=$(ip -4 addr | grep inet | grep -vE '127(\.[0-9]{1,3}){3}' | cut -d '/' -f 1 | grep -oE '[0-9]{1,3}(\.[0-9]{1,3}){3}')
        else
            echo
            warning "Birden fazla IP adresi tespit edildi."
            echo
            number_of_ip=$(ip -4 addr | grep inet | grep -vEc '127(\.[0-9]{1,3}){3}')
            echo -e "${CYAN}Kullanılacak IPv4 adresini seçin:${NC}"
            ip -4 addr | grep inet | grep -vE '127(\.[0-9]{1,3}){3}' | cut -d '/' -f 1 | grep -oE '[0-9]{1,3}(\.[0-9]{1,3}){3}' | nl -s ') '
            read -p "IP numarası [1]: " ip_number
            until [[ -z "$ip_number" || "$ip_number" =~ ^[0-9]+$ && "$ip_number" -le "$number_of_ip" ]]; do
                error "Geçersiz seçim."
                read -p "IP numarası [1]: " ip_number
            done
            [[ -z "$ip_number" ]] && ip_number="1"
            ip=$(ip -4 addr | grep inet | grep -vE '127(\.[0-9]{1,3}){3}' | cut -d '/' -f 1 | grep -oE '[0-9]{1,3}(\.[0-9]{1,3}){3}' | sed -n "$ip_number"p)
        fi
        success "IP adresi belirlendi: $ip"

        # Protokol Seçimi
        echo
        info "OpenVPN protokolü seçin:"
        echo "   1) UDP (önerilen)"
        echo "   2) TCP"
        read -p "Protokol [1]: " protocol
        until [[ -z "$protocol" || "$protocol" =~ ^[12]$ ]]; do
            error "Geçersiz seçim."
            read -p "Protokol [1]: " protocol
        done
        case "$protocol" in
            1|"") protocol=udp ;;
            2) protocol=tcp ;;
        esac
        success "Protokol seçildi: $protocol"

        # Port Seçimi
        echo
        info "OpenVPN port numarası girin:"
        read -p "Port [1194]: " port
        until [[ -z "$port" || "$port" =~ ^[0-9]+$ && "$port" -le 65535 ]]; do
            error "Geçersiz port numarası."
            read -p "Port [1194]: " port
        done
        [[ -z "$port" ]] && port="1194"
        success "Port seçildi: $port"

        # DNS Seçimi
        echo
        info "DNS sunucusu seçin:"
        echo -e "${WHITE}   1)${CYAN} Sistem DNS${NC}"
        echo -e "${WHITE}   2)${CYAN} Google DNS${NC}"
        echo -e "${WHITE}   3)${CYAN} Cloudflare DNS${NC}"
        echo -e "${WHITE}   4)${CYAN} OpenDNS${NC}"
        echo -e "${WHITE}   5)${CYAN} Quad9${NC}"
        echo -e "${WHITE}   6)${CYAN} AdGuard DNS${NC}"
        read -p "DNS [1]: " dns
        until [[ -z "$dns" || "$dns" =~ ^[1-6]$ ]]; do
            error "Geçersiz seçim."
            read -p "DNS [1]: " dns
        done
        success "DNS seçildi."

        # DNS ayarlarını yapılandır
        case "$dns" in
            1|"") # Sistem DNS - Hiçbir DNS push yapma
                dns1=""
                dns2=""
                ;;
            2) # Google DNS
                dns1="8.8.8.8"
                dns2="8.8.4.4"
                ;;
            3) # Cloudflare
                dns1="1.1.1.1"
                dns2="1.0.0.1"
                ;;
            4) # OpenDNS
                dns1="208.67.222.222"
                dns2="208.67.220.220"
                ;;
            5) # Quad9
                dns1="9.9.9.9"
                dns2="149.112.112.112"
                ;;
            6) # AdGuard DNS
                dns1="94.140.14.14"
                dns2="94.140.15.15"
                ;;
        esac

        # Şifreleme Seçimi
        echo
        info "Şifreleme algoritması seçin:"
        echo -e "${WHITE}   1)${CYAN} AES-256-GCM (önerilen)${NC}"
        echo -e "${WHITE}   2)${CYAN} AES-128-GCM${NC}"
        echo -e "${WHITE}   3)${CYAN} CHACHA20-POLY1305${NC}"
        read -p "Şifreleme [1]: " cipher_choice
        until [[ -z "$cipher_choice" || "$cipher_choice" =~ ^[1-3]$ ]]; do
            error "Geçersiz seçim."
            read -p "Şifreleme [1]: " cipher_choice
        done
        case "$cipher_choice" in
            1|"") cipher="AES-256-GCM" ;;
            2) cipher="AES-128-GCM" ;;
            3) cipher="CHACHA20-POLY1305" ;;
        esac
        success "Şifreleme seçildi: $cipher"

        # Maksimum Client Sayısı
        echo
        info "Maksimum eşzamanlı client sayısını belirleyin:"
        read -p "Maksimum client [10]: " max_clients
        until [[ -z "$max_clients" || "$max_clients" =~ ^[0-9]+$ && "$max_clients" -ge 1 && "$max_clients" -le 100 ]]; do
            error "Geçersiz değer (1-100 arası olmalı)."
            read -p "Maksimum client [10]: " max_clients
        done
        [[ -z "$max_clients" ]] && max_clients="10"
        success "Maksimum client sayısı belirlendi: $max_clients"

        # Client İsmi
        echo
        info "İlk client için isim girin:"
        read -p "İsim [client1]: " unsanitized_client
        client=$(sed 's/[^0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ_-]/_/g' <<< "$unsanitized_client")
        [[ -z "$client" ]] && client="client1"
        success "Client ismi belirlendi: $client"

        # Kurulum Onayı
        echo
        warning "OpenVPN kurulumu başlamaya hazır."
        read -n1 -r -p "Devam etmek için bir tuşa basın..."

        # Kurulum Başlangıcı
        echo
        info "OpenVPN kurulumu başlıyor..."
        install_dependencies

        # OpenVPN Kurulumu
        info "OpenVPN yapılandırılıyor..."
        mkdir -p /etc/openvpn/easy-rsa/
        wget -qO- 'https://github.com/OpenVPN/easy-rsa/releases/download/v3.1.1/EasyRSA-3.1.1.tgz' | tar xz -C /etc/openvpn/easy-rsa/ --strip-components 1

        # Sertifika Oluşturma
        info "SSL sertifikaları oluşturuluyor..."
        cd /etc/openvpn/easy-rsa/
        ./easyrsa --batch init-pki
        ./easyrsa --batch build-ca nopass
        ./easyrsa --batch --days=3650 build-server-full server nopass
        ./easyrsa --batch --days=3650 gen-crl

        # Sertifikaları Taşıma
        cp pki/ca.crt pki/private/ca.key pki/issued/server.crt pki/private/server.key pki/crl.pem /etc/openvpn/
        chown nobody:nobody /etc/openvpn/crl.pem
        chmod o+x /etc/openvpn/

        # IP Forwarding
        echo 'net.ipv4.ip_forward=1' > /etc/sysctl.d/99-openvpn-forward.conf
        echo 'net.ipv4.conf.all.forwarding=1' >> /etc/sysctl.d/99-openvpn-forward.conf
        sysctl -p /etc/sysctl.d/99-openvpn-forward.conf

        # Firewall
        configure_firewall "$port" "$protocol"

        # Server Yapılandırması
        info "Server yapılandırması oluşturuluyor..."
        {
            echo "port $port"
            echo "proto $protocol"
            echo "dev tun"
            echo "ca ca.crt"
            echo "cert server.crt"
            echo "key server.key"
            echo "dh none"
            echo "topology subnet"
            echo "server 10.8.0.0 255.255.255.0"
            
            # IP Yönlendirme
            echo 'push "redirect-gateway def1"'
            echo 'push "route-gateway 10.8.0.1"'
            
            # DNS Ayarları
            if [[ ! -z "$dns1" ]]; then
                echo "push \"dhcp-option DNS $dns1\""
            fi
            if [[ ! -z "$dns2" ]]; then
                echo "push \"dhcp-option DNS $dns2\""
            fi

            # Şifreleme ve Güvenlik
            echo "cipher $cipher"
            echo "auth SHA256"
            echo "tls-version-min 1.2"
            echo "tls-cipher TLS-ECDHE-ECDSA-WITH-AES-256-GCM-SHA384"

            # Performans Ayarları
            echo "fast-io"
            
            # Diğer Ayarlar
            echo "user nobody"
            echo "group nobody"
            echo "persist-key"
            echo "persist-tun"
            echo "verb 3"
            echo "status /var/log/openvpn/openvpn-status.log"
            echo "log-append /var/log/openvpn/openvpn.log"
            echo "duplicate-cn"
            echo "crl-verify crl.pem"
        } > /etc/openvpn/server.conf

        # Log dizini oluştur
        mkdir -p /var/log/openvpn
        
        # Client Yapılandırması
        info "Client yapılandırması oluşturuluyor..."
        {
            echo "client"
            echo "dev tun"
            echo "proto $protocol"
            echo "remote $ip $port"
            echo "resolv-retry infinite"
            echo "nobind"
            echo "persist-key"
            echo "persist-tun"
            echo "remote-cert-tls server"
            echo "cipher $cipher"
            echo "auth SHA256"
            echo "verb 3"
            echo "pull"
        } > /etc/openvpn/client-common.txt

        # İlk Client
        generate_client_config "$client" "$ip" "$port" "$protocol"

        # OpenVPN Servisi
        info "OpenVPN servisi başlatılıyor..."
        systemctl enable openvpn-server@server
        systemctl stop openvpn-server@server
        systemctl start openvpn-server@server
        sleep 3

        # Kurulum Tamamlandı
        echo
        success "OpenVPN kurulumu başarıyla tamamlandı!"
        echo
        info "Client yapılandırma dosyası: ~/$client.ovpn"
        info "Yeni client eklemek için bu betiği tekrar çalıştırın."
        echo
        echo -e "${GREEN}╔═════════════════════════════════════════════════╗${NC}"
        echo -e "${GREEN}║${WHITE}        OpenVPN Kurulumu Tamamlandı!            ${GREEN}║${NC}"
        echo -e "${GREEN}╚═════════════════════════════════════════════════╝${NC}"

        # Servis Durumunu Kontrol Et
        echo
        info "OpenVPN servis durumu kontrol ediliyor..."
        systemctl status openvpn-server@server

    else
        # Mevcut Kurulum Menüsü
        clear
        echo -e "${CYAN}╔═════════════════════════════════════════════════╗${NC}"
        echo -e "${CYAN}║${WHITE}              OpenVPN Yönetim Menüsü             ${CYAN}║${NC}"
        echo -e "${CYAN}╚═════════════════════════════════════════════════╝${NC}"
        echo
        echo -e "${WHITE}1)${CYAN} Yeni client ekle${NC}"
        echo -e "${WHITE}2)${CYAN} Client sertifikası iptal et${NC}"
        echo -e "${WHITE}3)${RED} OpenVPN'i kaldır${NC}"
        echo -e "${WHITE}4)${YELLOW} Çıkış${NC}"
        echo
        read -p "Seçiminiz: " option
        until [[ "$option" =~ ^[1-4]$ ]]; do
            error "Geçersiz seçim."
            read -p "Seçiminiz: " option
        done

        case "$option" in
            1)
                echo
                info "Yeni client için isim girin:"
                read -p "İsim: " unsanitized_client
                client=$(sed 's/[^0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ_-]/_/g' <<< "$unsanitized_client")
                while [[ -z "$client" || -e /etc/openvpn/easy-rsa/pki/issued/"$client".crt ]]; do
                    error "Geçersiz isim veya bu isimde bir client zaten var."
                    read -p "İsim: " unsanitized_client
                    client=$(sed 's/[^0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ_-]/_/g' <<< "$unsanitized_client")
                done
                cd /etc/openvpn/easy-rsa/
                port=$(grep '^port ' /etc/openvpn/server.conf | cut -d " " -f 2)
                protocol=$(grep '^proto ' /etc/openvpn/server.conf | cut -d " " -f 2)
                ip=$(grep '^remote ' /etc/openvpn/client-common.txt | cut -d " " -f 2)
                generate_client_config "$client" "$ip" "$port" "$protocol"
                ;;
            2)
                number_of_clients=$(tail -n +2 /etc/openvpn/easy-rsa/pki/index.txt | grep -c "^V")
                if [[ "$number_of_clients" = 0 ]]; then
                    error "Hiç client bulunmuyor!"
                    exit 1
                fi
                echo
                info "İptal edilecek client'ı seçin:"
                tail -n +2 /etc/openvpn/easy-rsa/pki/index.txt | grep "^V" | cut -d '=' -f 2 | nl -s ') '
                read -p "Client numarası: " client_number
                until [[ "$client_number" =~ ^[0-9]+$ && "$client_number" -le "$number_of_clients" ]]; do
                    error "Geçersiz seçim."
                    read -p "Client numarası: " client_number
                done
                client=$(tail -n +2 /etc/openvpn/easy-rsa/pki/index.txt | grep "^V" | cut -d '=' -f 2 | sed -n "$client_number"p)
                echo
                read -p "$client sertifikası iptal edilsin mi? [e/H]: " revoke
                until [[ "$revoke" =~ ^[eEhH]*$ ]]; do
                    error "Geçersiz seçim."
                    read -p "$client sertifikası iptal edilsin mi? [e/H]: " revoke
                done
                if [[ "$revoke" =~ ^[eE]$ ]]; then
                    cd /etc/openvpn/easy-rsa/
                    ./easyrsa --batch revoke "$client"
                    ./easyrsa --batch --days=3650 gen-crl
                    rm -f /etc/openvpn/crl.pem
                    cp /etc/openvpn/easy-rsa/pki/crl.pem /etc/openvpn/crl.pem
                    chown nobody:nobody /etc/openvpn/crl.pem
                    success "$client sertifikası iptal edildi!"
                else
                    warning "İptal işlemi durduruldu."
                fi
                ;;
            3)
                echo
                read -p "OpenVPN kaldırılsın mı? [e/H]: " remove
                until [[ "$remove" =~ ^[eEhH]*$ ]]; do
                    error "Geçersiz seçim."
                    read -p "OpenVPN kaldırılsın mı? [e/H]: " remove
                done
                if [[ "$remove" =~ ^[eE]$ ]]; then
                    # IP adresini al
                    ip=$(ip -4 addr | grep inet | grep -vE '127(\.[0-9]{1,3}){3}' | cut -d '/' -f 1 | grep -oE '[0-9]{1,3}(\.[0-9]{1,3}){3}' | head -n 1)
                    
                    # Port ve protokolü al
                    port=$(grep '^port ' /etc/openvpn/server.conf | cut -d " " -f 2)
                    protocol=$(grep '^proto ' /etc/openvpn/server.conf | cut -d " " -f 2)
                    
                    # OpenVPN kurallarını temizle
                    cleanup_firewall "$port" "$protocol"
                    
                    info "OpenVPN servisi durduruluyor..."
                    systemctl stop openvpn-server@server
                    systemctl disable openvpn-server@server
                    
                    info "OpenVPN dosyaları siliniyor..."
                    rm -rf /etc/openvpn/*
                    rm -f /etc/sysctl.d/99-openvpn-forward.conf
                    
                    info "OpenVPN paketi kaldırılıyor..."
                    dnf remove -y openvpn &> /dev/null
                    
                    success "OpenVPN başarıyla kaldırıldı!"
                else
                    warning "Kaldırma işlemi iptal edildi."
                fi
                ;;
            4)
                info "Programdan çıkılıyor..."
                exit 0
                ;;
        esac
    fi
}

# Betiği Çalıştır
main_installation 
