#!/bin/bash
#
# Görsel ve Kullanıcı Dostu OpenVPN Kurulum Betiği
# AlmaLinux 8.10 ve Plesk Panel için optimize edilmiştir
#

# Renk Kodları
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Logo ve Banner
print_banner() {
    clear
    echo -e "${BLUE}"
    echo "╔═══════════════════════════════════════════╗"
    echo "║           OpenVPN Kurulum Aracı           ║"
    echo "║         AlmaLinux 8.10 + Plesk           ║"
    echo "╚═══════════════════════════════════════════╝"
    echo -e "${NC}"
    sleep 1
}

# Mesaj Fonksiyonları
info() {
    echo -e "${BLUE}[BİLGİ]${NC} $1"
    sleep 0.5
}

success() {
    echo -e "${GREEN}[BAŞARILI]${NC} $1"
    sleep 0.5
}

warning() {
    echo -e "${YELLOW}[UYARI]${NC} $1"
    sleep 0.5
}

error() {
    echo -e "${RED}[HATA]${NC} $1"
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
        # NAT ayarları
        iptables -t nat -A POSTROUTING -s 10.8.0.0/24 ! -d 10.8.0.0/24 -j SNAT --to "$ip"
        
        # Port ve protokol kuralları
        iptables -A INPUT -p "$protocol" --dport "$port" -j ACCEPT
        iptables -A INPUT -i tun+ -j ACCEPT
        iptables -A FORWARD -i tun+ -j ACCEPT
        iptables -A FORWARD -i tun+ -o eth0 -m state --state RELATED,ESTABLISHED -j ACCEPT
        iptables -A FORWARD -i eth0 -o tun+ -m state --state RELATED,ESTABLISHED -j ACCEPT
        
        # Kuralları kaydet
        service iptables save
    } &> /dev/null
    success "IPTables başarıyla yapılandırıldı."
}

# Client Yapılandırması Oluşturma
generate_client_config() {
    local client=$1
    local ip=$2
    local port=$3
    local protocol=$4
    
    info "Client sertifikası oluşturuluyor: $client"
    cd /etc/openvpn/server/easy-rsa/
    ./easyrsa --batch --days=3650 build-client-full "$client" nopass
    
    info "Client yapılandırması oluşturuluyor..."
    {
        cat /etc/openvpn/server/client-common.txt
        echo "<ca>"
        cat /etc/openvpn/server/easy-rsa/pki/ca.crt
        echo "</ca>"
        echo "<cert>"
        sed -ne '/BEGIN CERTIFICATE/,$ p' /etc/openvpn/server/easy-rsa/pki/issued/"$client".crt
        echo "</cert>"
        echo "<key>"
        cat /etc/openvpn/server/easy-rsa/pki/private/"$client".key
        echo "</key>"
    } > ~/"$client".ovpn
    
    success "Client yapılandırması oluşturuldu: ~/$client.ovpn"
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
    
    if [[ ! -e /etc/openvpn/server/server.conf ]]; then
        # IP Adresi Seçimi
        info "IP adresi belirleniyor..."
        if [[ $(ip -4 addr | grep inet | grep -vEc '127(\.[0-9]{1,3}){3}') -eq 1 ]]; then
            ip=$(ip -4 addr | grep inet | grep -vE '127(\.[0-9]{1,3}){3}' | cut -d '/' -f 1 | grep -oE '[0-9]{1,3}(\.[0-9]{1,3}){3}')
        else
            echo
            warning "Birden fazla IP adresi tespit edildi."
            echo
            number_of_ip=$(ip -4 addr | grep inet | grep -vEc '127(\.[0-9]{1,3}){3}')
            echo -e "${BLUE}Kullanılacak IPv4 adresini seçin:${NC}"
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
        echo "   1) Sistem DNS"
        echo "   2) Google DNS"
        echo "   3) Cloudflare DNS"
        echo "   4) OpenDNS"
        echo "   5) Quad9"
        echo "   6) AdGuard DNS"
        read -p "DNS [1]: " dns
        until [[ -z "$dns" || "$dns" =~ ^[1-6]$ ]]; do
            error "Geçersiz seçim."
            read -p "DNS [1]: " dns
        done
        success "DNS seçildi."

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
            echo 'push "redirect-gateway def1 bypass-dhcp"'
            
            # DNS Yapılandırması
            case "$dns" in
                1|"")
                    if grep '^nameserver' "/etc/resolv.conf" | grep -qv '127.0.0.53'; then
                        resolv_conf="/etc/resolv.conf"
                    else
                        resolv_conf="/run/systemd/resolve/resolv.conf"
                    fi
                    grep -v '^#\|^;' "$resolv_conf" | grep '^nameserver' | grep -v '127.0.0.53' | grep -oE '[0-9]{1,3}(\.[0-9]{1,3}){3}' | while read line; do
                        echo "push \"dhcp-option DNS $line\""
                    done
                    ;;
                2)
                    echo 'push "dhcp-option DNS 8.8.8.8"'
                    echo 'push "dhcp-option DNS 8.8.4.4"'
                    ;;
                3)
                    echo 'push "dhcp-option DNS 1.1.1.1"'
                    echo 'push "dhcp-option DNS 1.0.0.1"'
                    ;;
                4)
                    echo 'push "dhcp-option DNS 208.67.222.222"'
                    echo 'push "dhcp-option DNS 208.67.220.220"'
                    ;;
                5)
                    echo 'push "dhcp-option DNS 9.9.9.9"'
                    echo 'push "dhcp-option DNS 149.112.112.112"'
                    ;;
                6)
                    echo 'push "dhcp-option DNS 94.140.14.14"'
                    echo 'push "dhcp-option DNS 94.140.15.15"'
                    ;;
            esac

            echo "duplicate-cn"
            echo "keepalive 10 120"
            echo "user nobody"
            echo "group nobody"
            echo "persist-key"
            echo "persist-tun"
            echo "verb 3"
            echo "crl-verify crl.pem"
            echo "cipher AES-256-GCM"
            echo "auth SHA256"
            echo "tls-version-min 1.2"
            echo "tls-cipher TLS-ECDHE-ECDSA-WITH-AES-256-GCM-SHA384"
        } > /etc/openvpn/server.conf

        # IP Forwarding
        echo 'net.ipv4.ip_forward=1' > /etc/sysctl.d/99-openvpn-forward.conf
        sysctl -p /etc/sysctl.d/99-openvpn-forward.conf

        # Firewall
        configure_firewall "$port" "$protocol"

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
            echo "cipher AES-256-GCM"
            echo "auth SHA256"
            echo "verb 3"
        } > /etc/openvpn/client-common.txt

        # OpenVPN Servisi
        info "OpenVPN servisi başlatılıyor..."
        systemctl enable openvpn@server
        systemctl start openvpn@server
        sleep 2
        systemctl status openvpn@server

        # İlk Client
        generate_client_config "$client" "$ip" "$port" "$protocol"

        # Kurulum Tamamlandı
        echo
        success "OpenVPN kurulumu başarıyla tamamlandı!"
        echo
        info "Client yapılandırma dosyası: ~/$client.ovpn"
        info "Yeni client eklemek için bu betiği tekrar çalıştırın."
        echo
        echo -e "${GREEN}╔═══════════════════════════════════════════╗${NC}"
        echo -e "${GREEN}║        Kurulum Başarıyla Tamamlandı       ║${NC}"
        echo -e "${GREEN}╚═══════════════════════════════════════════╝${NC}"

    else
        # Mevcut Kurulum Menüsü
        clear
        echo -e "${BLUE}OpenVPN Yönetim Menüsü${NC}"
        echo
        echo "1) Yeni client ekle"
        echo "2) Client sertifikası iptal et"
        echo "3) OpenVPN'i kaldır"
        echo "4) Çıkış"
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
                while [[ -z "$client" || -e /etc/openvpn/server/easy-rsa/pki/issued/"$client".crt ]]; do
                    error "Geçersiz isim veya bu isimde bir client zaten var."
                    read -p "İsim: " unsanitized_client
                    client=$(sed 's/[^0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ_-]/_/g' <<< "$unsanitized_client")
                done
                cd /etc/openvpn/server/easy-rsa/
                port=$(grep '^port ' /etc/openvpn/server/server.conf | cut -d " " -f 2)
                protocol=$(grep '^proto ' /etc/openvpn/server/server.conf | cut -d " " -f 2)
                ip=$(grep '^remote ' /etc/openvpn/server/client-common.txt | cut -d " " -f 2)
                generate_client_config "$client" "$ip" "$port" "$protocol"
                ;;
            2)
                number_of_clients=$(tail -n +2 /etc/openvpn/server/easy-rsa/pki/index.txt | grep -c "^V")
                if [[ "$number_of_clients" = 0 ]]; then
                    error "Hiç client bulunmuyor!"
                    exit 1
                fi
                echo
                info "İptal edilecek client'ı seçin:"
                tail -n +2 /etc/openvpn/server/easy-rsa/pki/index.txt | grep "^V" | cut -d '=' -f 2 | nl -s ') '
                read -p "Client numarası: " client_number
                until [[ "$client_number" =~ ^[0-9]+$ && "$client_number" -le "$number_of_clients" ]]; do
                    error "Geçersiz seçim."
                    read -p "Client numarası: " client_number
                done
                client=$(tail -n +2 /etc/openvpn/server/easy-rsa/pki/index.txt | grep "^V" | cut -d '=' -f 2 | sed -n "$client_number"p)
                echo
                read -p "$client sertifikası iptal edilsin mi? [e/H]: " revoke
                until [[ "$revoke" =~ ^[eEhH]*$ ]]; do
                    error "Geçersiz seçim."
                    read -p "$client sertifikası iptal edilsin mi? [e/H]: " revoke
                done
                if [[ "$revoke" =~ ^[eE]$ ]]; then
                    cd /etc/openvpn/server/easy-rsa/
                    ./easyrsa --batch revoke "$client"
                    ./easyrsa --batch --days=3650 gen-crl
                    rm -f /etc/openvpn/server/crl.pem
                    cp /etc/openvpn/server/easy-rsa/pki/crl.pem /etc/openvpn/server/crl.pem
                    chown nobody:nobody /etc/openvpn/server/crl.pem
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
                    port=$(grep '^port ' /etc/openvpn/server.conf | cut -d " " -f 2)
                    protocol=$(grep '^proto ' /etc/openvpn/server.conf | cut -d " " -f 2)
                    
                    info "IPTables kuralları kaldırılıyor..."
                    {
                        iptables -t nat -D POSTROUTING -s 10.8.0.0/24 ! -d 10.8.0.0/24 -j SNAT --to "$ip"
                        iptables -D INPUT -p "$protocol" --dport "$port" -j ACCEPT
                        iptables -D INPUT -i tun+ -j ACCEPT
                        iptables -D FORWARD -i tun+ -j ACCEPT
                        iptables -D FORWARD -i tun+ -o eth0 -m state --state RELATED,ESTABLISHED -j ACCEPT
                        iptables -D FORWARD -i eth0 -o tun+ -m state --state RELATED,ESTABLISHED -j ACCEPT
                        service iptables save
                    } &> /dev/null
                    
                    info "OpenVPN servisi durduruluyor..."
                    systemctl disable --now openvpn@server
                    
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
