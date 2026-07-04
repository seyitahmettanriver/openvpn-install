#!/bin/bash
#
# Gelişmiş ve Güvenli OpenVPN Kurulum Betiği / Advanced OpenVPN Install Script
# AlmaLinux 8/9 ve Plesk Panel için optimize edilmiştir / Optimized for AlmaLinux 8/9 & Plesk
#

# Renk Kodları ve UI Ayarları / Color Codes
RED='\033[1;31m'
GREEN='\033[1;32m'
YELLOW='\033[1;33m'
BLUE='\033[1;34m'
PURPLE='\033[1;35m'
CYAN='\033[1;36m'
WHITE='\033[1;37m'
ORANGE='\033[38;5;208m'
NC='\033[0m'
BOLD='\033[1m'

set_language() {
    # Default is Turkish
    MSG_ERR_ROOT="Bu betik root yetkileri gerektirir."
    MSG_WARN_OS="Bu betik AlmaLinux 8/9 için optimize edilmiştir. Farklı bir OS tespit edildi, ancak devam ediliyor..."
    MSG_INFO_PLESK="Plesk Panel tespit edildi. Güvenlik duvarı ayarları Plesk'e zarar vermeyecek şekilde yapılandırılacak."
    MSG_INFO_DEPS="Gerekli paketler yükleniyor (OpenVPN, Easy-RSA, iptables-services)..."
    MSG_OK_DEPS="Paketler başarıyla yüklendi."
    MSG_INFO_FW="Güvenlik Duvarı yapılandırılıyor (Ağ Arabirimi: "
    MSG_INFO_FWD_ACTIVE="Firewalld aktif olarak tespit edildi. Kurallar eklentisi yapılıyor..."
    MSG_OK_FWD="Firewalld başarıyla yapılandırıldı."
    MSG_INFO_IPT_ACTIVE="Firewalld bulunamadı. IPTables kullanılarak yapılandırılıyor..."
    MSG_OK_IPT="IPTables başarıyla yapılandırıldı."
    MSG_INFO_FW_CLEAN="Güvenlik Duvarı kuralları temizleniyor..."
    MSG_OK_FWD_CLEAN="Firewalld OpenVPN kuralları kaldırıldı."
    MSG_OK_IPT_CLEAN="IPTables OpenVPN kuralları kaldırıldı."
    MSG_INFO_CERT="Kullanıcı (Client) sertifikası oluşturuluyor: "
    MSG_INFO_PROF="Kullanıcı profili hazırlanıyor..."
    MSG_OK_PROF="Kullanıcı profili başarıyla oluşturuldu: "
    MSG_INFO_CHECKS="Sistem ön kontrolleri yapılıyor..."
    MSG_INFO_WIZARD="Yeni OpenVPN Kurulum Sihirbazı Başlıyor"
    MSG_PROMPT_IP="Sunucu Dış IP Adresi"
    MSG_PROMPT_PROTO="Protokol Seçin (1: UDP, 2: TCP)"
    MSG_PROMPT_PORT="Port Numarası"
    MSG_PROMPT_DNS="DNS Sunucusu"
    MSG_PROMPT_CIPHER="Şifreleme Algoritması"
    MSG_PROMPT_CLIENT="İlk Kullanıcı (Client) İsmi"
    MSG_WARN_START="Kurulum başlıyor. Bu işlem biraz zaman alabilir."
    MSG_PRESS_KEY="Başlamak için herhangi bir tuşa basın..."
    MSG_INFO_CONF="OpenVPN yapılandırılıyor..."
    MSG_INFO_SSL="SSL Sertifikaları oluşturuluyor (Lütfen bekleyin)..."
    MSG_INFO_NET="Ağ yönlendirmeleri (IP Forwarding) ayarlanıyor..."
    MSG_INFO_SRV="Sunucu ayarları yapılandırılıyor..."
    MSG_INFO_START="OpenVPN servisi başlatılıyor..."
    MSG_OK_DONE="Kurulum Başarıyla Tamamlandı!"
    MSG_OUT_PROF="Kullanıcı Profili :"
    MSG_OUT_NEXT="Yeni kullanıcı eklemek için bu betiği tekrar çalıştırın."
    MSG_MENU_TITLE="OpenVPN Yönetim Paneli"
    MSG_MENU_ADD="Yeni Kullanıcı (Client) Ekle"
    MSG_MENU_REVOKE="Kullanıcı İptal Et (Revoke)"
    MSG_MENU_REMOVE="OpenVPN'i Sistemden Tamamen Kaldır"
    MSG_MENU_EXIT="Çıkış"
    MSG_PROMPT_ACTION="İşlem Seçiniz"
    MSG_PROMPT_NEW_CLIENT="Yeni kullanıcı ismi:"
    MSG_ERR_CLIENT_EXISTS="Geçersiz isim veya bu isimde bir kullanıcı zaten var."
    MSG_ERR_NO_CLIENT="Kayıtlı kullanıcı bulunmuyor!"
    MSG_INFO_CLIENTS="Mevcut Kullanıcılar:"
    MSG_PROMPT_REVOKE_NUM="İptal edilecek kullanıcı numarası:"
    MSG_ERR_INVALID="Geçersiz seçim."
    MSG_PROMPT_SURE_REVOKE="kullanıcısı iptal edilecek. Emin misiniz? [e/H]: "
    MSG_OK_REVOKE="kullanıcısı başarıyla iptal edildi!"
    MSG_WARN_REMOVE="Bu işlem OpenVPN'i tamamen kaldıracak ve tüm ayarları silecektir!"
    MSG_PROMPT_SURE_REMOVE="Devam etmek istiyor musunuz? [e/H]: "
    MSG_INFO_STOP="Servisler durduruluyor..."
    MSG_INFO_CLEAN="Dosyalar temizleniyor..."
    MSG_INFO_PKG="Paket kaldırılıyor..."
    MSG_OK_REMOVE="OpenVPN sistemden tamamen kaldırıldı!"
    MSG_INFO_EXIT="Çıkış yapılıyor..."
    MSG_OPT_SYS_DNS="Sistem DNS"
    MSG_OPT_REC="Önerilen"
    MSG_YES_REGEX="^[eE]$"
    
    if [[ "$1" == "2" ]]; then
        # English
        MSG_ERR_ROOT="This script requires root privileges."
        MSG_WARN_OS="This script is optimized for AlmaLinux 8/9. A different OS was detected, but continuing..."
        MSG_INFO_PLESK="Plesk Panel detected. Firewall settings will be configured to not disrupt Plesk."
        MSG_INFO_DEPS="Installing required packages (OpenVPN, Easy-RSA, iptables-services)..."
        MSG_OK_DEPS="Packages successfully installed."
        MSG_INFO_FW="Configuring Firewall (Network Interface: "
        MSG_INFO_FWD_ACTIVE="Firewalld detected as active. Adding rules..."
        MSG_OK_FWD="Firewalld successfully configured."
        MSG_INFO_IPT_ACTIVE="Firewalld not found. Configuring using IPTables..."
        MSG_OK_IPT="IPTables successfully configured."
        MSG_INFO_FW_CLEAN="Cleaning Firewall rules..."
        MSG_OK_FWD_CLEAN="Firewalld OpenVPN rules removed."
        MSG_OK_IPT_CLEAN="IPTables OpenVPN rules removed."
        MSG_INFO_CERT="Generating Client certificate: "
        MSG_INFO_PROF="Preparing Client profile..."
        MSG_OK_PROF="Client profile successfully created: "
        MSG_INFO_CHECKS="Performing system pre-checks..."
        MSG_INFO_WIZARD="Starting New OpenVPN Installation Wizard"
        MSG_PROMPT_IP="Server Public IP Address"
        MSG_PROMPT_PROTO="Select Protocol (1: UDP, 2: TCP)"
        MSG_PROMPT_PORT="Port Number"
        MSG_PROMPT_DNS="DNS Server"
        MSG_PROMPT_CIPHER="Encryption Algorithm"
        MSG_PROMPT_CLIENT="First Client Name"
        MSG_WARN_START="Installation is starting. This process may take a while."
        MSG_PRESS_KEY="Press any key to begin..."
        MSG_INFO_CONF="Configuring OpenVPN..."
        MSG_INFO_SSL="Generating SSL Certificates (Please wait)..."
        MSG_INFO_NET="Configuring Network Routing (IP Forwarding)..."
        MSG_INFO_SRV="Configuring Server settings..."
        MSG_INFO_START="Starting OpenVPN service..."
        MSG_OK_DONE="Installation Completed Successfully!"
        MSG_OUT_PROF="Client Profile :"
        MSG_OUT_NEXT="Run this script again to add a new client."
        MSG_MENU_TITLE="OpenVPN Management Panel"
        MSG_MENU_ADD="Add a New Client"
        MSG_MENU_REVOKE="Revoke an Existing Client"
        MSG_MENU_REMOVE="Completely Remove OpenVPN"
        MSG_MENU_EXIT="Exit"
        MSG_PROMPT_ACTION="Select an Action"
        MSG_PROMPT_NEW_CLIENT="New client name:"
        MSG_ERR_CLIENT_EXISTS="Invalid name or a client with this name already exists."
        MSG_ERR_NO_CLIENT="No registered clients found!"
        MSG_INFO_CLIENTS="Existing Clients:"
        MSG_PROMPT_REVOKE_NUM="Enter client number to revoke:"
        MSG_ERR_INVALID="Invalid selection."
        MSG_PROMPT_SURE_REVOKE="will be revoked. Are you sure? [y/N]: "
        MSG_OK_REVOKE="successfully revoked!"
        MSG_WARN_REMOVE="This will completely remove OpenVPN and delete all settings!"
        MSG_PROMPT_SURE_REMOVE="Do you want to continue? [y/N]: "
        MSG_INFO_STOP="Stopping services..."
        MSG_INFO_CLEAN="Cleaning files..."
        MSG_INFO_PKG="Removing packages..."
        MSG_OK_REMOVE="OpenVPN has been completely removed from the system!"
        MSG_INFO_EXIT="Exiting..."
        MSG_OPT_SYS_DNS="System DNS"
        MSG_OPT_REC="Recommended"
        MSG_YES_REGEX="^[yY]$"
    elif [[ "$1" == "3" ]]; then
        # Spanish
        MSG_ERR_ROOT="Este script requiere privilegios de root."
        MSG_WARN_OS="Este script está optimizado para AlmaLinux 8/9. Se detectó un SO diferente, pero se continuará..."
        MSG_INFO_PLESK="Se detectó Plesk Panel. La configuración del firewall se adaptará para no interrumpir Plesk."
        MSG_INFO_DEPS="Instalando paquetes necesarios (OpenVPN, Easy-RSA, iptables-services)..."
        MSG_OK_DEPS="Paquetes instalados correctamente."
        MSG_INFO_FW="Configurando Firewall (Interfaz de red: "
        MSG_INFO_FWD_ACTIVE="Se detectó Firewalld activo. Agregando reglas..."
        MSG_OK_FWD="Firewalld configurado correctamente."
        MSG_INFO_IPT_ACTIVE="No se encontró Firewalld. Configurando con IPTables..."
        MSG_OK_IPT="IPTables configurado correctamente."
        MSG_INFO_FW_CLEAN="Limpiando reglas de Firewall..."
        MSG_OK_FWD_CLEAN="Reglas de OpenVPN eliminadas de Firewalld."
        MSG_OK_IPT_CLEAN="Reglas de OpenVPN eliminadas de IPTables."
        MSG_INFO_CERT="Generando certificado de Cliente: "
        MSG_INFO_PROF="Preparando perfil de Cliente..."
        MSG_OK_PROF="Perfil de cliente creado exitosamente: "
        MSG_INFO_CHECKS="Realizando comprobaciones del sistema..."
        MSG_INFO_WIZARD="Iniciando el Asistente de Instalación de OpenVPN"
        MSG_PROMPT_IP="Dirección IP Pública del Servidor"
        MSG_PROMPT_PROTO="Seleccione Protocolo (1: UDP, 2: TCP)"
        MSG_PROMPT_PORT="Número de Puerto"
        MSG_PROMPT_DNS="Servidor DNS"
        MSG_PROMPT_CIPHER="Algoritmo de Encriptación"
        MSG_PROMPT_CLIENT="Nombre del Primer Cliente"
        MSG_WARN_START="La instalación está comenzando. Este proceso puede tardar un poco."
        MSG_PRESS_KEY="Presione cualquier tecla para comenzar..."
        MSG_INFO_CONF="Configurando OpenVPN..."
        MSG_INFO_SSL="Generando Certificados SSL (Por favor espere)..."
        MSG_INFO_NET="Configurando enrutamiento de red (IP Forwarding)..."
        MSG_INFO_SRV="Configurando ajustes del Servidor..."
        MSG_INFO_START="Iniciando servicio OpenVPN..."
        MSG_OK_DONE="¡Instalación Completada con Éxito!"
        MSG_OUT_PROF="Perfil del Cliente :"
        MSG_OUT_NEXT="Ejecute este script nuevamente para agregar un nuevo cliente."
        MSG_MENU_TITLE="Panel de Gestión de OpenVPN"
        MSG_MENU_ADD="Agregar un Nuevo Cliente"
        MSG_MENU_REVOKE="Revocar un Cliente Existente"
        MSG_MENU_REMOVE="Eliminar Completamente OpenVPN"
        MSG_MENU_EXIT="Salir"
        MSG_PROMPT_ACTION="Seleccione una Acción"
        MSG_PROMPT_NEW_CLIENT="Nombre del nuevo cliente:"
        MSG_ERR_CLIENT_EXISTS="Nombre inválido o ya existe un cliente con este nombre."
        MSG_ERR_NO_CLIENT="¡No se encontraron clientes registrados!"
        MSG_INFO_CLIENTS="Clientes Existentes:"
        MSG_PROMPT_REVOKE_NUM="Ingrese el número de cliente a revocar:"
        MSG_ERR_INVALID="Selección inválida."
        MSG_PROMPT_SURE_REVOKE="será revocado. ¿Está seguro? [s/N]: "
        MSG_OK_REVOKE="revocado con éxito!"
        MSG_WARN_REMOVE="¡Esto eliminará completamente OpenVPN y todos los ajustes!"
        MSG_PROMPT_SURE_REMOVE="¿Desea continuar? [s/N]: "
        MSG_INFO_STOP="Deteniendo servicios..."
        MSG_INFO_CLEAN="Limpiando archivos..."
        MSG_INFO_PKG="Eliminando paquetes..."
        MSG_OK_REMOVE="¡OpenVPN ha sido eliminado completamente del sistema!"
        MSG_INFO_EXIT="Saliendo..."
        MSG_OPT_SYS_DNS="DNS del Sistema"
        MSG_OPT_REC="Recomendado"
        MSG_YES_REGEX="^[sSyY]$"
    fi
}

# Select Language
choose_language() {
    clear
    echo -e "${CYAN}╔════════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${CYAN}║${WHITE}                 Select Language / Dil Seçimi                   ${CYAN}║${NC}"
    echo -e "${CYAN}╚════════════════════════════════════════════════════════════════╝${NC}"
    echo
    echo -e "   ${GREEN}1)${WHITE} Türkçe (Varsayılan)${NC}"
    echo -e "   ${YELLOW}2)${WHITE} English${NC}"
    echo -e "   ${RED}3)${WHITE} Español${NC}"
    echo
    echo -e "${YELLOW} ❯ ${WHITE}Language [1]: ${NC}\c"
    read lang_choice
    [[ -z "$lang_choice" ]] && lang_choice=1
    set_language "$lang_choice"
}

# Logo ve Banner
print_banner() {
    clear
    echo -e "${BLUE}${BOLD}"
    cat << 'EOF'
   ____                    __   ______  _   __ 
  / __ \____  ___  ____   | |  / / __ \/ | / / 
 / / / / __ \/ _ \/ __ \  | | / / /_/ /  |/ /  
/ /_/ / /_/ /  __/ / / /  | |/ / ____/ /|  /   
\____/ .___/\___/_/ /_/   |___/_/   /_/ |_/    
    /_/                                        
EOF
    echo -e "${CYAN}╔════════════════════════════════════════════════════════════════╗"
    echo -e "║${WHITE}                 Gelişmiş OpenVPN Kurulum Aracı                 ${CYAN}║"
    echo -e "║${ORANGE}                AlmaLinux + Plesk Uyumlu Sürüm                  ${CYAN}║"
    echo -e "╚════════════════════════════════════════════════════════════════╝${NC}"
    echo
}

# Mesaj Fonksiyonları
info() { echo -e "${CYAN} ➔ ${WHITE}$1${NC}"; sleep 0.3; }
success() { echo -e "${GREEN} ✔ ${WHITE}$1${NC}"; sleep 0.3; }
warning() { echo -e "${ORANGE} ⚠ ${WHITE}$1${NC}"; sleep 0.3; }
error() { echo -e "${RED} ✖ ${WHITE}$1${NC}"; sleep 1; }
prompt() { echo -e "${YELLOW} ❯ ${WHITE}$1${NC}"; }

# Yükleme Kontrolü
check_root() {
    if [[ "$EUID" -ne 0 ]]; then
        error "$MSG_ERR_ROOT"
        exit 1
    fi
}

check_os() {
    if ! grep -q -E "AlmaLinux release 8|AlmaLinux release 9" /etc/redhat-release 2>/dev/null; then
        warning "$MSG_WARN_OS"
    fi
}

check_plesk() {
    if command -v plesk &> /dev/null; then
        info "$MSG_INFO_PLESK"
    fi
}

get_default_nic() {
    NIC=$(ip -4 route ls | grep default | grep -Po '(?<=dev )(\S+)' | head -1)
    if [[ -z "$NIC" ]]; then
        NIC=$(ip link | awk -F: '$0 !~ "lo|vir|wl|^[^0-9]"{print $2;getline}' | head -n 1 | tr -d ' ')
    fi
    echo "$NIC"
}

# Bağımlılıkları Yükleme
install_dependencies() {
    info "$MSG_INFO_DEPS"
    {
        dnf install -y epel-release
        dnf install -y openvpn openssl ca-certificates tar wget curl iptables-services
    } &> /dev/null
    success "$MSG_OK_DEPS"
}

# Firewall Yapılandırması
configure_firewall() {
    local port=$1
    local protocol=$2
    local nic=$3
    
    info "${MSG_INFO_FW}${nic})..."
    
    # Check if firewalld is active
    if systemctl is-active --quiet firewalld; then
        info "$MSG_INFO_FWD_ACTIVE"
        firewall-cmd --permanent --add-port=${port}/${protocol} &>/dev/null
        firewall-cmd --permanent --add-masquerade &>/dev/null
        firewall-cmd --permanent --zone=trusted --add-interface=tun0 &>/dev/null
        # Bazen firewalld zone kuralları yönlendirmeyi kesebilir, bu yüzden zengin/doğrudan kurallar ekliyoruz:
        firewall-cmd --permanent --direct --add-rule ipv4 nat POSTROUTING 0 -s 10.8.0.0/24 -o $nic -j MASQUERADE &>/dev/null
        firewall-cmd --permanent --direct --add-rule ipv4 filter FORWARD 0 -i tun+ -j ACCEPT &>/dev/null
        firewall-cmd --reload &>/dev/null
        success "$MSG_OK_FWD"
    else
        info "$MSG_INFO_IPT_ACTIVE"
        iptables-save > /root/iptables-backup-$(date +%Y%m%d-%H%M%S)
        
        # -I kullanarak kuralları EN ÜSTE ekliyoruz (Plesk'in DROP kurallarını aşmak için)
        iptables -t nat -C POSTROUTING -s 10.8.0.0/24 -o $nic -j MASQUERADE &>/dev/null || \
        iptables -t nat -I POSTROUTING 1 -s 10.8.0.0/24 -o $nic -j MASQUERADE
        
        iptables -C INPUT -i tun+ -j ACCEPT &>/dev/null || iptables -I INPUT 1 -i tun+ -j ACCEPT
        iptables -C FORWARD -i tun+ -j ACCEPT &>/dev/null || iptables -I FORWARD 1 -i tun+ -j ACCEPT
        iptables -C INPUT -i $nic -p $protocol --dport $port -j ACCEPT &>/dev/null || iptables -I INPUT 1 -i $nic -p $protocol --dport $port -j ACCEPT
        iptables -C FORWARD -i tun+ -o $nic -j ACCEPT &>/dev/null || iptables -I FORWARD 1 -i tun+ -o $nic -j ACCEPT
        iptables -C FORWARD -i $nic -o tun+ -j ACCEPT &>/dev/null || iptables -I FORWARD 1 -i $nic -o tun+ -j ACCEPT
        
        if systemctl is-active --quiet iptables; then
            service iptables save &>/dev/null
        else
            iptables-save > /etc/sysconfig/iptables
        fi
        success "$MSG_OK_IPT"
    fi
}

cleanup_firewall() {
    local port=$1
    local protocol=$2
    local nic=$(get_default_nic)
    
    info "$MSG_INFO_FW_CLEAN"
    
    if systemctl is-active --quiet firewalld; then
        firewall-cmd --permanent --remove-port=${port}/${protocol} &>/dev/null
        firewall-cmd --permanent --remove-masquerade &>/dev/null
        firewall-cmd --permanent --zone=trusted --remove-interface=tun0 &>/dev/null
        firewall-cmd --permanent --direct --remove-rule ipv4 nat POSTROUTING 0 -s 10.8.0.0/24 -o $nic -j MASQUERADE &>/dev/null
        firewall-cmd --permanent --direct --remove-rule ipv4 filter FORWARD 0 -i tun+ -j ACCEPT &>/dev/null
        firewall-cmd --reload &>/dev/null
        success "$MSG_OK_FWD_CLEAN"
    else
        iptables -t nat -D POSTROUTING -s 10.8.0.0/24 -o $nic -j MASQUERADE &>/dev/null
        iptables -D INPUT -i tun+ -j ACCEPT &>/dev/null
        iptables -D FORWARD -i tun+ -j ACCEPT &>/dev/null
        iptables -D INPUT -i $nic -p $protocol --dport $port -j ACCEPT &>/dev/null
        iptables -D FORWARD -i tun+ -o $nic -j ACCEPT &>/dev/null
        iptables -D FORWARD -i $nic -o tun+ -j ACCEPT &>/dev/null
        
        if systemctl is-active --quiet iptables; then
            service iptables save &>/dev/null
        else
            iptables-save > /etc/sysconfig/iptables
        fi
        success "$MSG_OK_IPT_CLEAN"
    fi
}

generate_client_config() {
    local client=$1
    local ip=$2
    local port=$3
    local protocol=$4
    
    info "${MSG_INFO_CERT}$client"
    cd /etc/openvpn/easy-rsa/
    ./easyrsa --batch --days=3650 build-client-full "$client" nopass > /dev/null 2>&1
    
    info "$MSG_INFO_PROF"
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
    
    success "${MSG_OK_PROF}~/$client.ovpn"
}

main_installation() {
    choose_language
    print_banner
    
    info "$MSG_INFO_CHECKS"
    check_root
    check_os
    check_plesk
    echo
    
    if [[ ! -e /etc/openvpn/server.conf ]]; then
        info "$MSG_INFO_WIZARD"
        echo
        
        # IP Adresi
        local ip=$(curl -s https://api.ipify.org || ip -4 addr | grep inet | grep -vE '127(\.[0-9]{1,3}){3}' | cut -d '/' -f 1 | grep -oE '[0-9]{1,3}(\.[0-9]{1,3}){3}' | head -n 1)
        prompt "${MSG_PROMPT_IP} [${ip}]: " 
        read custom_ip
        [[ -n "$custom_ip" ]] && ip="$custom_ip"
        
        # Protokol
        echo
        prompt "${MSG_PROMPT_PROTO} [1]: "
        read protocol
        case "$protocol" in
            2) protocol=tcp ;;
            *) protocol=udp ;;
        esac
        
        # Port
        echo
        prompt "${MSG_PROMPT_PORT} [1194]: "
        read port
        [[ -z "$port" ]] && port="1194"
        
        # DNS
        echo
        echo -e "   ${CYAN}1)${WHITE} ${MSG_OPT_SYS_DNS}${NC}   ${CYAN}2)${WHITE} Google${NC}       ${CYAN}3)${WHITE} Cloudflare${NC}"
        echo -e "   ${CYAN}4)${WHITE} OpenDNS${NC}      ${CYAN}5)${WHITE} Quad9${NC}        ${CYAN}6)${WHITE} AdGuard${NC}"
        prompt "${MSG_PROMPT_DNS} [1]: "
        read dns
        case "$dns" in
            2) dns1="8.8.8.8"; dns2="8.8.4.4" ;;
            3) dns1="1.1.1.1"; dns2="1.0.0.1" ;;
            4) dns1="208.67.222.222"; dns2="208.67.220.220" ;;
            5) dns1="9.9.9.9"; dns2="149.112.112.112" ;;
            6) dns1="94.140.14.14"; dns2="94.140.15.15" ;;
            *) dns1=""; dns2="" ;;
        esac

        # Şifreleme
        echo
        echo -e "   ${CYAN}1)${WHITE} AES-256-GCM (${MSG_OPT_REC})${NC}"
        echo -e "   ${CYAN}2)${WHITE} AES-128-GCM${NC}"
        echo -e "   ${CYAN}3)${WHITE} CHACHA20-POLY1305${NC}"
        prompt "${MSG_PROMPT_CIPHER} [1]: "
        read cipher_choice
        case "$cipher_choice" in
            2) cipher="AES-128-GCM" ;;
            3) cipher="CHACHA20-POLY1305" ;;
            *) cipher="AES-256-GCM" ;;
        esac

        # Client İsmi
        echo
        prompt "${MSG_PROMPT_CLIENT} [client1]: "
        read unsanitized_client
        client=$(sed 's/[^a-zA-Z0-9_-]/_/g' <<< "$unsanitized_client")
        [[ -z "$client" ]] && client="client1"
        
        echo
        warning "$MSG_WARN_START"
        read -n1 -r -p "$MSG_PRESS_KEY"
        echo -e "\n"
        
        install_dependencies
        
        info "$MSG_INFO_CONF"
        mkdir -p /etc/openvpn/easy-rsa/
        wget -qO- 'https://github.com/OpenVPN/easy-rsa/releases/download/v3.1.1/EasyRSA-3.1.1.tgz' | tar xz -C /etc/openvpn/easy-rsa/ --strip-components 1
        
        info "$MSG_INFO_SSL"
        cd /etc/openvpn/easy-rsa/
        ./easyrsa --batch init-pki >/dev/null
        ./easyrsa --batch build-ca nopass >/dev/null
        ./easyrsa --batch --days=3650 build-server-full server nopass >/dev/null
        ./easyrsa --batch --days=3650 gen-crl >/dev/null
        
        cp pki/ca.crt pki/private/ca.key pki/issued/server.crt pki/private/server.key pki/crl.pem /etc/openvpn/
        chown nobody:nobody /etc/openvpn/crl.pem
        chmod o+x /etc/openvpn/
        
        info "$MSG_INFO_NET"
        echo 'net.ipv4.ip_forward=1' > /etc/sysctl.d/99-openvpn-forward.conf
        sysctl -p /etc/sysctl.d/99-openvpn-forward.conf >/dev/null 2>&1
        
        NIC=$(get_default_nic)
        configure_firewall "$port" "$protocol" "$NIC"
        
        info "$MSG_INFO_SRV"
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
            
            if [[ -n "$dns1" ]]; then
                echo "push \"dhcp-option DNS $dns1\""
                echo "push \"dhcp-option DNS $dns2\""
            fi

            echo "cipher $cipher"
            echo "auth SHA256"
            echo "tls-version-min 1.2"
            echo "tls-cipher TLS-ECDHE-ECDSA-WITH-AES-256-GCM-SHA384"
            echo "fast-io"
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
        
        mkdir -p /var/log/openvpn
        
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
        
        generate_client_config "$client" "$ip" "$port" "$protocol"
        
        info "$MSG_INFO_START"
        systemctl enable openvpn-server@server &>/dev/null
        systemctl restart openvpn-server@server
        
        echo
        echo -e "${CYAN}════════════════════════════════════════════════════════════════${NC}"
        success "$MSG_OK_DONE"
        echo -e "${WHITE} ${MSG_OUT_PROF} ${GREEN}~/$client.ovpn${NC}"
        echo -e "${WHITE} ${MSG_OUT_NEXT}${NC}"
        echo -e "${CYAN}════════════════════════════════════════════════════════════════${NC}"

    else
        clear
        echo -e "${CYAN}╔════════════════════════════════════════════════════════════════╗"
        echo -e "║${WHITE}                 ${MSG_MENU_TITLE}                         ${CYAN}║"
        echo -e "╚════════════════════════════════════════════════════════════════╝${NC}"
        echo
        echo -e "   ${GREEN}1)${WHITE} ${MSG_MENU_ADD}${NC}"
        echo -e "   ${YELLOW}2)${WHITE} ${MSG_MENU_REVOKE}${NC}"
        echo -e "   ${RED}3)${WHITE} ${MSG_MENU_REMOVE}${NC}"
        echo -e "   ${CYAN}4)${WHITE} ${MSG_MENU_EXIT}${NC}"
        echo
        prompt "${MSG_PROMPT_ACTION} [1-4]: "
        read option
        
        case "$option" in
            1)
                echo
                prompt "${MSG_PROMPT_NEW_CLIENT} "
                read unsanitized_client
                client=$(sed 's/[^a-zA-Z0-9_-]/_/g' <<< "$unsanitized_client")
                if [[ -z "$client" || -e /etc/openvpn/easy-rsa/pki/issued/"$client".crt ]]; then
                    error "$MSG_ERR_CLIENT_EXISTS"
                    exit 1
                fi
                port=$(grep '^port ' /etc/openvpn/server.conf | cut -d " " -f 2)
                protocol=$(grep '^proto ' /etc/openvpn/server.conf | cut -d " " -f 2)
                ip=$(grep '^remote ' /etc/openvpn/client-common.txt | cut -d " " -f 2)
                generate_client_config "$client" "$ip" "$port" "$protocol"
                ;;
            2)
                number_of_clients=$(tail -n +2 /etc/openvpn/easy-rsa/pki/index.txt | grep -c "^V")
                if [[ "$number_of_clients" = 0 ]]; then
                    error "$MSG_ERR_NO_CLIENT"
                    exit 1
                fi
                echo
                info "$MSG_INFO_CLIENTS"
                tail -n +2 /etc/openvpn/easy-rsa/pki/index.txt | grep "^V" | cut -d '=' -f 2 | nl -s ') '
                prompt "${MSG_PROMPT_REVOKE_NUM} "
                read client_number
                client=$(tail -n +2 /etc/openvpn/easy-rsa/pki/index.txt | grep "^V" | cut -d '=' -f 2 | sed -n "$client_number"p)
                if [[ -z "$client" ]]; then
                    error "$MSG_ERR_INVALID"
                    exit 1
                fi
                prompt "$client ${MSG_PROMPT_SURE_REVOKE}"
                read revoke
                if [[ "$revoke" =~ $MSG_YES_REGEX ]]; then
                    cd /etc/openvpn/easy-rsa/
                    ./easyrsa --batch revoke "$client" >/dev/null
                    ./easyrsa --batch --days=3650 gen-crl >/dev/null
                    cp /etc/openvpn/easy-rsa/pki/crl.pem /etc/openvpn/crl.pem
                    chown nobody:nobody /etc/openvpn/crl.pem
                    success "$client $MSG_OK_REVOKE"
                fi
                ;;
            3)
                echo
                warning "$MSG_WARN_REMOVE"
                prompt "$MSG_PROMPT_SURE_REMOVE"
                read remove
                if [[ "$remove" =~ $MSG_YES_REGEX ]]; then
                    port=$(grep '^port ' /etc/openvpn/server.conf | cut -d " " -f 2)
                    protocol=$(grep '^proto ' /etc/openvpn/server.conf | cut -d " " -f 2)
                    cleanup_firewall "$port" "$protocol"
                    
                    info "$MSG_INFO_STOP"
                    systemctl stop openvpn-server@server
                    systemctl disable openvpn-server@server &>/dev/null
                    
                    info "$MSG_INFO_CLEAN"
                    rm -rf /etc/openvpn/*
                    rm -f /etc/sysctl.d/99-openvpn-forward.conf
                    
                    info "$MSG_INFO_PKG"
                    dnf remove -y openvpn &> /dev/null
                    
                    success "$MSG_OK_REMOVE"
                fi
                ;;
            4|*)
                info "$MSG_INFO_EXIT"
                exit 0
                ;;
        esac
    fi
}

main_installation
