#!/bin/bash

# Colores para la salida
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
NC='\033[0m' # No Color

# Variables globales
TARGET_URL=""
TARGET_IP=""
SESSION_NAME="htb_scan"
SCAN_FILE="scan_${TARGET_IP}.txt"

# Función para mostrar el menú principal
show_main_menu() {
    clear
    echo -e "${GREEN}=== MENÚ PRINCIPAL DE FUZZING ===${NC}"
    echo
    echo -e "${YELLOW}URL objetivo actual: ${GREEN}$TARGET_URL${NC}"
    echo
    echo "1. Fuzzing de Archivos y Directorios"
    echo "2. Fuzzing de Parámetros"
    echo "3. Fuzzing de VHOST y Subdominios"
    echo "4. Fuzzing de API REST"
    echo "5. Validación Manual"
    echo "6. Configuración"
    echo "7. Salir"
    echo
    echo -n "Seleccione una opción: "
}

# Función para mostrar el submenú de archivos y directorios
show_files_dirs_menu() {
    clear
    echo -e "${GREEN}=== FUZZING DE ARCHIVOS Y DIRECTORIOS ===${NC}"
    echo
    echo "1. FFUF"
    echo "2. Feroxbuster"
    echo "3. Gobuster"
    echo "4. Wfuzz"
    echo "5. Dirb"
    echo "6. Volver al menú principal"
    echo
    echo -n "Seleccione una herramienta: "
}

# Función para mostrar la sintaxis de FFUF
show_ffuf_syntax() {
    clear
    echo -e "${GREEN}=== FFUF - SINTAXIS Y EJEMPLOS ===${NC}"
    echo
    echo -e "${YELLOW}1. Fuzzing básico:${NC}"
    echo "ffuf -w /usr/share/wordlists/seclists/Discovery/Web-Content/common.txt \\"
    echo "     -u $TARGET_URL/FUZZ \\"
    echo "     -mc 200"
    echo
    echo -e "${YELLOW}2. Fuzzing con extensiones:${NC}"
    echo "ffuf -w /usr/share/wordlists/seclists/Discovery/Web-Content/common.txt \\"
    echo "     -u $TARGET_URL/FUZZ \\"
    echo "     -e .php,.html,.txt \\"
    echo "     -mc 200"
    echo
    echo -e "${YELLOW}3. Fuzzing recursivo:${NC}"
    echo "ffuf -w /usr/share/wordlists/seclists/Discovery/Web-Content/common.txt \\"
    echo "     -u $TARGET_URL/FUZZ \\"
    echo "     -recursion \\"
    echo "     -recursion-depth 2 \\"
    echo "     -mc 200"
    echo
    echo -e "${YELLOW}4. Fuzzing con filtrado:${NC}"
    echo "ffuf -w /usr/share/wordlists/seclists/Discovery/Web-Content/common.txt \\"
    echo "     -u $TARGET_URL/FUZZ \\"
    echo "     -mc 200 \\"
    echo "     -fs 0 \\"
    echo "     -fc 404 \\"
    echo "     -mr \"admin\" \\"
    echo "     -fr \"error\""
    echo
    echo -e "${YELLOW}5. Fuzzing con autenticación:${NC}"
    echo "ffuf -w /usr/share/wordlists/seclists/Discovery/Web-Content/common.txt \\"
    echo "     -u $TARGET_URL/FUZZ \\"
    echo "     -H \"Authorization: Bearer token123\" \\"
    echo "     -mc 200"
    echo
    echo -e "${YELLOW}6. Fuzzing con rate limit:${NC}"
    echo "ffuf -w /usr/share/wordlists/seclists/Discovery/Web-Content/common.txt \\"
    echo "     -u $TARGET_URL/FUZZ \\"
    echo "     -rate 100 \\"
    echo "     -mc 200"
    echo
    echo -e "${PURPLE}Notas importantes:${NC}"
    echo "1. Ajusta la velocidad según el objetivo"
    echo "2. Usa diferentes wordlists para mejor cobertura"
    echo "3. Combina filtros para resultados más precisos"
    echo "4. Documenta los hallazgos importantes"
    echo "5. Valida manualmente los resultados"
    echo
    read -p "Presione Enter para continuar..."
}

# Función para mostrar la sintaxis de Feroxbuster
show_feroxbuster_syntax() {
    clear
    echo -e "${GREEN}=== FEROXBUSTER - SINTAXIS Y EJEMPLOS ===${NC}"
    echo
    echo -e "${YELLOW}1. Fuzzing básico:${NC}"
    echo "feroxbuster -u $TARGET_URL \\"
    echo "            -w /usr/share/wordlists/seclists/Discovery/Web-Content/common.txt \\"
    echo "            --depth 3 \\"
    echo "            --threads 30"
    echo
    echo -e "${YELLOW}2. Fuzzing con filtrado:${NC}"
    echo "feroxbuster -u $TARGET_URL \\"
    echo "            -w /usr/share/wordlists/seclists/Discovery/Web-Content/common.txt \\"
    echo "            -C 404,403 \\"
    echo "            -S 1024 \\"
    echo "            --threads 30"
    echo
    echo -e "${YELLOW}3. Fuzzing con recursión:${NC}"
    echo "feroxbuster -u $TARGET_URL \\"
    echo "            -w /usr/share/wordlists/seclists/Discovery/Web-Content/common.txt \\"
    echo "            --depth 5 \\"
    echo "            --recursion"
    echo
    echo -e "${YELLOW}4. Fuzzing con autenticación:${NC}"
    echo "feroxbuster -u $TARGET_URL \\"
    echo "            -w /usr/share/wordlists/seclists/Discovery/Web-Content/common.txt \\"
    echo "            --headers \"Authorization: Bearer token123\""
    echo
    echo -e "${YELLOW}5. Fuzzing con exclusiones:${NC}"
    echo "feroxbuster -u $TARGET_URL \\"
    echo "            -w /usr/share/wordlists/seclists/Discovery/Web-Content/common.txt \\"
    echo "            -X \"error\" \\"
    echo "            -N 50"
    echo
    echo -e "${PURPLE}Notas importantes:${NC}"
    echo "1. Ajusta la profundidad según el objetivo"
    echo "2. Usa diferentes wordlists para mejor cobertura"
    echo "3. Combina herramientas para mejores resultados"
    echo "4. Documenta los hallazgos importantes"
    echo "5. Valida manualmente los resultados"
    echo
    read -p "Presione Enter para continuar..."
}

# Función para mostrar la sintaxis de Gobuster
show_gobuster_syntax() {
    clear
    echo -e "${GREEN}=== GOBUSTER - SINTAXIS Y EJEMPLOS ===${NC}"
    echo
    echo -e "${YELLOW}1. Fuzzing básico:${NC}"
    echo "gobuster dir -u $TARGET_URL \\"
    echo "            -w /usr/share/wordlists/seclists/Discovery/Web-Content/common.txt \\"
    echo "            -x .html,.php,.txt \\"
    echo "            -t 30"
    echo
    echo -e "${YELLOW}2. Fuzzing con filtrado:${NC}"
    echo "gobuster dir -u $TARGET_URL \\"
    echo "            -w /usr/share/wordlists/seclists/Discovery/Web-Content/common.txt \\"
    echo "            -s 200,204,301,302,307,401,403 \\"
    echo "            -b 404 \\"
    echo "            -t 50"
    echo
    echo -e "${YELLOW}3. Fuzzing con recursión:${NC}"
    echo "gobuster dir -u $TARGET_URL \\"
    echo "            -w /usr/share/wordlists/seclists/Discovery/Web-Content/common.txt \\"
    echo "            -r \\"
    echo "            -t 30"
    echo
    echo -e "${YELLOW}4. Fuzzing con autenticación:${NC}"
    echo "gobuster dir -u $TARGET_URL \\"
    echo "            -w /usr/share/wordlists/seclists/Discovery/Web-Content/common.txt \\"
    echo "            -H \"Authorization: Bearer token123\""
    echo
    echo -e "${YELLOW}5. Fuzzing con exclusiones:${NC}"
    echo "gobuster dir -u $TARGET_URL \\"
    echo "            -w /usr/share/wordlists/seclists/Discovery/Web-Content/common.txt \\"
    echo "            --exclude-length 0 \\"
    echo "            --exclude-text \"404\""
    echo
    echo -e "${PURPLE}Notas importantes:${NC}"
    echo "1. Ajusta la velocidad según el objetivo"
    echo "2. Usa diferentes wordlists para mejor cobertura"
    echo "3. Combina herramientas para mejores resultados"
    echo "4. Documenta los hallazgos importantes"
    echo "5. Valida manualmente los resultados"
    echo
    read -p "Presione Enter para continuar..."
}

# Función para mostrar la sintaxis de Wfuzz
show_wfuzz_syntax() {
    clear
    echo -e "${GREEN}=== WFUZZ - SINTAXIS Y EJEMPLOS ===${NC}"
    echo
    echo -e "${YELLOW}1. Fuzzing básico:${NC}"
    echo "wfuzz -w /usr/share/wordlists/seclists/Discovery/Web-Content/common.txt \\"
    echo "      --hc 404 \\"
    echo "      $TARGET_URL/FUZZ"
    echo
    echo -e "${YELLOW}2. Fuzzing con filtrado:${NC}"
    echo "wfuzz -w /usr/share/wordlists/seclists/Discovery/Web-Content/common.txt \\"
    echo "      --hc 404,403 \\"
    echo "      --hl 0 \\"
    echo "      --hw 0 \\"
    echo "      $TARGET_URL/FUZZ"
    echo
    echo -e "${YELLOW}3. Fuzzing con recursión:${NC}"
    echo "wfuzz -w /usr/share/wordlists/seclists/Discovery/Web-Content/common.txt \\"
    echo "      -R 2 \\"
    echo "      $TARGET_URL/FUZZ"
    echo
    echo -e "${YELLOW}4. Fuzzing con autenticación:${NC}"
    echo "wfuzz -w /usr/share/wordlists/seclists/Discovery/Web-Content/common.txt \\"
    echo "      -H \"Authorization: Bearer token123\" \\"
    echo "      $TARGET_URL/FUZZ"
    echo
    echo -e "${YELLOW}5. Fuzzing con múltiples parámetros:${NC}"
    echo "wfuzz -w /usr/share/wordlists/seclists/Discovery/Web-Content/common.txt:FUZZ1 \\"
    echo "      -w /usr/share/wordlists/seclists/Discovery/Web-Content/common.txt:FUZZ2 \\"
    echo "      $TARGET_URL/FUZZ1/FUZZ2"
    echo
    echo -e "${PURPLE}Notas importantes:${NC}"
    echo "1. Ajusta la velocidad según el objetivo"
    echo "2. Usa diferentes wordlists para mejor cobertura"
    echo "3. Combina herramientas para mejores resultados"
    echo "4. Documenta los hallazgos importantes"
    echo "5. Valida manualmente los resultados"
    echo
    read -p "Presione Enter para continuar..."
}

# Función para mostrar la sintaxis de Dirb
show_dirb_syntax() {
    clear
    echo -e "${GREEN}=== DIRB - SINTAXIS Y EJEMPLOS ===${NC}"
    echo
    echo -e "${YELLOW}1. Fuzzing básico:${NC}"
    echo "dirb $TARGET_URL /usr/share/dirb/wordlists/common.txt"
    echo
    echo -e "${YELLOW}2. Fuzzing con extensiones:${NC}"
    echo "dirb $TARGET_URL /usr/share/dirb/wordlists/common.txt -X .php,.html"
    echo
    echo -e "${YELLOW}3. Fuzzing con autenticación:${NC}"
    echo "dirb $TARGET_URL /usr/share/dirb/wordlists/common.txt -u usuario:password"
    echo
    echo -e "${YELLOW}4. Fuzzing con recursión:${NC}"
    echo "dirb $TARGET_URL /usr/share/dirb/wordlists/common.txt -r"
    echo
    echo -e "${YELLOW}5. Fuzzing con exclusiones:${NC}"
    echo "dirb $TARGET_URL /usr/share/dirb/wordlists/common.txt -N 404"
    echo
    echo -e "${PURPLE}Notas importantes:${NC}"
    echo "1. Ajusta la velocidad según el objetivo"
    echo "2. Usa diferentes wordlists para mejor cobertura"
    echo "3. Combina herramientas para mejores resultados"
    echo "4. Documenta los hallazgos importantes"
    echo "5. Valida manualmente los resultados"
    echo
    read -p "Presione Enter para continuar..."
}

# Función para mostrar el submenú de parámetros
show_params_menu() {
    clear
    echo -e "${GREEN}=== FUZZING DE PARÁMETROS ===${NC}"
    echo
    echo "1. FFUF Parámetros"
    echo "2. Arjun"
    echo "3. ParamSpider"
    echo "4. Wfuzz Parámetros"
    echo "5. Volver al menú principal"
    echo
    echo -n "Seleccione una herramienta: "
}

# Función para mostrar el submenú de VHOST y Subdominios
show_vhost_menu() {
    clear
    echo -e "${GREEN}=== FUZZING DE VHOST Y SUBDOMINIOS ===${NC}"
    echo
    echo "1. FFUF VHOST"
    echo "2. Gobuster VHOST"
    echo "3. Subfinder"
    echo "4. Amass"
    echo "5. Assetfinder"
    echo "6. Sublist3r"
    echo "7. DNS Recon"
    echo "8. VHost Scan"
    echo "9. AltDNS"
    echo "10. Volver al menú principal"
    echo
    echo -n "Seleccione una herramienta: "
}

# Función para mostrar el submenú de API REST
show_api_menu() {
    clear
    echo -e "${GREEN}=== FUZZING DE API REST ===${NC}"
    echo
    echo "1. FFUF API"
    echo "2. Wfuzz API"
    echo "3. Arjun API"
    echo "4. API Endpoints Discovery"
    echo "5. Volver al menú principal"
    echo
    echo -n "Seleccione una herramienta: "
}

# Función para mostrar el submenú de validación manual
show_validation_menu() {
    clear
    echo -e "${GREEN}=== VALIDACIÓN MANUAL ===${NC}"
    echo
    echo "1. Verificar Respuestas HTTP"
    echo "2. Analizar Headers"
    echo "3. Probar Métodos HTTP"
    echo "4. Verificar Redirecciones"
    echo "5. Volver al menú principal"
    echo
    echo -n "Seleccione una opción: "
}

# Función para mostrar el submenú de configuración
show_config_menu() {
    clear
    echo -e "${GREEN}=== CONFIGURACIÓN ===${NC}"
    echo
    echo "1. Cambiar URL Objetivo"
    echo "2. Configurar Wordlists"
    echo "3. Configurar Proxies"
    echo "4. Configurar Headers"
    echo "5. Volver al menú principal"
    echo
    echo -n "Seleccione una opción: "
}

# Funciones para mostrar sintaxis de herramientas de parámetros
show_ffuf_params_syntax() {
    clear
    echo -e "${GREEN}=== FFUF PARÁMETROS - SINTAXIS Y EJEMPLOS ===${NC}"
    echo
    echo -e "${YELLOW}1. Fuzzing de parámetros GET:${NC}"
    echo "ffuf -w /usr/share/wordlists/seclists/Discovery/Web-Content/burp-parameter-names.txt \\"
    echo "     -u $TARGET_URL/?FUZZ=test \\"
    echo "     -fs 0"
    echo
    echo -e "${YELLOW}2. Fuzzing de parámetros POST:${NC}"
    echo "ffuf -w /usr/share/wordlists/seclists/Discovery/Web-Content/burp-parameter-names.txt \\"
    echo "     -u $TARGET_URL \\"
    echo "     -X POST \\"
    echo "     -d 'FUZZ=test' \\"
    echo "     -fs 0"
    echo
    echo -e "${YELLOW}3. Fuzzing de múltiples parámetros:${NC}"
    echo "ffuf -w /usr/share/wordlists/seclists/Discovery/Web-Content/burp-parameter-names.txt:FUZZ1 \\"
    echo "     -w /usr/share/wordlists/seclists/Discovery/Web-Content/burp-parameter-names.txt:FUZZ2 \\"
    echo "     -u $TARGET_URL/?FUZZ1=test&FUZZ2=test \\"
    echo "     -fs 0"
    echo
    read -p "Presione Enter para continuar..."
}

show_arjun_syntax() {
    clear
    echo -e "${GREEN}=== ARJUN - SINTAXIS Y EJEMPLOS ===${NC}"
    echo
    echo -e "${YELLOW}1. Descubrimiento básico:${NC}"
    echo "arjun -u $TARGET_URL"
    echo
    echo -e "${YELLOW}2. Descubrimiento con métodos HTTP:${NC}"
    echo "arjun -u $TARGET_URL -m GET,POST"
    echo
    echo -e "${YELLOW}3. Descubrimiento con headers:${NC}"
    echo "arjun -u $TARGET_URL -H 'Authorization: Bearer token'"
    echo
    read -p "Presione Enter para continuar..."
}

# Funciones para mostrar sintaxis de herramientas VHOST
show_ffuf_vhost_syntax() {
    clear
    echo -e "${GREEN}=== FFUF VHOST - SINTAXIS Y EJEMPLOS ===${NC}"
    echo
    echo -e "${YELLOW}1. Fuzzing básico de VHOST:${NC}"
    echo "ffuf -w /usr/share/wordlists/seclists/Discovery/DNS/subdomains-top1million-5000.txt \\"
    echo "     -u $TARGET_URL \\"
    echo "     -H 'Host: FUZZ.ejemplo.com' \\"
    echo "     -fs 0"
    echo
    echo -e "${YELLOW}2. Fuzzing con SSL:${NC}"
    echo "ffuf -w /usr/share/wordlists/seclists/Discovery/DNS/subdomains-top1million-5000.txt \\"
    echo "     -u https://$TARGET_URL \\"
    echo "     -H 'Host: FUZZ.ejemplo.com' \\"
    echo "     -fs 0"
    echo
    read -p "Presione Enter para continuar..."
}

show_gobuster_vhost_syntax() {
    clear
    echo -e "${GREEN}=== GOBUSTER VHOST - SINTAXIS Y EJEMPLOS ===${NC}"
    echo
    echo -e "${YELLOW}1. Fuzzing básico de VHOST:${NC}"
    echo "gobuster vhost -u $TARGET_URL \\"
    echo "               -w /usr/share/wordlists/seclists/Discovery/DNS/subdomains-top1million-5000.txt"
    echo
    echo -e "${YELLOW}2. Fuzzing con SSL:${NC}"
    echo "gobuster vhost -u https://$TARGET_URL \\"
    echo "               -w /usr/share/wordlists/seclists/Discovery/DNS/subdomains-top1million-5000.txt"
    echo
    read -p "Presione Enter para continuar..."
}

# Funciones para mostrar sintaxis de herramientas API
show_ffuf_api_syntax() {
    clear
    echo -e "${GREEN}=== FFUF API - SINTAXIS Y EJEMPLOS ===${NC}"
    echo
    echo -e "${YELLOW}1. Fuzzing de endpoints:${NC}"
    echo "ffuf -w /usr/share/wordlists/seclists/Discovery/Web-Content/api-endpoints.txt \\"
    echo "     -u $TARGET_URL/api/FUZZ \\"
    echo "     -H 'Content-Type: application/json' \\"
    echo "     -fs 0"
    echo
    echo -e "${YELLOW}2. Fuzzing de métodos HTTP:${NC}"
    echo "ffuf -w /usr/share/wordlists/seclists/Discovery/Web-Content/api-methods.txt \\"
    echo "     -u $TARGET_URL/api/endpoint \\"
    echo "     -X FUZZ \\"
    echo "     -H 'Content-Type: application/json' \\"
    echo "     -fs 0"
    echo
    read -p "Presione Enter para continuar..."
}

# Funciones para validación manual
show_http_validation() {
    clear
    echo -e "${GREEN}=== VALIDACIÓN DE RESPUESTAS HTTP ===${NC}"
    echo
    echo -e "${YELLOW}1. Verificar código de estado:${NC}"
    echo "curl -I $TARGET_URL"
    echo
    echo -e "${YELLOW}2. Verificar redirecciones:${NC}"
    echo "curl -L $TARGET_URL"
    echo
    echo -e "${YELLOW}3. Verificar headers:${NC}"
    echo "curl -I -H 'User-Agent: Mozilla/5.0' $TARGET_URL"
    echo
    read -p "Presione Enter para continuar..."
}

# Funciones para configuración
show_wordlist_config() {
    clear
    echo -e "${GREEN}=== CONFIGURACIÓN DE WORDLISTS ===${NC}"
    echo
    echo -e "${YELLOW}Wordlists disponibles:${NC}"
    echo "1. /usr/share/wordlists/seclists/Discovery/Web-Content/common.txt"
    echo "2. /usr/share/wordlists/seclists/Discovery/Web-Content/big.txt"
    echo "3. /usr/share/wordlists/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt"
    echo "4. /usr/share/wordlists/seclists/Discovery/DNS/subdomains-top1million-5000.txt"
    echo
    read -p "Presione Enter para continuar..."
}

# Funciones para herramientas de parámetros pendientes
show_paramspider_syntax() {
    clear
    echo -e "${GREEN}=== PARAMSPIDER - SINTAXIS Y EJEMPLOS ===${NC}"
    echo
    echo -e "${YELLOW}1. Descubrimiento básico:${NC}"
    echo "python3 paramspider.py --domain $TARGET_URL"
    echo
    echo -e "${YELLOW}2. Descubrimiento con exclusión:${NC}"
    echo "python3 paramspider.py --domain $TARGET_URL --exclude js,css,svg"
    echo
    echo -e "${YELLOW}3. Descubrimiento con salida:${NC}"
    echo "python3 paramspider.py --domain $TARGET_URL --output params.txt"
    echo
    read -p "Presione Enter para continuar..."
}

show_wfuzz_params_syntax() {
    clear
    echo -e "${GREEN}=== WFUZZ PARÁMETROS - SINTAXIS Y EJEMPLOS ===${NC}"
    echo
    echo -e "${YELLOW}1. Fuzzing de parámetros GET:${NC}"
    echo "wfuzz -w /usr/share/wordlists/seclists/Discovery/Web-Content/burp-parameter-names.txt \\"
    echo "      --hc 404 \\"
    echo "      $TARGET_URL/?FUZZ=test"
    echo
    echo -e "${YELLOW}2. Fuzzing de parámetros POST:${NC}"
    echo "wfuzz -w /usr/share/wordlists/seclists/Discovery/Web-Content/burp-parameter-names.txt \\"
    echo "      -X POST \\"
    echo "      -d 'FUZZ=test' \\"
    echo "      --hc 404 \\"
    echo "      $TARGET_URL"
    echo
    read -p "Presione Enter para continuar..."
}

# Funciones para herramientas VHOST pendientes
show_subfinder_syntax() {
    clear
    echo -e "${GREEN}=== SUBFINDER - SINTAXIS Y EJEMPLOS ===${NC}"
    echo
    echo -e "${YELLOW}1. Descubrimiento básico:${NC}"
    echo "subfinder -d $TARGET_URL"
    echo
    echo -e "${YELLOW}2. Descubrimiento con recursión:${NC}"
    echo "subfinder -d $TARGET_URL -recursive"
    echo
    echo -e "${YELLOW}3. Descubrimiento con salida:${NC}"
    echo "subfinder -d $TARGET_URL -o subdomains.txt"
    echo
    read -p "Presione Enter para continuar..."
}

show_amass_syntax() {
    clear
    echo -e "${GREEN}=== AMASS - SINTAXIS Y EJEMPLOS ===${NC}"
    echo
    echo -e "${YELLOW}1. Descubrimiento pasivo:${NC}"
    echo "amass enum -passive -d $TARGET_URL"
    echo
    echo -e "${YELLOW}2. Descubrimiento activo:${NC}"
    echo "amass enum -active -d $TARGET_URL"
    echo
    echo -e "${YELLOW}3. Descubrimiento completo:${NC}"
    echo "amass enum -brute -d $TARGET_URL"
    echo
    read -p "Presione Enter para continuar..."
}

# Funciones para herramientas API pendientes
show_wfuzz_api_syntax() {
    clear
    echo -e "${GREEN}=== WFUZZ API - SINTAXIS Y EJEMPLOS ===${NC}"
    echo
    echo -e "${YELLOW}1. Fuzzing de endpoints:${NC}"
    echo "wfuzz -w /usr/share/wordlists/seclists/Discovery/Web-Content/api-endpoints.txt \\"
    echo "      -H 'Content-Type: application/json' \\"
    echo "      --hc 404 \\"
    echo "      $TARGET_URL/api/FUZZ"
    echo
    echo -e "${YELLOW}2. Fuzzing de métodos HTTP:${NC}"
    echo "wfuzz -w /usr/share/wordlists/seclists/Discovery/Web-Content/api-methods.txt \\"
    echo "      -H 'Content-Type: application/json' \\"
    echo "      --hc 404 \\"
    echo "      -X FUZZ \\"
    echo "      $TARGET_URL/api/endpoint"
    echo
    read -p "Presione Enter para continuar..."
}

show_arjun_api_syntax() {
    clear
    echo -e "${GREEN}=== ARJUN API - SINTAXIS Y EJEMPLOS ===${NC}"
    echo
    echo -e "${YELLOW}1. Descubrimiento de endpoints:${NC}"
    echo "arjun -u $TARGET_URL/api"
    echo
    echo -e "${YELLOW}2. Descubrimiento con autenticación:${NC}"
    echo "arjun -u $TARGET_URL/api -H 'Authorization: Bearer token'"
    echo
    echo -e "${YELLOW}3. Descubrimiento con métodos específicos:${NC}"
    echo "arjun -u $TARGET_URL/api -m GET,POST,PUT,DELETE"
    echo
    read -p "Presione Enter para continuar..."
}

show_api_endpoints_syntax() {
    clear
    echo -e "${GREEN}=== API ENDPOINTS DISCOVERY - SINTAXIS Y EJEMPLOS ===${NC}"
    echo
    echo -e "${YELLOW}1. Descubrimiento con FFUF:${NC}"
    echo "ffuf -w /usr/share/wordlists/seclists/Discovery/Web-Content/api-endpoints.txt \\"
    echo "     -u $TARGET_URL/api/FUZZ \\"
    echo "     -H 'Content-Type: application/json' \\"
    echo "     -fs 0"
    echo
    echo -e "${YELLOW}2. Descubrimiento con Wfuzz:${NC}"
    echo "wfuzz -w /usr/share/wordlists/seclists/Discovery/Web-Content/api-endpoints.txt \\"
    echo "      -H 'Content-Type: application/json' \\"
    echo "      --hc 404 \\"
    echo "      $TARGET_URL/api/FUZZ"
    echo
    read -p "Presione Enter para continuar..."
}

# Funciones para validación manual pendientes
show_headers_analysis() {
    clear
    echo -e "${GREEN}=== ANÁLISIS DE HEADERS ===${NC}"
    echo
    echo -e "${YELLOW}1. Verificar todos los headers:${NC}"
    echo "curl -I $TARGET_URL"
    echo
    echo -e "${YELLOW}2. Verificar headers específicos:${NC}"
    echo "curl -I $TARGET_URL | grep -i 'server\\|x-powered-by\\|x-aspnet-version'"
    echo
    echo -e "${YELLOW}3. Verificar headers de seguridad:${NC}"
    echo "curl -I $TARGET_URL | grep -i 'content-security-policy\\|x-frame-options\\|x-xss-protection'"
    echo
    read -p "Presione Enter para continuar..."
}

show_http_methods() {
    clear
    echo -e "${GREEN}=== PRUEBA DE MÉTODOS HTTP ===${NC}"
    echo
    echo -e "${YELLOW}1. Probar método GET:${NC}"
    echo "curl -X GET $TARGET_URL"
    echo
    echo -e "${YELLOW}2. Probar método POST:${NC}"
    echo "curl -X POST $TARGET_URL"
    echo
    echo -e "${YELLOW}3. Probar método OPTIONS:${NC}"
    echo "curl -X OPTIONS $TARGET_URL"
    echo
    echo -e "${YELLOW}4. Probar método TRACE:${NC}"
    echo "curl -X TRACE $TARGET_URL"
    echo
    read -p "Presione Enter para continuar..."
}

show_redirect_validation() {
    clear
    echo -e "${GREEN}=== VALIDACIÓN DE REDIRECCIONES ===${NC}"
    echo
    echo -e "${YELLOW}1. Seguir redirecciones:${NC}"
    echo "curl -L $TARGET_URL"
    echo
    echo -e "${YELLOW}2. Ver redirecciones sin seguirlas:${NC}"
    echo "curl -I $TARGET_URL"
    echo
    echo -e "${YELLOW}3. Ver redirecciones con verbose:${NC}"
    echo "curl -v $TARGET_URL"
    echo
    read -p "Presione Enter para continuar..."
}

# Funciones para configuración pendientes
show_proxy_config() {
    clear
    echo -e "${GREEN}=== CONFIGURACIÓN DE PROXIES ===${NC}"
    echo
    echo -e "${YELLOW}1. Configurar proxy HTTP:${NC}"
    echo "export http_proxy=http://proxy:port"
    echo "export https_proxy=http://proxy:port"
    echo
    echo -e "${YELLOW}2. Configurar proxy SOCKS:${NC}"
    echo "export http_proxy=socks5://proxy:port"
    echo "export https_proxy=socks5://proxy:port"
    echo
    echo -e "${YELLOW}3. Configurar proxy con autenticación:${NC}"
    echo "export http_proxy=http://user:pass@proxy:port"
    echo "export https_proxy=http://user:pass@proxy:port"
    echo
    read -p "Presione Enter para continuar..."
}

show_headers_config() {
    clear
    echo -e "${GREEN}=== CONFIGURACIÓN DE HEADERS ===${NC}"
    echo
    echo -e "${YELLOW}1. Headers comunes:${NC}"
    echo "User-Agent: Mozilla/5.0"
    echo "Accept: text/html,application/xhtml+xml"
    echo "Accept-Language: en-US,en;q=0.9"
    echo
    echo -e "${YELLOW}2. Headers de autenticación:${NC}"
    echo "Authorization: Bearer token123"
    echo "X-API-Key: your-api-key"
    echo
    echo -e "${YELLOW}3. Headers personalizados:${NC}"
    echo "X-Custom-Header: value"
    echo "X-Forwarded-For: 127.0.0.1"
    echo
    read -p "Presione Enter para continuar..."
}

# Funciones para herramientas VHOST adicionales
show_assetfinder_syntax() {
    clear
    echo -e "${GREEN}=== ASSETFINDER - SINTAXIS Y EJEMPLOS ===${NC}"
    echo
    echo -e "${YELLOW}1. Descubrimiento básico:${NC}"
    echo "assetfinder $TARGET_URL"
    echo
    echo -e "${YELLOW}2. Descubrimiento con subdominios:${NC}"
    echo "assetfinder --subs-only $TARGET_URL"
    echo
    echo -e "${YELLOW}3. Descubrimiento con salida:${NC}"
    echo "assetfinder $TARGET_URL > subdomains.txt"
    echo
    echo -e "${PURPLE}Notas importantes:${NC}"
    echo "1. Herramienta rápida y ligera"
    echo "2. Utiliza múltiples fuentes"
    echo "3. Ideal para descubrimiento inicial"
    echo
    read -p "Presione Enter para continuar..."
}

show_sublist3r_syntax() {
    clear
    echo -e "${GREEN}=== SUBLIST3R - SINTAXIS Y EJEMPLOS ===${NC}"
    echo
    echo -e "${YELLOW}1. Descubrimiento básico:${NC}"
    echo "sublist3r -d $TARGET_URL"
    echo
    echo -e "${YELLOW}2. Descubrimiento con salida:${NC}"
    echo "sublist3r -d $TARGET_URL -o subdomains.txt"
    echo
    echo -e "${YELLOW}3. Descubrimiento con threads:${NC}"
    echo "sublist3r -d $TARGET_URL -t 40"
    echo
    echo -e "${PURPLE}Notas importantes:${NC}"
    echo "1. Utiliza múltiples motores de búsqueda"
    echo "2. Soporta DNS bruteforce"
    echo "3. Ideal para enumeración pasiva"
    echo
    read -p "Presione Enter para continuar..."
}

show_dnsrecon_syntax() {
    clear
    echo -e "${GREEN}=== DNS RECON - SINTAXIS Y EJEMPLOS ===${NC}"
    echo
    echo -e "${YELLOW}1. Escaneo básico:${NC}"
    echo "dnsrecon -d $TARGET_URL"
    echo
    echo -e "${YELLOW}2. Escaneo con wordlist:${NC}"
    echo "dnsrecon -d $TARGET_URL -D /usr/share/wordlists/dns.txt"
    echo
    echo -e "${YELLOW}3. Escaneo completo:${NC}"
    echo "dnsrecon -d $TARGET_URL -t brt,srv,axfr"
    echo
    echo -e "${PURPLE}Notas importantes:${NC}"
    echo "1. Soporta múltiples tipos de escaneo"
    echo "2. Incluye transferencia de zona"
    echo "3. Ideal para análisis DNS detallado"
    echo
    read -p "Presione Enter para continuar..."
}

show_vhostscan_syntax() {
    clear
    echo -e "${GREEN}=== VHOST SCAN - SINTAXIS Y EJEMPLOS ===${NC}"
    echo
    echo -e "${YELLOW}1. Escaneo básico:${NC}"
    echo "vhostscan -t $TARGET_URL"
    echo
    echo -e "${YELLOW}2. Escaneo con wordlist:${NC}"
    echo "vhostscan -t $TARGET_URL -w /usr/share/wordlists/vhosts.txt"
    echo
    echo -e "${YELLOW}3. Escaneo con SSL:${NC}"
    echo "vhostscan -t $TARGET_URL -s"
    echo
    echo -e "${PURPLE}Notas importantes:${NC}"
    echo "1. Especializado en descubrimiento de VHOST"
    echo "2. Soporta SSL/TLS"
    echo "3. Ideal para entornos virtuales"
    echo
    read -p "Presione Enter para continuar..."
}

show_altdns_syntax() {
    clear
    echo -e "${GREEN}=== ALTDNS - SINTAXIS Y EJEMPLOS ===${NC}"
    echo
    echo -e "${YELLOW}1. Generación básica:${NC}"
    echo "altdns -i subdomains.txt -o permutations.txt"
    echo
    echo -e "${YELLOW}2. Generación con wordlist:${NC}"
    echo "altdns -i subdomains.txt -w words.txt -o permutations.txt"
    echo
    echo -e "${YELLOW}3. Resolución de DNS:${NC}"
    echo "altdns -i subdomains.txt -o permutations.txt -r -s resolved.txt"
    echo
    echo -e "${PURPLE}Notas importantes:${NC}"
    echo "1. Genera permutaciones de subdominios"
    echo "2. Ideal para descubrimiento de subdominios ocultos"
    echo "3. Útil para ampliar resultados de otras herramientas"
    echo
    read -p "Presione Enter para continuar..."
}

# Manejadores de menús
handle_files_dirs_menu() {
    while true; do
        show_files_dirs_menu
        read -r option
        
        case $option in
            1) show_ffuf_syntax ;;
            2) show_feroxbuster_syntax ;;
            3) show_gobuster_syntax ;;
            4) show_wfuzz_syntax ;;
            5) show_dirb_syntax ;;
            6) return ;;
            *) echo -e "${RED}Opción inválida${NC}" ;;
        esac
    done
}

handle_params_menu() {
    while true; do
        show_params_menu
        read -r option
        
        case $option in
            1) show_ffuf_params_syntax ;;
            2) show_arjun_syntax ;;
            3) show_paramspider_syntax ;;
            4) show_wfuzz_params_syntax ;;
            5) return ;;
            *) echo -e "${RED}Opción inválida${NC}" ;;
        esac
    done
}

handle_vhost_menu() {
    while true; do
        show_vhost_menu
        read -r option
        
        case $option in
            1) show_ffuf_vhost_syntax ;;
            2) show_gobuster_vhost_syntax ;;
            3) show_subfinder_syntax ;;
            4) show_amass_syntax ;;
            5) show_assetfinder_syntax ;;
            6) show_sublist3r_syntax ;;
            7) show_dnsrecon_syntax ;;
            8) show_vhostscan_syntax ;;
            9) show_altdns_syntax ;;
            10) return ;;
            *) echo -e "${RED}Opción inválida${NC}" ;;
        esac
    done
}

handle_api_menu() {
    while true; do
        show_api_menu
        read -r option
        
        case $option in
            1) show_ffuf_api_syntax ;;
            2) show_wfuzz_api_syntax ;;
            3) show_arjun_api_syntax ;;
            4) show_api_endpoints_syntax ;;
            5) return ;;
            *) echo -e "${RED}Opción inválida${NC}" ;;
        esac
    done
}

handle_validation_menu() {
    while true; do
        show_validation_menu
        read -r option
        
        case $option in
            1) show_http_validation ;;
            2) show_headers_analysis ;;
            3) show_http_methods ;;
            4) show_redirect_validation ;;
            5) return ;;
            *) echo -e "${RED}Opción inválida${NC}" ;;
        esac
    done
}

handle_config_menu() {
    while true; do
        show_config_menu
        read -r option
        
        case $option in
            1) get_target_url "Cambiar URL objetivo" ;;
            2) show_wordlist_config ;;
            3) show_proxy_config ;;
            4) show_headers_config ;;
            5) return ;;
            *) echo -e "${RED}Opción inválida${NC}" ;;
        esac
    done
}

# Función para solicitar la URL
get_target_url() {
    local prompt="$1"
    echo -e "${GREEN}=== Configuración del Objetivo ===${NC}"
    echo -e "${YELLOW}$prompt${NC}"
    echo -n "Ingrese la URL objetivo (ej: http://ejemplo.com o http://10.10.10.10): "
    read -r TARGET_URL
    
    # Validar que la URL no esté vacía
    if [ -z "$TARGET_URL" ]; then
        echo -e "${RED}Error: La URL no puede estar vacía${NC}"
        return 1
    fi
    
    # Validar formato básico de URL
    if ! [[ $TARGET_URL =~ ^https?:// ]]; then
        echo -e "${RED}Error: La URL debe comenzar con http:// o https://${NC}"
        return 1
    fi
    
    # Extraer el dominio/IP de la URL
    local domain=$(echo "$TARGET_URL" | sed -E 's|^https?://([^/]+).*|\1|')
    
    # Validar que el dominio/IP no esté vacío
    if [ -z "$domain" ]; then
        echo -e "${RED}Error: La URL debe contener un dominio o dirección IP válida${NC}"
        return 1
    fi
    
    # Validar formato de IP o dominio
    if ! [[ $domain =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]] && ! [[ $domain =~ ^[a-zA-Z0-9][a-zA-Z0-9-]*(\.[a-zA-Z0-9][a-zA-Z0-9-]*)*$ ]]; then
        echo -e "${RED}Error: El formato del dominio o IP no es válido${NC}"
        return 1
    fi
    
    echo -e "${GREEN}URL objetivo configurada: ${YELLOW}$TARGET_URL${NC}"
    echo -e "${GREEN}Dominio/IP objetivo: ${YELLOW}$domain${NC}"
    echo
    return 0
}

# Bucle principal
while true; do
    if [ -z "$TARGET_URL" ]; then
        if ! get_target_url "Configuración inicial del objetivo"; then
            echo -e "${RED}Error: Debe proporcionar una URL válida para continuar${NC}"
            exit 1
        fi
    fi

    show_main_menu
    read -r option
    
    case $option in
        1) handle_files_dirs_menu ;;
        2) handle_params_menu ;;
        3) handle_vhost_menu ;;
        4) handle_api_menu ;;
        5) handle_validation_menu ;;
        6) handle_config_menu ;;
        7) echo -e "${GREEN}Saliendo...${NC}"; exit 0 ;;
        *) echo -e "${RED}Opción inválida${NC}" ;;
    esac
    
    echo
    read -p "Presione Enter para continuar..."
    clear
done
