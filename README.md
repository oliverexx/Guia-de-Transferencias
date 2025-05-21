# Tr4nsf13ro4rch1v0s
# Tr4nsg - Guía de Transferencia de Archivos

Una herramienta interactiva en Bash que proporciona una guía completa para la transferencia de archivos en sistemas Windows y Linux.

## 🚀 Características

### Windows
- **Métodos de Envío (Upload)**
  - PowerShell Web Uploads
  - SMB Uploads
  - FTP Uploads

- **Métodos de Recepción (Download)**
  - PowerShell Web Downloads
  - PowerShell Fileless Downloads
  - SMB Transfers
  - FTP Transfers
  - Base64 Encode/Decode
  - Métodos Alternativos (Bitsadmin, Certutil)

### Linux
- **Métodos de Envío (Upload)**
  - SCP
  - FTP
  - cURL
  - Netcat

- **Métodos de Recepción (Download)**
  - Wget
  - cURL
  - PHP
  - FTP
  - Base64
  - Netcat
  - Python

## 📋 Requisitos

- Bash shell
- Permisos de ejecución en el script
- Dependencias específicas según el método de transferencia seleccionado

## 🛠️ Instalación

1. Clona o descarga este repositorio
2. Dale permisos de ejecución al script:
```bash
chmod +x Tr4nsfieroArchivos.sh
```

## 💻 Uso

1. Ejecuta el script:
```bash
./Tr4nsfieroArchivos.sh
```

2. Sigue el menú interactivo para seleccionar:
   - Sistema operativo (Windows/Linux)
   - Tipo de operación (Envío/Recepción)
   - Método específico de transferencia

3. Proporciona la información requerida según el método seleccionado:
   - IP objetivo
   - Dominio
   - Credenciales
   - Rutas de archivos
   - Puertos

## 🔒 Seguridad

- El script no almacena ninguna información sensible
- Las credenciales se solicitan de forma segura
- Se recomienda usar métodos encriptados cuando sea posible
- Verifica siempre los permisos y políticas de seguridad antes de realizar transferencias

## ⚠️ Consideraciones

- Algunos métodos pueden requerir permisos de administrador
- Las nuevas versiones de Windows pueden bloquear ciertos métodos
- Verifica la disponibilidad de las herramientas necesarias en el sistema
- Considera las políticas de seguridad de la red antes de realizar transferencias

## 🤝 Contribuciones

Las contribuciones son bienvenidas. Por favor, abre un issue para discutir los cambios propuestos o envía un pull request.

## 📝 Licencia

Este proyecto está bajo la Licencia MIT. Ver el archivo `LICENSE` para más detalles.

## ⚠️ Descargo de Responsabilidad

Esta herramienta está diseñada con fines educativos y de administración de sistemas. El usuario es responsable de su uso y debe asegurarse de cumplir con todas las políticas y regulaciones aplicables. 
