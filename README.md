# Transferencia de Archivos
Una herramienta interactiva en Bash para facilitar la transferencia de archivos entre sistemas Windows y Linux (Kali), especialmente útil en entornos de pentesting y administración de sistemas.
## Características
### Transferencia desde Kali Linux
- **SCP**: Transferencia segura usando SSH
- **Python HTTP Server**: Servidor web simple para compartir archivos
- **Netcat**: Transferencia directa a través de TCP/UDP
- **FTP**: Protocolo estándar de transferencia de archivos
- **SMB**: Compartir archivos usando impacket-smbserver
- **Rsync**: Sincronización eficiente de archivos entre sistemas Linux

### Transferencia desde Windows
- **PowerShell Web Downloads**: Múltiples métodos para descargar archivos
- **SMB Shares**: Compartir archivos usando el protocolo SMB
- **FTP**: Transferencia de archivos usando FTP

### Características Adicionales
- Interfaz interactiva y fácil de usar
- Soporte para transferencias bidireccionales
- Métodos alternativos usando Base64 cuando sea necesario
- Instrucciones detalladas para cada método
- Soporte para autenticación en métodos que lo requieren

## Requisitos
### Para Kali Linux
- Python 3
- OpenSSH Server (para SCP)
- impacket (para SMB)
- pyftpdlib (para FTP)
- rsync (para transferencias Rsync)

### Para Windows
- PowerShell
- Acceso a Internet (para descargas web)
- Permisos de administrador (para algunos métodos)

## Instalación
1. Clona el repositorio:
git clone https://github.com/oliverexx/transferencia-archivos.git

## Uso
1. Selecciona el sistema operativo de origen (Kali Linux o Windows)
2. Elige el método de transferencia deseado
3. Sigue las instrucciones específicas para cada método
4. Los archivos se transferirán según el método seleccionado

## Notas Importantes
- Asegúrate de tener los permisos necesarios en ambos sistemas
- Verifica que los puertos requeridos estén abiertos
- Algunos métodos pueden requerir configuración adicional en el firewall
- Para transferencias seguras, se recomienda usar SCP o métodos con autenticación

## Contribuciones
Las contribuciones son bienvenidas. Por favor, abre un issue para discutir los cambios propuestos.
## Redes
- LinkedIn: https://www.linkedin.com/in/axel-tear
- GitHub: https://github.com/oliverexx/
