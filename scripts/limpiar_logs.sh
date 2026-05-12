#!/bin/bash
# Encuentra y borra logs de más de 7 días
find /var/log -type f -name "*.log" -mtime +7 -exec rm -f {} \;
echo "Limpieza de logs completada."