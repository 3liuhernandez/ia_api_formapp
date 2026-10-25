#!/bin/sh
set -e

# Asegurar permisos sobre los volúmenes montados en Coolify (/data y /app/public/updates)
mkdir -p /data /app/public/updates /app/logs
chown -R node:node /data /app/public/updates /app/logs 2>/dev/null || true

# Ejecutar el comando pasado como parámetro bajo el usuario 'node'
exec su-exec node "$@"
