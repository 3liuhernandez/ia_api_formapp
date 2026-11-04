#!/bin/sh
set -e

# Asegurar permisos sobre los volúmenes montados en Coolify (/data y /app/public/updates)
mkdir -p /data /app/public/updates /app/logs
chown -R node:node /data /app/public/updates /app/logs 2>/dev/null || true

# Si su-exec está instalado, ejecutar bajo usuario 'node'; si no, ejecutar directamente
if command -v su-exec >/dev/null 2>&1; then
    exec su-exec node "$@"
else
    exec "$@"
fi
