#!/bin/sh
set -e

# Asegurar permisos sobre los volúmenes montados en Coolify (/data y /app/public/updates)
mkdir -p /data /app/public/updates /app/logs
chown -R node:node /data /app/public/updates /app/logs 2>/dev/null || true

# Ejecutar como usuario 'node' de forma segura (runuser en Debian, su-exec en Alpine, o fallback directo)
if command -v runuser >/dev/null 2>&1; then
    exec runuser -u node -- "$@"
elif command -v su-exec >/dev/null 2>&1; then
    exec su-exec node "$@"
else
    exec "$@"
fi
