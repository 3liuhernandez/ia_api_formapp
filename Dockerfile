# ==========================================
# Imagen base: Debian Slim oficial de Node.js
# Ventajas:
# - better-sqlite3 incluye binarios precompilados para Linux x64 (glibc).
# - No requiere compilar C++ (cero python, make o g++).
# - Cero dependencias de repositorios externos (evita timeouts de red).
# ==========================================
FROM node:22-bookworm-slim

WORKDIR /app

# Variables de entorno por defecto
ENV NODE_ENV=production \
    PORT=3001 \
    DATABASE_PATH=/data/database.sqlite

# Crear directorios para los volúmenes persistentes de Coolify y dar permisos a 'node'
RUN mkdir -p /data /app/public/updates /app/logs && \
    chown -R node:node /app /data

# Copiar manifiestos de dependencias primero para aprovechar caché
COPY package*.json ./

# Instalar dependencias de producción (en Debian glibc se descargan binarios precompilados directamente)
RUN npm ci --omit=dev && npm cache clean --force

# Copiar el código fuente
COPY --chown=node:node server.js ./
COPY --chown=node:node manage-users.js ./

# Copiar y preparar el script de inicio (entrypoint)
COPY docker-entrypoint.sh /docker-entrypoint.sh
RUN sed -i 's/\r$//' /docker-entrypoint.sh && \
    chmod +x /docker-entrypoint.sh

# Exponer el puerto de la aplicación
EXPOSE 3001

# Verificación de salud nativa con Node.js (inmune a paquetes externos)
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
  CMD node -e "fetch('http://localhost:3001/api/health').then(r => process.exit(r.ok ? 0 : 1)).catch(() => process.exit(1))"

ENTRYPOINT ["/docker-entrypoint.sh"]
CMD ["node", "server.js"]
