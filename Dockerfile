# ==========================================
# Etapa 1: Builder (Compilación de dependencias nativas C++)
# ==========================================
FROM node:22-alpine AS builder

WORKDIR /app

# Instalar herramientas para compilar módulos nativos (better-sqlite3)
RUN apk update && \
    (apk add --no-cache python3 make g++ || \
     (sleep 2 && apk add --no-cache python3 make g++) || \
     (sleep 4 && apk add --no-cache python3 make g++))

# Copiar manifiestos primero para cachear dependencias
COPY package*.json ./

# Instalar solo dependencias de producción
RUN npm ci --omit=dev && npm cache clean --force

# ==========================================
# Etapa 2: Runner (Imagen final para Coolify)
# ==========================================
FROM node:22-alpine AS runner

WORKDIR /app

# Instalar dependencias de runtime:
# - libstdc++: requerido por better-sqlite3
# - tzdata: zonas horarias
# - su-exec: cambio seguro de usuario
RUN apk update && \
    (apk add --no-cache libstdc++ tzdata su-exec || \
     (sleep 2 && apk add --no-cache libstdc++ tzdata su-exec) || \
     (sleep 4 && apk add --no-cache libstdc++ tzdata su-exec) || true)

# Variables de entorno por defecto
ENV NODE_ENV=production \
    PORT=3001 \
    DATABASE_PATH=/data/database.sqlite

# Crear directorios para los volúmenes persistentes de Coolify
RUN mkdir -p /data /app/public/updates /app/logs && \
    chown -R node:node /app /data

# Copiar dependencias ya compiladas desde el builder
COPY --from=builder --chown=node:node /app/node_modules ./node_modules

# Copiar el código fuente
COPY --chown=node:node package*.json ./
COPY --chown=node:node server.js ./
COPY --chown=node:node manage-users.js ./

# Copiar y preparar el script de inicio (entrypoint)
COPY docker-entrypoint.sh /docker-entrypoint.sh
RUN sed -i 's/\r$//' /docker-entrypoint.sh && \
    chmod +x /docker-entrypoint.sh

# Exponer el puerto de la aplicación
EXPOSE 3001

# Verificación de salud nativa con Node.js (sin depender de curl externo)
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
  CMD node -e "fetch('http://localhost:3001/api/health').then(r => process.exit(r.ok ? 0 : 1)).catch(() => process.exit(1))"

ENTRYPOINT ["/docker-entrypoint.sh"]
CMD ["node", "server.js"]
