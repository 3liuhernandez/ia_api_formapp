# ==========================================
# Etapa 1: Builder (Compilación de dependencias nativas C++)
# ==========================================
FROM node:22-alpine AS builder

WORKDIR /app

# Instalar herramientas para compilar módulos nativos (better-sqlite3)
RUN apk add --no-cache python3 make g++

# Copiar manifiestos primero para cachear dependencias
COPY package*.json ./

# Instalar solo dependencias de producción
RUN npm ci --omit=dev && npm cache clean --force

# ==========================================
# Etapa 2: Runner (Imagen final para Coolify)
# ==========================================
FROM node:22-alpine AS runner

WORKDIR /app

# Instalar dependencias necesarias:
# - libstdc++: requerido por better-sqlite3
# - curl: para el healthcheck de Coolify / Docker
# - tzdata: zonas horarias
# - su-exec: para cambiar de root a node de forma segura tras ajustar permisos
RUN apk add --no-cache libstdc++ curl tzdata su-exec

# Variables de entorno por defecto (Coolify puede sobrescribirlas desde su panel)
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

# Verificación de estado de salud (Coolify Healthcheck)
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
  CMD curl -f http://localhost:3001/api/health || exit 1

ENTRYPOINT ["/docker-entrypoint.sh"]
CMD ["node", "server.js"]
