# Guía de Deploy - ElimAPP API en VPS

## Requisitos del VPS
- Ubuntu 20.04+ (o similar)
- Node.js 18+ instalado
- PM2 instalado globalmente

---

## 1. Instalar Node.js (si no lo tienes)

```bash
curl -fsSL https://deb.nodesource.com/setup_20.x | sudo -E bash -
sudo apt-get install -y nodejs
```

## 2. Instalar PM2

```bash
sudo npm install -g pm2
```

## 3. Subir la API al servidor

Sube la carpeta `api/` a tu VPS (por FTP, SCP, o Git):

```bash
# Desde tu PC:
scp -r ./api usuario@TU_IP_VPS:/home/usuario/elimapp-api
```

## 4. Instalar dependencias

```bash
cd /home/usuario/elimapp-api
npm install --production
```

## 5. Configurar variables de entorno

```bash
cp .env.example .env
nano .env
```

**⚠️ IMPORTANTE - Genera una API Key segura:**

```bash
node -e "console.log(require('crypto').randomBytes(32).toString('hex'))"
```

Copia el resultado y pégalo en `API_KEY` del `.env`. 
**Esa misma clave debe ir en `services/api.ts` de la APP**.

```env
PORT=3001
API_KEY=TU_CLAVE_GENERADA_AQUÍ
NODE_ENV=production
RATE_LIMIT_WINDOW_MINUTES=15
RATE_LIMIT_MAX_REQUESTS=100
```

## 6. Crear directorio de logs

```bash
mkdir -p logs
```

## 7. Iniciar con PM2

```bash
pm2 start ecosystem.config.js
pm2 save
pm2 startup  # Para que inicie con el servidor
```

## 8. Verificar

```bash
# Estado
pm2 status

# Logs en vivo
pm2 logs elimapp-api

# Test
curl http://localhost:3001/api/health
```

## 9. Configurar Firewall

```bash
sudo ufw allow 3001/tcp
# O si usas Nginx como proxy:
sudo ufw allow 80/tcp
sudo ufw allow 443/tcp
```

---

## Configurar Nginx (recomendado)

Para usar un dominio y HTTPS:

```bash
sudo apt install nginx certbot python3-certbot-nginx
```

Crear config:
```bash
sudo nano /etc/nginx/sites-available/elimapp
```

```nginx
server {
    listen 80;
    server_name tu-dominio.com;

    location / {
        proxy_pass http://127.0.0.1:3001;
        proxy_http_version 1.1;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}
```

```bash
sudo ln -s /etc/nginx/sites-available/elimapp /etc/nginx/sites-enabled/
sudo nginx -t
sudo systemctl restart nginx

# SSL con Let's Encrypt (gratis)
sudo certbot --nginx -d tu-dominio.com
```

---

## Actualizar la APP

En `services/api.ts` cambia:
```typescript
const API_BASE_URL = 'https://tu-dominio.com/api';
const API_KEY = 'LA_MISMA_CLAVE_DEL_ENV';
```

---

## Comandos útiles de PM2

```bash
pm2 status              # Ver estado
pm2 logs elimapp-api    # Ver logs
pm2 restart elimapp-api # Reiniciar
pm2 stop elimapp-api    # Detener
pm2 delete elimapp-api  # Eliminar
```
