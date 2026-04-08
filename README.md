# ia_formapp_api
api backend para el proyecto de formapp creado por la IA

# actualizaciones con el servidor
ahora se puede actualizar la version de la app desde el servidor

# como subir una nueva version
1. ve a la carpeta app-apks-updates
2. ejecuta el script python submit_new_apk_version.py
3. selecciona el archivo app-release.apk
4. ingresa el numero de version
5. ingresa las notas del cambio
6. presiona enter


# Configuracion del servidor

# variables de entorno
PORT=3001
API_KEY=CAMBIA_ESTO_POR_UNA_CLAVE_SEGURA_LARGA_Y_ALEATORIA
ALLOWED_ORIGINS=
NODE_ENV=production
RATE_LIMIT_WINDOW_MINUTES=15
RATE_LIMIT_MAX_REQUESTS=100

# para subir la version de la app
python -m pip install requests
py .\app-apks-updates\submit_new_apk_version.py

# configuracion de coolify

- Ir a Configuracion > General
- Ubicar el contenedor "Container Labels"
- Desmarcar "Readonly labels"
- Busca la línea 9 de ese cuadro negro. Actualmente dice: 
    > traefik.http.routers.https-0-ck8ghwscowc0s80oww08ksog.middlewares=gzip
- Cámbiala por:
    > traefik.http.routers.https-0-ck8ghwscowc0s80oww08ksog.middlewares=gzip,limit-upload
- Añade la definición del límite al final:
    > traefik.http.middlewares.limit-upload.buffering.maxRequestBodyBytes=104857600
- Después de hacer esto:
- Haz clic en el botón verde "Save" (Arriba a la derecha).

- Dale a "Restart" o "Redeploy" al servicio para que Docker tome las nuevas etiquetas.