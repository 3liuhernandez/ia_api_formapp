# Guía de Gestión Manual de Usuarios (API)

Esta guía contiene los comandos SQL necesarios para gestionar los usuarios de la base de datos de la API directamente desde la terminal de tu VPS.

## 1. Acceder a la Base de Datos
Desde el directorio de la API (`/ruta/a/ia/api`), ejecuta:

```bash
sqlite3 database.sqlite
```

*(Si no tienes `sqlite3` instalado, puedes usar `sudo apt install sqlite3` en Ubuntu/Debian).*

---

## 2. Operaciones CRUD (SQL)

Una vez dentro de la terminal de SQLite (`sqlite>`), puedes usar los siguientes comandos:

### Listar todos los usuarios
```sql
SELECT id, username, nombre, role FROM users;
```

### Crear un nuevo usuario
Para añadir un usuario, utiliza el siguiente comando (ajusta los valores según necesites):
```sql
INSERT INTO users (username, password_hash, nombre, role) 
VALUES ('nombre_usuario', 'clave_segura', 'Nombre Completo', 1);
```
*Nota: La `password_hash` se maneja como texto plano en esta versión de la API.*

### Cambiar contraseña de un usuario
```sql
UPDATE users SET password_hash = 'nueva_clave' WHERE username = 'el_usuario';
```

### Cambiar el ROL de un usuario
```sql
UPDATE users SET role = 2 WHERE username = 'el_usuario';
```

### Eliminar un usuario
```sql
DELETE FROM users WHERE username = 'el_usuario';
```

---

## 3. Referencia de Roles
| ID | Nombre | Descripción |
| :--- | :--- | :--- |
| **1** | Servidor | Solo puede registrar y ver sus propios envíos (24h). |
| **2** | Coordinador | Puede ver todos los registros y exportar a Excel. |
| **3** | Admin | Acceso total y gestión (equivalente al admin global). |

---

## 4. Salir de SQLite
Para salir de la terminal interactiva, escribe:
```bash
.exit
```

> [!IMPORTANT]
> Los cambios se guardan automáticamente al ejecutar los comandos (`COMMIT`). Asegúrate de escribir bien el `username` para evitar modificar o borrar el usuario equivocado.
