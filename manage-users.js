require('dotenv').config();
const Database = require('better-sqlite3');
const path = require('path');

const dbPath = process.env.DATABASE_PATH || path.join(__dirname, 'database.sqlite');
const db = new Database(dbPath);

const args = process.argv.slice(2);
const command = args[0];

if (!command) {
    console.log(`
Uso: node manage-users.js <comando> [opciones]

Comandos disponibles:
  list                      Muestra todos los usuarios
  add <user> <pass> <nom> <role>  Añade un nuevo usuario
  delete <user>             Elimina un usuario
  role <user> <role>        Cambia el rol de un usuario
  pass <user> <new-pass>    Cambia la contraseña
  bans                      Lista IPs baneadas
  unban <ip>                Desbanea una IP
`);
    process.exit(0);
}

try {
    switch (command) {
        case 'list':
            const users = db.prepare('SELECT id, username, nombre, role FROM users').all();
            console.table(users);
            break;

        case 'add':
            const [username, password, nombre, role] = args.slice(1);
            if (!username || !password || !nombre) {
                console.error('Error: Faltan argumentos (user, pass, nombre)');
                process.exit(1);
            }
            db.prepare('INSERT INTO users (username, password, nombre, role) VALUES (?, ?, ?, ?)')
                .run(username, password, nombre, parseInt(role) || 1);
            console.log(`✅ Usuario ${username} creado con éxito`);
            break;

        case 'delete':
            const userToDelete = args[1];
            if (!userToDelete) {
                console.error('Error: Usuario requerido');
                process.exit(1);
            }
            const info = db.prepare('DELETE FROM users WHERE username = ?').run(userToDelete);
            if (info.changes > 0) console.log(`✅ Usuario ${userToDelete} eliminado`);
            else console.log('⚠️ Usuario no encontrado');
            break;

        case 'role':
            const userRole = args[1];
            const newRole = args[2];
            if (!userRole || !newRole) {
                console.error('Error: Usuario y rol requeridos');
                process.exit(1);
            }
            db.prepare('UPDATE users SET role = ? WHERE username = ?').run(parseInt(newRole), userRole);
            console.log(`✅ Rol de ${userRole} actualizado a ${newRole}`);
            break;

        case 'pass':
            const userPass = args[1];
            const newPass = args[2];
            if (!userPass || !newPass) {
                console.error('Error: Usuario y clave requeridos');
                process.exit(1);
            }
            db.prepare('UPDATE users SET password = ? WHERE username = ?').run(newPass, userPass);
            console.log(`✅ Contraseña de ${userPass} actualizada`);
            break;

        case 'bans':
            const activeBans = db.prepare('SELECT ip, expires_at FROM bans').all();
            if (activeBans.length === 0) console.log('✅ No hay IPs baneadas actualmente');
            else console.table(activeBans);
            break;

        case 'unban':
            const ipToUnban = args[1];
            if (!ipToUnban) {
                console.error('Error: IP requerida');
                process.exit(1);
            }
            const banInfo = db.prepare('DELETE FROM bans WHERE ip = ?').run(ipToUnban);
            if (banInfo.changes > 0) console.log(`✅ IP ${ipToUnban} desbaneada con éxito`);
            else console.log('⚠️ La IP no estaba en la lista de baneos');
            break;

        default:
            console.log('Comando no reconocido');
    }
} catch (error) {
    console.error('❌ Error:', error.message);
} finally {
    db.close();
}
