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
  list                            Muestra todos los usuarios
  add <user> <pass> <name> <role> Añade un usuario (role: register | admin)
  delete <user>                   Elimina un usuario
  role <user> <role>              Cambia el rol (register | admin)
  pass <user> <new-pass>          Cambia la contraseña
  bans                            Lista IPs baneadas
  unban <ip>                      Desbanea una IP
`);
    process.exit(0);
}

const VALID_ROLES = ['register', 'admin'];

try {
    switch (command) {
        case 'list':
            const users = db.prepare('SELECT id, username, name, role FROM users').all();
            console.table(users);
            break;

        case 'add': {
            const [username, password, name, role = 'register'] = args.slice(1);
            if (!username || !password || !name) {
                console.error('Error: Faltan argumentos (user, pass, name)');
                process.exit(1);
            }
            if (!VALID_ROLES.includes(role)) {
                console.error(`Error: role debe ser uno de: ${VALID_ROLES.join(', ')}`);
                process.exit(1);
            }
            db.prepare('INSERT INTO users (username, password, name, role) VALUES (?, ?, ?, ?)')
                .run(username, password, name, role);
            console.log(`✅ Usuario ${username} creado con rol '${role}'`);
            break;
        }

        case 'delete': {
            const userToDelete = args[1];
            if (!userToDelete) {
                console.error('Error: Usuario requerido');
                process.exit(1);
            }
            const info = db.prepare('DELETE FROM users WHERE username = ?').run(userToDelete);
            if (info.changes > 0) console.log(`✅ Usuario ${userToDelete} eliminado`);
            else console.log('⚠️ Usuario no encontrado');
            break;
        }

        case 'role': {
            const userRole = args[1];
            const newRole = args[2];
            if (!userRole || !newRole) {
                console.error('Error: Usuario y rol requeridos');
                process.exit(1);
            }
            if (!VALID_ROLES.includes(newRole)) {
                console.error(`Error: role debe ser uno de: ${VALID_ROLES.join(', ')}`);
                process.exit(1);
            }
            const info = db.prepare('UPDATE users SET role = ? WHERE username = ?').run(newRole, userRole);
            if (info.changes > 0) console.log(`✅ Rol de ${userRole} actualizado a '${newRole}'`);
            else console.log('⚠️ Usuario no encontrado');
            break;
        }

        case 'pass': {
            const userPass = args[1];
            const newPass = args[2];
            if (!userPass || !newPass) {
                console.error('Error: Usuario y clave requeridos');
                process.exit(1);
            }
            db.prepare('UPDATE users SET password = ? WHERE username = ?').run(newPass, userPass);
            console.log(`✅ Contraseña de ${userPass} actualizada`);
            break;
        }

        case 'bans': {
            const activeBans = db.prepare('SELECT ip, expires_at FROM bans').all();
            if (activeBans.length === 0) console.log('✅ No hay IPs baneadas');
            else console.table(activeBans);
            break;
        }

        case 'unban': {
            const ipToUnban = args[1];
            if (!ipToUnban) {
                console.error('Error: IP requerida');
                process.exit(1);
            }
            const banInfo = db.prepare('DELETE FROM bans WHERE ip = ?').run(ipToUnban);
            if (banInfo.changes > 0) console.log(`✅ IP ${ipToUnban} desbaneada`);
            else console.log('⚠️ La IP no estaba baneada');
            break;
        }

        default:
            console.log('Comando no reconocido');
    }
} catch (error) {
    console.error('❌ Error:', error.message);
} finally {
    db.close();
}