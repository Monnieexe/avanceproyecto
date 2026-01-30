require('dotenv').config();
const express = require('express');
const mysql = require('mysql2/promise');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const path = require('path'); 

const app = express();
app.use(express.json());
app.use(cors());

app.use(express.static(path.join(__dirname, 'Public')));

// Ruta principal explícita (por seguridad)
app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'Public', 'index.html'));
});


const connectionConfig = process.env.MYSQL_URL || {
    host: process.env.DB_HOST || 'localhost',
    user: process.env.DB_USER || 'root',
    password: process.env.DB_PASSWORD || '',
    database: process.env.DB_NAME || 'sistemagestion',
    port: process.env.DB_PORT || 3306
};

const pool = mysql.createPool(connectionConfig);


pool.getConnection()
    .then(async conn => {
        console.log("✅ ¡Conectado a la Base de Datos!");
        
        // 1. Tabla de USUARIOS
        await conn.query(`
            CREATE TABLE IF NOT EXISTS users (
                id INT AUTO_INCREMENT PRIMARY KEY,
                username VARCHAR(255) NOT NULL,
                email VARCHAR(255) NOT NULL,
                password VARCHAR(255) NOT NULL
            )
        `);

        // 2. Tabla de RESERVAS
        await conn.query(`
            CREATE TABLE IF NOT EXISTS reservas (
                id INT AUTO_INCREMENT PRIMARY KEY,
                user_id INT,
                destino VARCHAR(255),
                precio VARCHAR(50),
                fecha_viaje VARCHAR(50)
            )
        `);

        // 3. Tabla de MENSAJES (Contacto)
        await conn.query(`
            CREATE TABLE IF NOT EXISTS mensajes (
                id INT AUTO_INCREMENT PRIMARY KEY,
                nombre VARCHAR(255),
                email VARCHAR(255),
                mensaje TEXT
            )
        `);

        console.log("✨ ¡Tablas verificadas y listas para usarse!");
        conn.release();
    })
    .catch(err => {
        console.error("❌ ERROR DE CONEXIÓN A BD:", err.message);
        console.error("👉 Si estás en local, verifica que XAMPP esté prendido.");
        console.error("👉 Si estás en Railway, verifica las Variables de Referencia.");
    });

// --- MIDDLEWARE DE SEGURIDAD (TOKEN) ---
const verifyToken = (req, res, next) => {
    const token = req.headers['authorization']?.split(' ')[1];
    if (!token) return res.status(401).json({ error: 'Acceso denegado (Falta token)' });
    try {
        const secret = process.env.JWT_SECRET || 'secreto_super_seguro';
        req.user = jwt.verify(token, secret);
        next();
    } catch (e) {
        res.status(403).json({ error: 'Token inválido o expirado' });
    }
};

// --- RUTAS DE LA API ---

// 1. Registro de Usuario
app.post('/auth/register', async (req, res) => {
    try {
        const { username, email, password } = req.body;
        // Encriptar contraseña
        const hash = await bcrypt.hash(password, 10);
        // Guardar en BD
        await pool.query('INSERT INTO users (username, email, password) VALUES (?, ?, ?)', [username, email, hash]);
        res.status(201).json({ message: 'Usuario creado exitosamente' });
    } catch (e) {
        console.error(e);
        res.status(400).json({ error: 'El usuario o correo ya existe' });
    }
});

// 2. Inicio de Sesión (Login)
app.post('/auth/login', async (req, res) => {
    try {
        const { username, password } = req.body;
        const [users] = await pool.query('SELECT * FROM users WHERE username = ?', [username]);
        
        if (!users.length || !(await bcrypt.compare(password, users[0].password))) {
            return res.status(400).json({ error: 'Usuario o contraseña incorrectos' });
        }
        
        // Crear Token
        const secret = process.env.JWT_SECRET || 'secreto_super_seguro';
        const token = jwt.sign({ id: users[0].id }, secret, { expiresIn: '2h' });
        
        res.json({ token, username });
    } catch (e) {
        res.status(500).json({ error: e.message });
    }
});

// 3. Guardar Reserva (Protegido con Token)
app.post('/api/reservas', verifyToken, async (req, res) => {
    try {
        const { destino, precio, fecha_viaje } = req.body;
        await pool.query('INSERT INTO reservas (user_id, destino, precio, fecha_viaje) VALUES (?, ?, ?, ?)', 
            [req.user.id, destino, precio, fecha_viaje]);
        res.json({ message: 'Reserva guardada' });
    } catch (e) {
        res.status(500).json({ error: 'Error al guardar la reserva' });
    }
});

// 4. Obtener Mis Reservas (Protegido)
app.get('/api/reservas', verifyToken, async (req, res) => {
    try {
        const [rows] = await pool.query('SELECT * FROM reservas WHERE user_id = ? ORDER BY id DESC', [req.user.id]);
        res.json(rows);
    } catch (e) {
        res.status(500).json({ error: 'Error al obtener reservas' });
    }
});

// 5. Eliminar Reserva (Protegido)
app.delete('/api/reservas/:id', verifyToken, async (req, res) => {
    try {
        await pool.query('DELETE FROM reservas WHERE id = ? AND user_id = ?', [req.params.id, req.user.id]);
        res.json({ message: 'Reserva eliminada' });
    } catch (e) {
        res.status(500).json({ error: 'Error al eliminar' });
    }
});

// 6. Formulario de Contacto
app.post('/api/contacto', async (req, res) => {
    try {
        const { nombre, email, mensaje } = req.body;
        console.log("📩 Mensaje recibido de:", nombre);
        await pool.query('INSERT INTO mensajes (nombre, email, mensaje) VALUES (?, ?, ?)', [nombre, email, mensaje]);
        res.json({ message: 'Mensaje enviado correctamente' });
    } catch (e) {
        console.error(e);
        res.status(500).json({ error: 'Error al guardar mensaje' });
    }
});


const PORT = process.env.PORT || 3001;


app.listen(PORT, '0.0.0.0', () => {
    console.log(`🚀 SERVIDOR CORRIENDO en el puerto ${PORT}`);
});