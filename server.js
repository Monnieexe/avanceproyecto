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

// --- 1. ARCHIVOS ---
app.use(express.static(path.join(__dirname, 'Public')));
app.get('/', (req, res) => res.sendFile(path.join(__dirname, 'Public', 'index.html')));

// --- 2. CONEXIÓN BLINDADA (USANDO LA URL MAESTRA) ---
const connectionConfig = process.env.MYSQL_URL || {
    host: process.env.MYSQLHOST || process.env.DB_HOST || 'localhost',
    user: process.env.MYSQLUSER || process.env.DB_USER || 'root',
    password: process.env.MYSQLPASSWORD || process.env.DB_PASSWORD || '',
    database: process.env.MYSQLDATABASE || process.env.DB_NAME || 'sistemagestion',
    port: process.env.MYSQLPORT || process.env.DB_PORT || 3306
};


const pool = mysql.createPool(connectionConfig);

// --- 3. VERIFICADOR DE TABLAS ---
pool.getConnection()
    .then(async conn => {
        console.log("✅ ¡CONEXIÓN EXITOSA A LA BD!");
        
        
        await conn.query(`CREATE TABLE IF NOT EXISTS users (id INT AUTO_INCREMENT PRIMARY KEY, username VARCHAR(255), email VARCHAR(255), password VARCHAR(255))`);
        await conn.query(`CREATE TABLE IF NOT EXISTS reservas (id INT AUTO_INCREMENT PRIMARY KEY, user_id INT, destino VARCHAR(255), precio VARCHAR(50), fecha_viaje VARCHAR(50))`);
        await conn.query(`CREATE TABLE IF NOT EXISTS mensajes (id INT AUTO_INCREMENT PRIMARY KEY, nombre VARCHAR(255), email VARCHAR(255), mensaje TEXT)`);

        console.log("✨ Tablas listas para recibir datos.");
        conn.release();
    })
    .catch(err => {
        console.error("❌ ERROR DE CONEXIÓN:", err.message);
    });

// --- MIDDLEWARE ---
const verifyToken = (req, res, next) => {
    const token = req.headers['authorization']?.split(' ')[1];
    if (!token) return res.status(401).json({ error: 'Falta token' });
    try {
        req.user = jwt.verify(token, process.env.JWT_SECRET || 'secreto');
        next();
    } catch (e) { res.status(403).json({ error: 'Token inválido' }); }
};

// --- RUTAS ---
app.post('/auth/register', async (req, res) => {
    try {
        const { username, email, password } = req.body;
        const hash = await bcrypt.hash(password, 10);
        await pool.query('INSERT INTO users (username, email, password) VALUES (?, ?, ?)', [username, email, hash]);
        res.status(201).json({ message: 'Usuario creado' });
    } catch (e) { 
        console.error(e); 
        res.status(400).json({ error: 'Error al registrar usuario' }); 
    }
});

app.post('/auth/login', async (req, res) => {
    try {
        const { username, password } = req.body;
        const [users] = await pool.query('SELECT * FROM users WHERE username = ?', [username]);
        if (!users.length || !(await bcrypt.compare(password, users[0].password))) 
            return res.status(400).json({ error: 'Credenciales incorrectas' });
        
        const token = jwt.sign({ id: users[0].id }, process.env.JWT_SECRET || 'secreto', { expiresIn: '2h' });
        res.json({ token, username });
    } catch (e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/reservas', verifyToken, async (req, res) => {
    try {
        const { destino, precio, fecha_viaje } = req.body;
        await pool.query('INSERT INTO reservas (user_id, destino, precio, fecha_viaje) VALUES (?, ?, ?, ?)', 
            [req.user.id, destino, precio, fecha_viaje]);
        res.json({ message: 'Guardado' });
    } catch (e) { res.status(500).json({ error: 'Error al reservar' }); }
});

app.get('/api/reservas', verifyToken, async (req, res) => {
    const [rows] = await pool.query('SELECT * FROM reservas WHERE user_id = ?', [req.user.id]);
    res.json(rows);
});

app.delete('/api/reservas/:id', verifyToken, async (req, res) => {
    await pool.query('DELETE FROM reservas WHERE id = ? AND user_id = ?', [req.params.id, req.user.id]);
    res.json({ message: 'Eliminado' });
});

app.post('/api/contacto', async (req, res) => {
    try {
        const { nombre, email, mensaje } = req.body;
        await pool.query('INSERT INTO mensajes (nombre, email, mensaje) VALUES (?, ?, ?)', [nombre, email, mensaje]);
        res.json({ message: 'Enviado' });
    } catch (e) { res.status(500).json({ error: 'Error al enviar' }); }
});


const PORT = process.env.PORT || 3001;
app.listen(PORT, '0.0.0.0', () => {
    console.log(`🚀 SERVIDOR LISTO en el puerto ${PORT}`);
});
