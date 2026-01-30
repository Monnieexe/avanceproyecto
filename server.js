require('dotenv').config();
const express = require('express');
const mysql = require('mysql2/promise');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cors = require('cors');

const app = express();
app.use(express.json());

const path = require('path'); 



app.use(express.static(__dirname));
app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'index.html'));
});


const pool = mysql.createPool({
    host: process.env.DB_HOST,
    user: process.env.DB_USER,
    password: process.env.DB_PASSWORD,
    database: process.env.DB_NAME
});

// Prueba de conexión al arrancar
pool.getConnection()
    .then(conn => {
        console.log("✅ ¡Conectado a la Base de Datos!");
        conn.release();
    })
    .catch(err => {
        console.error("❌ ERROR DE BASE DE DATOS:", err.message);
        console.error("👉 Revisa tu archivo .env y la contraseña.");
    });

// Middleware de seguridad
const verifyToken = (req, res, next) => {
    const token = req.headers['authorization']?.split(' ')[1];
    if (!token) return res.status(401).json({ error: 'Falta token' });
    try { req.user = jwt.verify(token, process.env.JWT_SECRET); next(); }
    catch (e) { res.status(403).json({ error: 'Token inválido' }); }
};

// --- RUTAS ---

// Registro
app.post('/auth/register', async (req, res) => {
    try {
        const { username, email, password } = req.body;
        const hash = await bcrypt.hash(password, 10);
        await pool.query('INSERT INTO users (username, email, password) VALUES (?, ?, ?)', [username, email, hash]);
        res.status(201).json({ message: 'Usuario creado' });
    } catch (e) { res.status(400).json({ error: 'El usuario ya existe' }); }
});

// Login
app.post('/auth/login', async (req, res) => {
    try {
        const { username, password } = req.body;
        const [users] = await pool.query('SELECT * FROM users WHERE username = ?', [username]);
        if (!users.length || !(await bcrypt.compare(password, users[0].password))) 
            return res.status(400).json({ error: 'Usuario o contraseña incorrectos' });
        
        const token = jwt.sign({ id: users[0].id }, process.env.JWT_SECRET, { expiresIn: '2h' });
        res.json({ token, username });
    } catch (e) { res.status(500).json({ error: e.message }); }
});

// Reservas
app.post('/api/reservas', verifyToken, async (req, res) => {
    try {
        const { destino, precio, fecha_viaje } = req.body;
        await pool.query('INSERT INTO reservas (user_id, destino, precio, fecha_viaje) VALUES (?, ?, ?, ?)', 
            [req.user.id, destino, precio, fecha_viaje]);
        res.json({ message: 'Guardado' });
    } catch (e) { res.status(500).json({ error: 'Error al reservar' }); }
});

app.get('/api/reservas', verifyToken, async (req, res) => {
    const [rows] = await pool.query('SELECT * FROM reservas WHERE user_id = ? ORDER BY fecha_viaje ASC', [req.user.id]);
    res.json(rows);
});

app.delete('/api/reservas/:id', verifyToken, async (req, res) => {
    await pool.query('DELETE FROM reservas WHERE id = ? AND user_id = ?', [req.params.id, req.user.id]);
    res.json({ message: 'Eliminado' });
});

// Contacto
app.post('/api/contacto', async (req, res) => {
    try {
        const { nombre, email, mensaje } = req.body;
        console.log("📩 Nuevo mensaje de:", nombre);
        await pool.query('INSERT INTO mensajes (nombre, email, mensaje) VALUES (?, ?, ?)', [nombre, email, mensaje]);
        res.json({ message: 'Enviado' });
    } catch (e) { console.error(e); res.status(500).json({ error: 'Error al guardar mensaje' }); }
});

// --- ARRANQUE EN PUERTO 3001 ---
const PORT = 3001;
app.listen(PORT, () => {
    console.log(`🚀 SERVIDOR LISTO en http://localhost:${PORT}`);
    console.log("👉 Ve a tu navegador y prueba entrar.");
});