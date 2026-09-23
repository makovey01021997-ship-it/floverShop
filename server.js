const express = require('express');
const session = require('express-session');
const sqlite3 = require('sqlite3').verbose();
const bcrypt = require('bcryptjs');
const path = require('path');

const app = express();
const db = new sqlite3.Database('./shop.db');

app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(express.static(path.join(__dirname, 'public')));

app.use(session({
    secret: 'flower_secret_key_123',
    resave: false,
    saveUninitialized: false
}));

// --- БАЗА ДАНИХ (ІНІЦІАЛІЗАЦІЯ) ---
db.serialize(() => {
    // Таблиця користувачів
    db.run(`CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT,
        email TEXT UNIQUE,
        password TEXT,
        role TEXT DEFAULT 'user'
    )`);

    // Таблиця товарів
    db.run(`CREATE TABLE IF NOT EXISTS products (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        title TEXT,
        price REAL,
        image TEXT
    )`);

    // Таблиця замовлень з розширеними полями доставки та оплати
    db.run(`CREATE TABLE IF NOT EXISTS orders (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER,
        items TEXT,
        total_price REAL,
        delivery_type TEXT,
        delivery_address TEXT,
        delivery_date TEXT,
        delivery_time TEXT,
        payment_method TEXT,
        status TEXT DEFAULT 'Нове',
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    )`);

    // Адмін за замовчуванням (admin@shop.com / admin123)
    const adminEmail = 'admin@shop.com';
    db.get("SELECT * FROM users WHERE email = ?", [adminEmail], (err, user) => {
        if (!user) {
            const hash = bcrypt.hashSync('admin123', 10);
            db.run("INSERT INTO users (name, email, password, role) VALUES (?, ?, ?, ?)", 
                   ['Адміністратор', adminEmail, hash, 'admin']);
            console.log('Адміністратора створено: admin@shop.com / admin123');
        }
    });

    // Тестові товари
    db.get("SELECT count(*) as count FROM products", (err, row) => {
        if (row.count === 0) {
            db.run("INSERT INTO products (title, price, image) VALUES ('Букет червоних троянд', 1200, 'https://images.unsplash.com/photo-1518709268805-4e9042af9f23?w=400')");
            db.run("INSERT INTO products (title, price, image) VALUES ('Ніжні півонії', 1500, 'https://images.unsplash.com/photo-1563241527-3004b7be0ffd?w=400')");
            db.run("INSERT INTO products (title, price, image) VALUES ('Тюльпани весняні', 800, 'https://images.unsplash.com/photo-1520763185298-1b434c919102?w=400')");
        }
    });
});

// --- API АВТОРИЗАЦІЇ ---
app.post('/api/register', async (req, res) => {
    const { name, email, password } = req.body;
    const hash = await bcrypt.hash(password, 10);
    db.run("INSERT INTO users (name, email, password) VALUES (?, ?, ?)", [name, email, hash], function(err) {
        if (err) return res.status(400).json({ error: 'Email вже використовується' });
        req.session.userId = this.lastID;
        req.session.role = 'user';
        req.session.userName = name;
        res.json({ success: true });
    });
});

app.post('/api/login', (req, res) => {
    const { email, password } = req.body;
    db.get("SELECT * FROM users WHERE email = ?", [email], async (err, user) => {
        if (!user || !(await bcrypt.compare(password, user.password))) {
            return res.status(400).json({ error: 'Невірний email або пароль' });
        }
        req.session.userId = user.id;
        req.session.role = user.role;
        req.session.userName = user.name;
        res.json({ success: true, role: user.role });
    });
});

app.get('/api/logout', (req, res) => {
    req.session.destroy();
    res.json({ success: true });
});

app.get('/api/me', (req, res) => {
    if (!req.session.userId) return res.status(401).json({ error: 'Не авторизований' });
    res.json({ id: req.session.userId, name: req.session.userName, role: req.session.role });
});

// --- API ТОВАРІВ ТА ЗАМОВЛЕНЬ ---
app.get('/api/products', (req, res) => {
    db.all("SELECT * FROM products", [], (err, rows) => res.json(rows));
});

app.post('/api/orders', (req, res) => {
    if (!req.session.userId) return res.status(401).json({ error: 'Увійдіть в акаунт для оформлення замовлення' });
    const { items, totalPrice, deliveryType, deliveryAddress, deliveryDate, deliveryTime, paymentMethod } = req.body;
    
    db.run(`INSERT INTO orders (user_id, items, total_price, delivery_type, delivery_address, delivery_date, delivery_time, payment_method) 
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
           [req.session.userId, JSON.stringify(items), totalPrice, deliveryType, deliveryAddress, deliveryDate, deliveryTime, paymentMethod], 
           function(err) {
               if (err) return res.status(500).json({ error: 'Помилка при збереженні замовлення' });
               res.json({ success: true, orderId: this.lastID });
           });
});

app.get('/api/my-orders', (req, res) => {
    if (!req.session.userId) return res.status(401).json({ error: 'Не авторизований' });
    db.all("SELECT * FROM orders WHERE user_id = ? ORDER BY id DESC", [req.session.userId], (err, rows) => res.json(rows));
});

// --- API АДМІН-ПАНЕЛІ ---
const checkAdmin = (req, res, next) => {
    if (req.session.role !== 'admin') return res.status(403).json({ error: 'Доступ заборонено' });
    next();
};

app.get('/api/admin/orders', checkAdmin, (req, res) => {
    db.all(`SELECT orders.*, users.name, users.email FROM orders 
            JOIN users ON orders.user_id = users.id 
            ORDER BY orders.id DESC`, [], (err, rows) => res.json(rows));
});

app.post('/api/admin/products', checkAdmin, (req, res) => {
    const { title, price, image } = req.body;
    db.run("INSERT INTO products (title, price, image) VALUES (?, ?, ?)", [title, price, image], function(err) {
        res.json({ success: true });
    });
});

// Видалення товару
app.delete('/api/admin/products/:id', checkAdmin, (req, res) => {
    db.run("DELETE FROM products WHERE id = ?", [req.params.id], function(err) {
        if (err) return res.status(500).json({ error: 'Помилка видалення' });
        res.json({ success: true });
    });
});

app.listen(3000, () => console.log('Сервер запущено: http://localhost:3000'));