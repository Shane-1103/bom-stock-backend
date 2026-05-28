require("dotenv").config();

const express = require("express");
const cors = require("cors");
const mysql = require("mysql2/promise");
const multer = require("multer");
const path = require("path");
const fs = require("fs");
const dayjs = require("dayjs");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");

const app = express();
const PORT = process.env.PORT || 4000;
const JWT_SECRET = process.env.JWT_SECRET || "change-this-secret-key";

app.use(cors());
app.use(express.json({ limit: "50mb" }));
app.use("/uploads", express.static(path.join(__dirname, "uploads")));

const pool = mysql.createPool({
  host: process.env.DB_HOST || "localhost",
  port: Number(process.env.DB_PORT || 3306),
  user: process.env.DB_USER || "root",
  password: process.env.DB_PASSWORD || "",
  database: process.env.DB_NAME || "bom_stock_app",
  waitForConnections: true,
  connectionLimit: 10,
});

function ensureDir(dir) {
  if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
}

async function query(sql, params = []) {
  const [rows] = await pool.execute(sql, params);
  return rows;
}

const ROLE_PERMISSIONS = {
  OWNER: ["*"],
  ADMIN: ["orders:read","orders:create","orders:update","orders:ship","inventory:read","inventory:update","inventory:transfer","products:read","products:create","products:update","bom:read","bom:update","reports:read","reports:print","chat:read","chat:send","users:read"],
  SALES: ["orders:read","orders:create","orders:update","products:read","inventory:read","reports:read","chat:read","chat:send"],
  WAREHOUSE: ["orders:read","orders:ship","inventory:read","inventory:update","inventory:transfer","products:read","reports:read","chat:read","chat:send"],
  STAFF: ["orders:read","products:read","inventory:read","chat:read","chat:send"]
};

function authRequired(req, res, next) {
  try {
    const header = req.headers.authorization || "";
    const token = header.startsWith("Bearer ") ? header.slice(7) : null;
    if (!token) return res.status(401).json({ error: "Missing login token" });
    req.user = jwt.verify(token, JWT_SECRET);
    next();
  } catch {
    res.status(401).json({ error: "Invalid or expired token" });
  }
}

function can(role, permission) {
  const p = ROLE_PERMISSIONS[role] || [];
  return p.includes("*") || p.includes(permission);
}

function requirePermission(permission) {
  return (req, res, next) => {
    if (!req.user) return res.status(401).json({ error: "Please login first" });
    if (!can(req.user.role, permission)) return res.status(403).json({ error: "Permission denied", required_permission: permission });
    next();
  };
}

app.get("/api/health", (req, res) => res.json({ ok: true, app: "BOM Stock App API" }));

app.get("/api/db-test", async (req, res) => {
  try {
    const rows = await query("SELECT 1 AS ok");
    res.json({ ok: true, db: rows[0] });
  } catch (err) {
    res.status(500).json({ ok: false, error: err.message });
  }
});


app.get("/api/setup-db", async (req, res) => {
  try {
    const statements = [
      `CREATE TABLE IF NOT EXISTS users (
        id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
        name VARCHAR(120) NOT NULL,
        email VARCHAR(180) NOT NULL UNIQUE,
        password_hash VARCHAR(255) NOT NULL,
        role ENUM('OWNER', 'ADMIN', 'SALES', 'WAREHOUSE', 'STAFF') NOT NULL DEFAULT 'STAFF',
        status ENUM('ACTIVE', 'INACTIVE') NOT NULL DEFAULT 'ACTIVE',
        created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
        updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
      )`,

      `CREATE TABLE IF NOT EXISTS sales_agents (
        id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
        name VARCHAR(180) NOT NULL,
        phone VARCHAR(80) NULL,
        email VARCHAR(180) NULL,
        remark TEXT NULL,
        status ENUM('ACTIVE', 'INACTIVE') NOT NULL DEFAULT 'ACTIVE',
        created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
        updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
      )`,
      `CREATE TABLE IF NOT EXISTS customers (
        id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
        customer_code VARCHAR(80) NULL UNIQUE,
        name VARCHAR(180) NOT NULL,
        phone VARCHAR(80) NULL,
        email VARCHAR(180) NULL,
        address TEXT NULL,
        platform ENUM('GENERAL', 'SHOPEE', 'TIKTOK', 'SALESMAN', 'OTHER') NOT NULL DEFAULT 'GENERAL',
        sales_agent_id BIGINT UNSIGNED NULL,
        shop_name VARCHAR(180) NULL,
        remark TEXT NULL,
        status ENUM('ACTIVE', 'INACTIVE') NOT NULL DEFAULT 'ACTIVE',
        created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
        updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
      )`,
      `CREATE TABLE IF NOT EXISTS warehouses (
        id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
        name VARCHAR(120) NOT NULL,
        code VARCHAR(50) NOT NULL UNIQUE,
        address TEXT NULL,
        status ENUM('ACTIVE', 'INACTIVE') NOT NULL DEFAULT 'ACTIVE',
        created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
        updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
      )`,
      `CREATE TABLE IF NOT EXISTS products (
        id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
        sku VARCHAR(100) NOT NULL UNIQUE,
        name VARCHAR(180) NOT NULL,
        category VARCHAR(120) NULL,
        vehicle_model VARCHAR(120) NULL,
        sticker_code VARCHAR(120) NULL,
        cover_color VARCHAR(120) NULL,
        price DECIMAL(12,2) NOT NULL DEFAULT 0.00,
        cost DECIMAL(12,2) NOT NULL DEFAULT 0.00,
        image_url VARCHAR(500) NULL,
        is_component BOOLEAN NOT NULL DEFAULT FALSE,
        status ENUM('ACTIVE', 'INACTIVE') NOT NULL DEFAULT 'ACTIVE',
        created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
        updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
      )`,
      `CREATE TABLE IF NOT EXISTS bom_items (
        id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
        product_id BIGINT UNSIGNED NOT NULL,
        component_product_id BIGINT UNSIGNED NOT NULL,
        quantity DECIMAL(12,3) NOT NULL DEFAULT 1.000,
        unit VARCHAR(40) NOT NULL DEFAULT 'pcs',
        created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
        updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
        INDEX idx_bom_product_id (product_id),
        INDEX idx_bom_component_product_id (component_product_id)
      )`,
      `CREATE TABLE IF NOT EXISTS inventory (
        id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
        product_id BIGINT UNSIGNED NOT NULL,
        warehouse_id BIGINT UNSIGNED NOT NULL,
        qty_on_hand DECIMAL(12,3) NOT NULL DEFAULT 0.000,
        qty_reserved DECIMAL(12,3) NOT NULL DEFAULT 0.000,
        qty_available DECIMAL(12,3) GENERATED ALWAYS AS (qty_on_hand - qty_reserved) STORED,
        created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
        updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
        UNIQUE KEY unique_product_warehouse (product_id, warehouse_id)
      )`,
      `CREATE TABLE IF NOT EXISTS stock_movements (
        id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
        product_id BIGINT UNSIGNED NOT NULL,
        from_warehouse_id BIGINT UNSIGNED NULL,
        to_warehouse_id BIGINT UNSIGNED NULL,
        qty DECIMAL(12,3) NOT NULL,
        type ENUM('IN', 'OUT', 'TRANSFER', 'ADJUSTMENT', 'ORDER_RESERVED', 'ORDER_RELEASED') NOT NULL,
        reference_no VARCHAR(120) NULL,
        remark TEXT NULL,
        created_by BIGINT UNSIGNED NULL,
        created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
      )`,



      `CREATE TABLE IF NOT EXISTS promotion_rules (
        id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
        promotion_id BIGINT UNSIGNED NOT NULL,
        rule_type ENUM('BUY_X_FREE_Y') NOT NULL DEFAULT 'BUY_X_FREE_Y',
        target_type ENUM('VEHICLE_MODEL','STICKER_CODE','CATEGORY','PRODUCT') NOT NULL DEFAULT 'VEHICLE_MODEL',
        target_value VARCHAR(180) NOT NULL,
        buy_qty DECIMAL(12,3) NOT NULL DEFAULT 0,
        free_qty DECIMAL(12,3) NOT NULL DEFAULT 0,
        free_product_id BIGINT UNSIGNED NULL,
        status ENUM('ACTIVE','INACTIVE') NOT NULL DEFAULT 'ACTIVE',
        created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
      )`,
      `CREATE TABLE IF NOT EXISTS inventory_operations (
        id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
        operation_no VARCHAR(120) NOT NULL UNIQUE,
        operation_type ENUM('IN','OUT','TRANSFER','ADJUSTMENT') NOT NULL,
        from_warehouse_id BIGINT UNSIGNED NULL,
        to_warehouse_id BIGINT UNSIGNED NULL,
        operation_date DATE NOT NULL,
        reference_no VARCHAR(120) NULL,
        remark VARCHAR(5000) NULL,
        created_by BIGINT UNSIGNED NULL,
        created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
      )`,
      `CREATE TABLE IF NOT EXISTS inventory_operation_items (
        id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
        operation_id BIGINT UNSIGNED NOT NULL,
        product_id BIGINT UNSIGNED NOT NULL,
        qty DECIMAL(12,3) NOT NULL,
        batch_no VARCHAR(120) NULL,
        remark VARCHAR(1000) NULL,
        created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
      )`,
      `CREATE TABLE IF NOT EXISTS vehicle_models (
        id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
        name VARCHAR(120) NOT NULL UNIQUE,
        remark TEXT NULL,
        status ENUM('ACTIVE', 'INACTIVE') NOT NULL DEFAULT 'ACTIVE',
        created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
        updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
      )`,
      `CREATE TABLE IF NOT EXISTS sticker_codes (
        id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
        code VARCHAR(120) NOT NULL UNIQUE,
        name VARCHAR(180) NULL,
        remark TEXT NULL,
        status ENUM('ACTIVE', 'INACTIVE') NOT NULL DEFAULT 'ACTIVE',
        created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
        updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
      )`,
      `CREATE TABLE IF NOT EXISTS cover_colors (
        id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
        name VARCHAR(120) NOT NULL UNIQUE,
        color_code VARCHAR(80) NULL,
        remark TEXT NULL,
        status ENUM('ACTIVE', 'INACTIVE') NOT NULL DEFAULT 'ACTIVE',
        created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
        updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
      )`,
      `CREATE TABLE IF NOT EXISTS product_categories (
        id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
        name VARCHAR(120) NOT NULL UNIQUE,
        remark TEXT NULL,
        status ENUM('ACTIVE', 'INACTIVE') NOT NULL DEFAULT 'ACTIVE',
        created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
        updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
      )`,
      `CREATE TABLE IF NOT EXISTS promotions (
        id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
        promo_code VARCHAR(100) NOT NULL UNIQUE,
        promo_name VARCHAR(180) NOT NULL,
        platform ENUM('ALL', 'SHOPEE', 'TIKTOK', 'SALESMAN SO', 'OTHER') NOT NULL DEFAULT 'ALL',
        start_date DATE NOT NULL,
        end_date DATE NOT NULL,
        package_price DECIMAL(12,2) NOT NULL DEFAULT 0.00,
        remark VARCHAR(5000) NULL,
        status ENUM('ACTIVE', 'INACTIVE') NOT NULL DEFAULT 'ACTIVE',
        created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
        updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
      )`,
      `CREATE TABLE IF NOT EXISTS promotion_items (
        id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
        promotion_id BIGINT UNSIGNED NOT NULL,
        product_id BIGINT UNSIGNED NOT NULL,
        qty DECIMAL(12,3) NOT NULL DEFAULT 1.000,
        foc BOOLEAN NOT NULL DEFAULT FALSE,
        remark VARCHAR(1000) NULL,
        created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
        INDEX idx_promotion_items_promo (promotion_id),
        INDEX idx_promotion_items_product (product_id)
      )`,
      `CREATE TABLE IF NOT EXISTS announcements (
        id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
        title VARCHAR(180) NOT NULL,
        message VARCHAR(5000) NOT NULL,
        priority ENUM('NORMAL', 'IMPORTANT', 'URGENT') NOT NULL DEFAULT 'NORMAL',
        start_date DATE NULL,
        end_date DATE NULL,
        status ENUM('ACTIVE', 'INACTIVE') NOT NULL DEFAULT 'ACTIVE',
        created_by BIGINT UNSIGNED NULL,
        created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
        updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
      )`,
      `CREATE TABLE IF NOT EXISTS order_item_status_options (
        id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
        name VARCHAR(80) NOT NULL UNIQUE,
        sort_order INT NOT NULL DEFAULT 0,
        is_shipped BOOLEAN NOT NULL DEFAULT FALSE,
        status ENUM('ACTIVE', 'INACTIVE') NOT NULL DEFAULT 'ACTIVE',
        created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
        updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
      )`,
      `CREATE TABLE IF NOT EXISTS orders (
        id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
        order_id VARCHAR(120) NOT NULL UNIQUE,
        order_date DATE NOT NULL DEFAULT (CURRENT_DATE),
        so_number VARCHAR(120) NULL UNIQUE,
        do_number VARCHAR(120) NULL,
        promotion_id BIGINT UNSIGNED NULL,
        order_type ENUM('SALESMAN SO', 'SHOPEE', 'TIKTOK', 'OTHER') NOT NULL,
        tracking_number VARCHAR(180) NULL UNIQUE,
        customer_id BIGINT UNSIGNED NULL,
        shop_name VARCHAR(180) NULL,
        customer_name VARCHAR(180) NULL,
        status ENUM('Draft', 'Pending', 'Confirmed', 'Packed', 'Partial Shipped', 'Shipped', 'Completed', 'Cancelled') NOT NULL DEFAULT 'Pending',
        deadline_ship_date DATE NULL,
        warehouse_id BIGINT UNSIGNED NULL,
        total DECIMAL(12,2) NOT NULL DEFAULT 0.00,
        remark TEXT NULL,
        created_by BIGINT UNSIGNED NULL,
        created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
        updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
      )`,
      `CREATE TABLE IF NOT EXISTS order_items (
        id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
        order_id BIGINT UNSIGNED NOT NULL,
        product_id BIGINT UNSIGNED NOT NULL,
        qty DECIMAL(12,3) NOT NULL DEFAULT 1.000,
        price DECIMAL(12,2) NOT NULL DEFAULT 0.00,
        discount DECIMAL(12,2) NOT NULL DEFAULT 0.00,
        foc BOOLEAN NOT NULL DEFAULT FALSE,
        item_status VARCHAR(80) NOT NULL DEFAULT 'Pending',
        shipped_date DATE NULL,
        remark VARCHAR(5000) NULL,
        created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
        updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
      )`,
      `CREATE TABLE IF NOT EXISTS order_shipments (
        id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
        order_id BIGINT UNSIGNED NOT NULL,
        tracking_number VARCHAR(180) NOT NULL,
        ship_date DATE NOT NULL,
        ship_time TIME NOT NULL,
        shipped_qty DECIMAL(12,3) NOT NULL DEFAULT 0.000,
        courier VARCHAR(120) NULL,
        created_by BIGINT UNSIGNED NULL,
        created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
      )`,
      `CREATE TABLE IF NOT EXISTS order_item_media (
        id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
        order_item_id BIGINT UNSIGNED NOT NULL,
        media_type ENUM('photo', 'video') NOT NULL,
        file_url VARCHAR(500) NOT NULL,
        file_name VARCHAR(255) NULL,
        file_size BIGINT UNSIGNED NULL,
        mime_type VARCHAR(120) NULL,
        uploaded_by BIGINT UNSIGNED NULL,
        uploaded_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
      )`,
      `CREATE TABLE IF NOT EXISTS shipment_reports (
        id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
        report_no VARCHAR(120) NOT NULL UNIQUE,
        date_from DATE NULL,
        date_to DATE NULL,
        order_type ENUM('SALESMAN SO', 'SHOPEE', 'TIKTOK', 'OTHER') NULL,
        shop_name VARCHAR(180) NULL,
        generated_by BIGINT UNSIGNED NULL,
        generated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
      )`,
      `CREATE TABLE IF NOT EXISTS chat_rooms (
        id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
        room_name VARCHAR(180) NOT NULL,
        room_type ENUM('GENERAL', 'ORDER', 'WAREHOUSE') NOT NULL DEFAULT 'GENERAL',
        order_id BIGINT UNSIGNED NULL,
        created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
      )`,
      `CREATE TABLE IF NOT EXISTS chat_messages (
        id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
        room_id BIGINT UNSIGNED NOT NULL,
        sender_id BIGINT UNSIGNED NULL,
        message TEXT NOT NULL,
        attachment_url VARCHAR(500) NULL,
        created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
      )`,
      `CREATE TABLE IF NOT EXISTS audit_logs (
        id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
        user_id BIGINT UNSIGNED NULL,
        action VARCHAR(120) NOT NULL,
        module VARCHAR(120) NOT NULL,
        record_id VARCHAR(120) NULL,
        before_json JSON NULL,
        after_json JSON NULL,
        created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
      )`
    ];

    for (const sql of statements) {
      await pool.execute(sql);
    }


    try {
      await pool.execute("ALTER TABLE orders ADD COLUMN tracking_number VARCHAR(180) NULL AFTER order_type");
    } catch (e) {
      if (!String(e.message).includes("Duplicate column")) throw e;
    }

    try {
      await pool.execute("ALTER TABLE orders ADD COLUMN customer_id BIGINT UNSIGNED NULL AFTER tracking_number");
    } catch (e) {
      if (!String(e.message).includes("Duplicate column")) throw e;
    }



    try {
      await pool.execute("ALTER TABLE orders ADD COLUMN promotion_id BIGINT UNSIGNED NULL AFTER do_number");
    } catch (e) {
      if (!String(e.message).includes("Duplicate column")) throw e;
    }


    const productVariantAlterStatements = [
      "ALTER TABLE products ADD COLUMN vehicle_model VARCHAR(120) NULL AFTER category",
      "ALTER TABLE products ADD COLUMN sticker_code VARCHAR(120) NULL AFTER vehicle_model",
      "ALTER TABLE products ADD COLUMN cover_color VARCHAR(120) NULL AFTER sticker_code"
    ];
    for (const sql of productVariantAlterStatements) {
      try {
        await pool.execute(sql);
      } catch (e) {
        const msg = String(e.message || "");
        if (!msg.includes("Duplicate column")) throw e;
      }
    }

    const orderV2AlterStatements = [
      "ALTER TABLE orders ADD COLUMN order_date DATE NOT NULL DEFAULT (CURRENT_DATE) AFTER order_id",
      "ALTER TABLE orders ADD COLUMN so_number VARCHAR(120) NULL AFTER order_date",
      "ALTER TABLE orders ADD COLUMN do_number VARCHAR(120) NULL AFTER so_number",
      "ALTER TABLE order_items ADD COLUMN discount DECIMAL(12,2) NOT NULL DEFAULT 0.00 AFTER price",
      "ALTER TABLE order_items ADD COLUMN foc BOOLEAN NOT NULL DEFAULT FALSE AFTER discount",
      "ALTER TABLE order_items ADD COLUMN item_status VARCHAR(80) NOT NULL DEFAULT 'Pending' AFTER foc",
      "ALTER TABLE order_items ADD COLUMN shipped_date DATE NULL AFTER item_status",
      "ALTER TABLE order_items MODIFY COLUMN remark VARCHAR(5000) NULL"
    ];
    for (const sql of orderV2AlterStatements) {
      try {
        await pool.execute(sql);
      } catch (e) {
        const msg = String(e.message || "");
        if (!msg.includes("Duplicate column") && !msg.includes("check that column/key exists")) throw e;
      }
    }

    await pool.execute(`INSERT IGNORE INTO order_item_status_options (name, sort_order, is_shipped) VALUES
      ('Pending', 1, FALSE),
      ('Preparing', 2, FALSE),
      ('Packed', 3, FALSE),
      ('Partial Shipped', 4, FALSE),
      ('Shipped', 5, TRUE),
      ('Completed', 6, TRUE),
      ('Cancelled', 7, FALSE)`);



    try {
      await pool.execute("ALTER TABLE customers ADD COLUMN sales_agent_id BIGINT UNSIGNED NULL AFTER platform");
    } catch (e) {
      if (!String(e.message).includes("Duplicate column")) throw e;
    }

    const uniqueIndexStatements = [
      "CREATE UNIQUE INDEX unique_order_so_number ON orders (so_number)",
      "CREATE UNIQUE INDEX unique_order_tracking_number ON orders (tracking_number)"
    ];
    for (const sql of uniqueIndexStatements) {
      try {
        await pool.execute(sql);
      } catch (e) {
        const msg = String(e.message || "");
        if (!msg.includes("Duplicate key name") && !msg.includes("Duplicate entry")) {
          console.log("Index setup skipped:", msg);
        }
      }
    }


    await pool.execute(`INSERT IGNORE INTO vehicle_models (name) VALUES ('Y15ZR'), ('LC135'), ('RS150'), ('NVX')`);
    await pool.execute(`INSERT IGNORE INTO sticker_codes (code, name) VALUES ('RX01','RX01'), ('RX02','RX02'), ('THAI01','THAI01')`);
    await pool.execute(`INSERT IGNORE INTO cover_colors (name) VALUES ('Black'), ('Red'), ('Blue'), ('Silver'), ('Orange')`);
    await pool.execute(`INSERT IGNORE INTO product_categories (name) VALUES ('Sticker'), ('Cover Set'), ('Jersey'), ('Motor Parts')`);

    await pool.execute(`INSERT IGNORE INTO warehouses (name, code, address) VALUES
      ('Main Warehouse', 'MAIN', 'Main stock location'),
      ('Johor Warehouse', 'JHR', 'Johor branch warehouse'),
      ('Penang Warehouse', 'PNG', 'Penang branch warehouse')`);

    await pool.execute(`INSERT IGNORE INTO products (sku, name, category, price, cost, is_component) VALUES
      ('BRK-DISC-01', 'Racing Brake Disc', 'Motor Parts', 180.00, 95.00, FALSE),
      ('SOB-JERSEY-BKOR', 'SOB Racing Jersey', 'Apparel', 89.00, 38.00, FALSE),
      ('CARE-CHAIN-01', 'Chain Cleaner Kit', 'Maintenance', 45.00, 20.00, FALSE),
      ('COMP-STEEL-PLATE', 'Steel Plate', 'Component', 25.00, 18.00, TRUE),
      ('COMP-DRYFIT-FABRIC', 'Dry Fit Fabric', 'Component', 18.00, 12.00, TRUE)`);

    await pool.execute(`INSERT IGNORE INTO inventory (product_id, warehouse_id, qty_on_hand, qty_reserved)
      SELECT p.id, w.id, 0, 0 FROM products p CROSS JOIN warehouses w`);

    const tables = await query("SHOW TABLES");
    res.json({ ok: true, message: "Database setup completed", tables });
  } catch (err) {
    res.status(500).json({ ok: false, error: err.message });
  }
});


// AUTH
app.post("/api/auth/register", async (req, res) => {
  try {
    const { name, email, password, role = "STAFF" } = req.body;
    if (!name || !email || !password) return res.status(400).json({ error: "name, email, password are required" });
    const existing = await query("SELECT id FROM users WHERE email=?", [email]);
    if (existing.length) return res.status(409).json({ error: "Email already exists" });
    const hash = await bcrypt.hash(password, 12);
    const [result] = await pool.execute("INSERT INTO users (name,email,password_hash,role,status) VALUES (?,?,?,?, 'ACTIVE')", [name,email,hash,role]);
    res.json({ success: true, id: result.insertId });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.post("/api/auth/login", async (req, res) => {
  try {
    const { email, password } = req.body;
    const rows = await query("SELECT * FROM users WHERE email=? AND status='ACTIVE' LIMIT 1", [email]);
    if (!rows.length) return res.status(401).json({ error: "Invalid email or password" });
    const user = rows[0];
    const ok = await bcrypt.compare(password, user.password_hash);
    if (!ok) return res.status(401).json({ error: "Invalid email or password" });
    const token = jwt.sign({ id:user.id, name:user.name, email:user.email, role:user.role }, JWT_SECRET, { expiresIn:"7d" });
    res.json({ token, user:{ id:user.id, name:user.name, email:user.email, role:user.role, permissions:ROLE_PERMISSIONS[user.role] || [] } });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.get("/api/auth/me", authRequired, (req,res) => res.json({ user:req.user, permissions:ROLE_PERMISSIONS[req.user.role] || [] }));



// SALES AGENTS
app.get("/api/sales-agents", authRequired, requirePermission("orders:read"), async (req, res) => {
  try {
    const { status = "ACTIVE" } = req.query;
    const rows = await query(
      `SELECT * FROM sales_agents ${status && status !== "ALL" ? "WHERE status=?" : ""} ORDER BY name ASC`,
      status && status !== "ALL" ? [status] : []
    );
    res.json(rows);
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.post("/api/sales-agents", authRequired, requirePermission("orders:create"), async (req, res) => {
  try {
    const { name, phone, email, remark, status = "ACTIVE" } = req.body;
    if (!name) return res.status(400).json({ error: "Sales agent name is required" });
    const [result] = await pool.execute(
      "INSERT INTO sales_agents (name, phone, email, remark, status) VALUES (?, ?, ?, ?, ?)",
      [name, phone || null, email || null, remark || null, status]
    );
    res.json({ success: true, id: result.insertId });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.put("/api/sales-agents/:id", authRequired, requirePermission("orders:update"), async (req, res) => {
  try {
    const { name, phone, email, remark, status = "ACTIVE" } = req.body;
    await pool.execute(
      "UPDATE sales_agents SET name=?, phone=?, email=?, remark=?, status=? WHERE id=?",
      [name, phone || null, email || null, remark || null, status, req.params.id]
    );
    res.json({ success: true });
  } catch (err) { res.status(500).json({ error: err.message }); }
});


// CUSTOMERS
app.get("/api/customers", authRequired, requirePermission("orders:read"), async (req, res) => {
  try {
    const { q, platform, status = "ACTIVE" } = req.query;
    const where = [];
    const params = [];
    if (q) {
      where.push("(c.customer_code LIKE ? OR c.name LIKE ? OR c.phone LIKE ? OR c.email LIKE ? OR c.shop_name LIKE ?)");
      params.push(`%${q}%`, `%${q}%`, `%${q}%`, `%${q}%`, `%${q}%`);
    }
    if (platform && platform !== "ALL") {
      where.push("c.platform = ?");
      params.push(platform);
    }
    if (status && status !== "ALL") {
      where.push("c.status = ?");
      params.push(status);
    }
    const rows = await query(
      `SELECT c.*, sa.name AS sales_agent_name FROM customers c LEFT JOIN sales_agents sa ON sa.id=c.sales_agent_id ${where.length ? "WHERE " + where.join(" AND ") : ""} ORDER BY c.created_at DESC LIMIT 300`,
      params
    );
    res.json(rows);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.post("/api/customers", authRequired, requirePermission("orders:create"), async (req, res) => {
  try {
    const { customer_code, name, phone, email, address, platform = "GENERAL", sales_agent_id, shop_name, remark, status = "ACTIVE" } = req.body;
    if (!name) return res.status(400).json({ error: "Customer name is required" });
    const [result] = await pool.execute(
      `INSERT INTO customers (customer_code, name, phone, email, address, platform, sales_agent_id, shop_name, remark, status)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
      [customer_code || null, name, phone || null, email || null, address || null, platform, sales_agent_id || null, shop_name || null, remark || null, status]
    );
    res.json({ success: true, id: result.insertId });
  } catch (err) {
    if (err.code === "ER_DUP_ENTRY") return res.status(409).json({ error: "Customer code already exists" });
    res.status(500).json({ error: err.message });
  }
});

app.put("/api/customers/:id", authRequired, requirePermission("orders:update"), async (req, res) => {
  try {
    const { customer_code, name, phone, email, address, platform = "GENERAL", sales_agent_id, shop_name, remark, status = "ACTIVE" } = req.body;
    await pool.execute(
      `UPDATE customers SET customer_code=?, name=?, phone=?, email=?, address=?, platform=?, sales_agent_id=?, shop_name=?, remark=?, status=? WHERE id=?`,
      [customer_code || null, name, phone || null, email || null, address || null, platform, sales_agent_id || null, shop_name || null, remark || null, status, req.params.id]
    );
    res.json({ success: true });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});






// ERP CORE PACKAGE

// BOM
app.get("/api/bom/:productId", authRequired, requirePermission("products:read"), async (req,res)=>{
  try{
    const productRows = await query("SELECT * FROM products WHERE id=?", [req.params.productId]);
    if(!productRows.length) return res.status(404).json({error:"Product not found"});
    const items = await query("SELECT bi.*, p.sku, p.name, p.cost, p.image_url, (bi.quantity * p.cost) AS total_cost FROM bom_items bi LEFT JOIN products p ON p.id=bi.component_product_id WHERE bi.product_id=?", [req.params.productId]);
    const total = items.reduce((s,x)=>s+Number(x.total_cost||0),0);
    res.json({...productRows[0], bom_items:items, bom_cost:total});
  }catch(err){res.status(500).json({error:err.message})}
});

app.post("/api/bom/:productId/items", authRequired, requirePermission("products:update"), async (req,res)=>{
  try{
    const { component_product_id, quantity=1, unit="pcs" } = req.body;
    if(!component_product_id) return res.status(400).json({error:"component_product_id required"});
    const [r] = await pool.execute("INSERT INTO bom_items (product_id, component_product_id, quantity, unit) VALUES (?,?,?,?)", [req.params.productId, component_product_id, quantity, unit]);
    res.json({success:true,id:r.insertId});
  }catch(err){res.status(500).json({error:err.message})}
});

app.put("/api/bom-items/:id", authRequired, requirePermission("products:update"), async (req,res)=>{
  try{
    const { quantity=1, unit="pcs" } = req.body;
    await pool.execute("UPDATE bom_items SET quantity=?, unit=? WHERE id=?", [quantity, unit, req.params.id]);
    res.json({success:true});
  }catch(err){res.status(500).json({error:err.message})}
});

app.delete("/api/bom-items/:id", authRequired, requirePermission("products:update"), async (req,res)=>{
  try{ await pool.execute("DELETE FROM bom_items WHERE id=?", [req.params.id]); res.json({success:true});}
  catch(err){res.status(500).json({error:err.message})}
});

// Promotion rules Buy X Free Y
app.get("/api/promotions/:id/rules", authRequired, requirePermission("orders:read"), async (req,res)=>{
  try{res.json(await query("SELECT pr.*, p.sku AS free_sku, p.name AS free_product_name FROM promotion_rules pr LEFT JOIN products p ON p.id=pr.free_product_id WHERE promotion_id=? ORDER BY id DESC",[req.params.id]));}
  catch(err){res.status(500).json({error:err.message})}
});

app.post("/api/promotions/:id/rules", authRequired, requirePermission("orders:update"), async (req,res)=>{
  try{
    const {target_type="VEHICLE_MODEL",target_value,buy_qty,free_qty,free_product_id,status="ACTIVE"}=req.body;
    if(!target_value) return res.status(400).json({error:"target_value required"});
    const [r]=await pool.execute("INSERT INTO promotion_rules (promotion_id,target_type,target_value,buy_qty,free_qty,free_product_id,status) VALUES (?,?,?,?,?,?,?)",[req.params.id,target_type,target_value,buy_qty||0,free_qty||0,free_product_id||null,status]);
    res.json({success:true,id:r.insertId});
  }catch(err){res.status(500).json({error:err.message})}
});

app.post("/api/promotions/calculate", authRequired, requirePermission("orders:read"), async (req,res)=>{
  try{
    const { promotion_id, items=[] } = req.body;
    const rules = await query("SELECT * FROM promotion_rules WHERE promotion_id=? AND status='ACTIVE'", [promotion_id]);
    const products = items.length ? await query(`SELECT * FROM products WHERE id IN (${items.map(()=>"?").join(",")})`, items.map(i=>i.product_id)) : [];
    const productMap = Object.fromEntries(products.map(p=>[p.id,p]));
    const results = [];
    for(const rule of rules){
      let qty = 0;
      for(const item of items){
        const p = productMap[item.product_id];
        if(!p) continue;
        if(rule.target_type==="VEHICLE_MODEL" && p.vehicle_model===rule.target_value) qty += Number(item.qty||0);
        if(rule.target_type==="STICKER_CODE" && p.sticker_code===rule.target_value) qty += Number(item.qty||0);
        if(rule.target_type==="CATEGORY" && p.category===rule.target_value) qty += Number(item.qty||0);
        if(rule.target_type==="PRODUCT" && String(p.id)===String(rule.target_value)) qty += Number(item.qty||0);
      }
      const free = Math.floor(qty / Number(rule.buy_qty||1)) * Number(rule.free_qty||0);
      results.push({rule, matched_qty:qty, free_qty:free});
    }
    res.json({ok:true, results});
  }catch(err){res.status(500).json({error:err.message})}
});

// Inventory operations
app.get("/api/inventory-operations", authRequired, requirePermission("inventory:read"), async (req,res)=>{
  try{res.json(await query("SELECT io.*, fw.name AS from_warehouse, tw.name AS to_warehouse FROM inventory_operations io LEFT JOIN warehouses fw ON fw.id=io.from_warehouse_id LEFT JOIN warehouses tw ON tw.id=io.to_warehouse_id ORDER BY io.created_at DESC LIMIT 200"));}
  catch(err){res.status(500).json({error:err.message})}
});

app.post("/api/inventory-operations", authRequired, requirePermission("inventory:update"), async (req,res)=>{
  const conn = await pool.getConnection();
  try{
    const {operation_no, operation_type, from_warehouse_id, to_warehouse_id, operation_date, reference_no, remark, items=[]}=req.body;
    if(!operation_no || !operation_type || !operation_date) return res.status(400).json({error:"operation_no, operation_type, operation_date required"});
    await conn.beginTransaction();
    const [r]=await conn.execute("INSERT INTO inventory_operations (operation_no,operation_type,from_warehouse_id,to_warehouse_id,operation_date,reference_no,remark,created_by) VALUES (?,?,?,?,?,?,?,?)",[operation_no,operation_type,from_warehouse_id||null,to_warehouse_id||null,operation_date,reference_no||null,remark||null,req.user.id]);
    for(const item of items){
      await conn.execute("INSERT INTO inventory_operation_items (operation_id,product_id,qty,batch_no,remark) VALUES (?,?,?,?,?)",[r.insertId,item.product_id,item.qty,item.batch_no||null,item.remark||null]);
      if(operation_type==="IN" || operation_type==="ADJUSTMENT"){
        await conn.execute("INSERT INTO inventory (product_id,warehouse_id,qty_on_hand,qty_reserved) VALUES (?,?,?,0) ON DUPLICATE KEY UPDATE qty_on_hand=qty_on_hand+VALUES(qty_on_hand)",[item.product_id,to_warehouse_id,item.qty]);
      }
      if(operation_type==="OUT"){
        await conn.execute("UPDATE inventory SET qty_on_hand=qty_on_hand-? WHERE product_id=? AND warehouse_id=?",[item.qty,item.product_id,from_warehouse_id]);
      }
      if(operation_type==="TRANSFER"){
        await conn.execute("UPDATE inventory SET qty_on_hand=qty_on_hand-? WHERE product_id=? AND warehouse_id=?",[item.qty,item.product_id,from_warehouse_id]);
        await conn.execute("INSERT INTO inventory (product_id,warehouse_id,qty_on_hand,qty_reserved) VALUES (?,?,?,0) ON DUPLICATE KEY UPDATE qty_on_hand=qty_on_hand+VALUES(qty_on_hand)",[item.product_id,to_warehouse_id,item.qty]);
      }
    }
    await conn.commit(); res.json({success:true,id:r.insertId});
  }catch(err){await conn.rollback(); res.status(500).json({error:err.message});}
  finally{conn.release();}
});

// Order item evidence upload
app.post("/api/order-items/:id/evidence", authRequired, requirePermission("orders:update"), upload.single("file"), async (req,res)=>{
  try{
    if(!req.file) return res.status(400).json({error:"file required"});
    const mime = req.file.mimetype || "";
    const media_type = mime.startsWith("video") ? "video" : "photo";
    const file_url = "/uploads/" + req.file.filename;
    const [r] = await pool.execute("INSERT INTO order_item_media (order_item_id, media_type, file_url, file_name, file_size, mime_type, uploaded_by) VALUES (?,?,?,?,?,?,?)",[req.params.id,media_type,file_url,req.file.originalname,req.file.size,mime,req.user.id]);
    res.json({success:true,id:r.insertId,file_url,media_type});
  }catch(err){res.status(500).json({error:err.message})}
});

app.get("/api/order-items/:id/evidence", authRequired, requirePermission("orders:read"), async (req,res)=>{
  try{res.json(await query("SELECT * FROM order_item_media WHERE order_item_id=? ORDER BY uploaded_at DESC",[req.params.id]));}
  catch(err){res.status(500).json({error:err.message})}
});


// PRODUCT VARIANT OPTIONS
function registerOptionRoutes(basePath, table, codeField = "name") {
  app.get(`/api/${basePath}`, authRequired, requirePermission("products:read"), async (req, res) => {
    try {
      const { status = "ACTIVE" } = req.query;
      const rows = await query(
        `SELECT * FROM ${table} ${status && status !== "ALL" ? "WHERE status=?" : ""} ORDER BY ${codeField} ASC`,
        status && status !== "ALL" ? [status] : []
      );
      res.json(rows);
    } catch (err) { res.status(500).json({ error: err.message }); }
  });

  app.post(`/api/${basePath}`, authRequired, requirePermission("products:create"), async (req, res) => {
    try {
      const { name, code, color_code, remark, status = "ACTIVE" } = req.body;
      let sql, params;
      if (table === "sticker_codes") {
        sql = "INSERT INTO sticker_codes (code, name, remark, status) VALUES (?, ?, ?, ?)";
        params = [code || name, name || code, remark || null, status];
      } else if (table === "cover_colors") {
        sql = "INSERT INTO cover_colors (name, color_code, remark, status) VALUES (?, ?, ?, ?)";
        params = [name, color_code || null, remark || null, status];
      } else {
        sql = `INSERT INTO ${table} (name, remark, status) VALUES (?, ?, ?)`;
        params = [name, remark || null, status];
      }
      const [result] = await pool.execute(sql, params);
      res.json({ success: true, id: result.insertId });
    } catch (err) {
      if (err.code === "ER_DUP_ENTRY") return res.status(409).json({ error: "Option already exists" });
      res.status(500).json({ error: err.message });
    }
  });

  app.put(`/api/${basePath}/:id`, authRequired, requirePermission("products:update"), async (req, res) => {
    try {
      const { name, code, color_code, remark, status = "ACTIVE" } = req.body;
      let sql, params;
      if (table === "sticker_codes") {
        sql = "UPDATE sticker_codes SET code=?, name=?, remark=?, status=? WHERE id=?";
        params = [code || name, name || code, remark || null, status, req.params.id];
      } else if (table === "cover_colors") {
        sql = "UPDATE cover_colors SET name=?, color_code=?, remark=?, status=? WHERE id=?";
        params = [name, color_code || null, remark || null, status, req.params.id];
      } else {
        sql = `UPDATE ${table} SET name=?, remark=?, status=? WHERE id=?`;
        params = [name, remark || null, status, req.params.id];
      }
      await pool.execute(sql, params);
      res.json({ success: true });
    } catch (err) { res.status(500).json({ error: err.message }); }
  });
}

registerOptionRoutes("vehicle-models", "vehicle_models", "name");
registerOptionRoutes("sticker-codes", "sticker_codes", "code");
registerOptionRoutes("cover-colors", "cover_colors", "name");
registerOptionRoutes("product-categories", "product_categories", "name");


// PROMOTIONS
app.get("/api/promotions", authRequired, requirePermission("orders:read"), async (req, res) => {
  try {
    const { status = "ACTIVE", active_today } = req.query;
    const where = [];
    const params = [];
    if (status && status !== "ALL") { where.push("status=?"); params.push(status); }
    if (active_today === "true") {
      const today = dayjs().format("YYYY-MM-DD");
      where.push("start_date <= ? AND end_date >= ?");
      params.push(today, today);
    }
    const rows = await query(
      `SELECT * FROM promotions ${where.length ? "WHERE " + where.join(" AND ") : ""} ORDER BY start_date DESC, created_at DESC`,
      params
    );
    res.json(rows);
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.post("/api/promotions", authRequired, requirePermission("orders:create"), async (req, res) => {
  try {
    const { promo_code, promo_name, platform = "ALL", start_date, end_date, package_price = 0, remark, status = "ACTIVE", items = [] } = req.body;
    if (!promo_code || !promo_name || !start_date || !end_date) return res.status(400).json({ error: "promo_code, promo_name, start_date, end_date required" });
    const conn = await pool.getConnection();
    try {
      await conn.beginTransaction();
      const [result] = await conn.execute(
        "INSERT INTO promotions (promo_code, promo_name, platform, start_date, end_date, package_price, remark, status) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
        [promo_code, promo_name, platform, start_date, end_date, package_price, remark || null, status]
      );
      for (const item of items) {
        await conn.execute("INSERT INTO promotion_items (promotion_id, product_id, qty, foc, remark) VALUES (?, ?, ?, ?, ?)", [result.insertId, item.product_id, item.qty || 1, item.foc ? 1 : 0, item.remark || null]);
      }
      await conn.commit();
      res.json({ success: true, id: result.insertId });
    } catch (e) { await conn.rollback(); throw e; } finally { conn.release(); }
  } catch (err) {
    if (err.code === "ER_DUP_ENTRY") return res.status(409).json({ error: "Promotion code already exists" });
    res.status(500).json({ error: err.message });
  }
});

app.get("/api/promotions/:id", authRequired, requirePermission("orders:read"), async (req, res) => {
  try {
    const rows = await query("SELECT * FROM promotions WHERE id=?", [req.params.id]);
    if (!rows.length) return res.status(404).json({ error: "Promotion not found" });
    const items = await query("SELECT pi.*, p.sku, p.name, p.image_url FROM promotion_items pi LEFT JOIN products p ON p.id=pi.product_id WHERE pi.promotion_id=?", [req.params.id]);
    res.json({ ...rows[0], items });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.put("/api/promotions/:id", authRequired, requirePermission("orders:update"), async (req, res) => {
  try {
    const { promo_code, promo_name, platform = "ALL", start_date, end_date, package_price = 0, remark, status = "ACTIVE" } = req.body;
    await pool.execute(
      "UPDATE promotions SET promo_code=?, promo_name=?, platform=?, start_date=?, end_date=?, package_price=?, remark=?, status=? WHERE id=?",
      [promo_code, promo_name, platform, start_date, end_date, package_price, remark || null, status, req.params.id]
    );
    res.json({ success: true });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.post("/api/promotions/:id/items", authRequired, requirePermission("orders:update"), async (req, res) => {
  try {
    const { product_id, qty = 1, foc = false, remark } = req.body;
    const [result] = await pool.execute("INSERT INTO promotion_items (promotion_id, product_id, qty, foc, remark) VALUES (?, ?, ?, ?, ?)", [req.params.id, product_id, qty, foc ? 1 : 0, remark || null]);
    res.json({ success: true, id: result.insertId });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.delete("/api/promotion-items/:id", authRequired, requirePermission("orders:update"), async (req, res) => {
  try {
    await pool.execute("DELETE FROM promotion_items WHERE id=?", [req.params.id]);
    res.json({ success: true });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// ANNOUNCEMENTS
app.get("/api/announcements", authRequired, requirePermission("orders:read"), async (req, res) => {
  try {
    const { status = "ACTIVE", active_today } = req.query;
    const where = [];
    const params = [];
    if (status && status !== "ALL") { where.push("status=?"); params.push(status); }
    if (active_today === "true") {
      const today = dayjs().format("YYYY-MM-DD");
      where.push("(start_date IS NULL OR start_date <= ?) AND (end_date IS NULL OR end_date >= ?)");
      params.push(today, today);
    }
    const rows = await query(
      `SELECT * FROM announcements ${where.length ? "WHERE " + where.join(" AND ") : ""} ORDER BY FIELD(priority,'URGENT','IMPORTANT','NORMAL'), created_at DESC`,
      params
    );
    res.json(rows);
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.post("/api/announcements", authRequired, requirePermission("orders:create"), async (req, res) => {
  try {
    const { title, message, priority = "NORMAL", start_date, end_date, status = "ACTIVE" } = req.body;
    if (!title || !message) return res.status(400).json({ error: "title and message required" });
    const [result] = await pool.execute(
      "INSERT INTO announcements (title, message, priority, start_date, end_date, status, created_by) VALUES (?, ?, ?, ?, ?, ?, ?)",
      [title, message, priority, start_date || null, end_date || null, status, req.user.id]
    );
    res.json({ success: true, id: result.insertId });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.put("/api/announcements/:id", authRequired, requirePermission("orders:update"), async (req, res) => {
  try {
    const { title, message, priority = "NORMAL", start_date, end_date, status = "ACTIVE" } = req.body;
    await pool.execute(
      "UPDATE announcements SET title=?, message=?, priority=?, start_date=?, end_date=?, status=? WHERE id=?",
      [title, message, priority, start_date || null, end_date || null, status, req.params.id]
    );
    res.json({ success: true });
  } catch (err) { res.status(500).json({ error: err.message }); }
});


// ORDER ITEM STATUS OPTIONS
app.get("/api/order-item-status-options", authRequired, requirePermission("orders:read"), async (req, res) => {
  try {
    const rows = await query("SELECT * FROM order_item_status_options WHERE status='ACTIVE' ORDER BY sort_order ASC, name ASC");
    res.json(rows);
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.post("/api/order-item-status-options", authRequired, requirePermission("orders:update"), async (req, res) => {
  try {
    const { name, sort_order = 99, is_shipped = false } = req.body;
    if (!name) return res.status(400).json({ error: "Status name is required" });
    const [result] = await pool.execute("INSERT INTO order_item_status_options (name, sort_order, is_shipped) VALUES (?, ?, ?)", [name, sort_order, is_shipped ? 1 : 0]);
    res.json({ success: true, id: result.insertId });
  } catch (err) {
    if (err.code === "ER_DUP_ENTRY") return res.status(409).json({ error: "Status already exists" });
    res.status(500).json({ error: err.message });
  }
});


// ORDERS
app.post("/api/orders", authRequired, requirePermission("orders:create"), async (req,res) => {
  try {
    const { order_id, order_date, so_number, do_number, promotion_id, order_type, tracking_number, customer_id, shop_name, customer_name, status="Pending", deadline_ship_date, warehouse_id, total=0, remark, items=[] } = req.body;
    if (!order_id || !order_type) return res.status(400).json({ error:"ORDER ID and order_type required" });

    const duplicateWhere = ["order_id = ?"];
    const duplicateParams = [order_id];
    if (so_number) {
      duplicateWhere.push("so_number = ?");
      duplicateParams.push(so_number);
    }
    if (tracking_number) {
      duplicateWhere.push("tracking_number = ?");
      duplicateParams.push(tracking_number);
    }
    const duplicates = await query(
      `SELECT order_id, so_number, tracking_number FROM orders WHERE ${duplicateWhere.join(" OR ")} LIMIT 1`,
      duplicateParams
    );
    if (duplicates.length) {
      const d = duplicates[0];
      if (d.order_id === order_id) return res.status(409).json({ error: "ORDER ID already exists" });
      if (so_number && d.so_number === so_number) return res.status(409).json({ error: "SO NUMBER already exists" });
      if (tracking_number && d.tracking_number === tracking_number) return res.status(409).json({ error: "TRACKING NUMBER already exists" });
      return res.status(409).json({ error: "Duplicate order value exists" });
    }

    const conn = await pool.getConnection();
    try {
      await conn.beginTransaction();
      const [result] = await conn.execute(
        "INSERT INTO orders (order_id,order_date,so_number,do_number,promotion_id,order_type,tracking_number,customer_id,shop_name,customer_name,status,deadline_ship_date,warehouse_id,total,remark,created_by) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
        [order_id,order_date||dayjs().format("YYYY-MM-DD"),so_number||null,do_number||null,promotion_id||null,order_type,tracking_number||null,customer_id||null,shop_name||null,customer_name||null,status,deadline_ship_date||null,warehouse_id||null,total,remark||null,req.user.id]
      );
      for (const item of items) {
        await conn.execute("INSERT INTO order_items (order_id,product_id,qty,price,discount,foc,item_status,shipped_date,remark) VALUES (?,?,?,?,?,?,?,?,?)", [result.insertId,item.product_id,item.qty,item.price||0,item.discount||0,item.foc?1:0,item.item_status||"Pending",item.shipped_date||null,item.remark||null]);
      }
      await conn.commit();
      res.json({ success:true, id:result.insertId });
    } catch(e) { await conn.rollback(); throw e; } finally { conn.release(); }
  } catch(err) {
    if (err.code === "ER_DUP_ENTRY") return res.status(409).json({ error: "ORDER ID / SO NUMBER / TRACKING NUMBER already exists" });
    res.status(500).json({ error:err.message });
  }
});

app.get("/api/orders", authRequired, requirePermission("orders:read"), async (req,res) => {
  try {
    const { type, shop, status } = req.query;
    const where=[], params=[];
    if(type){where.push("order_type=?");params.push(type)}
    if(shop){where.push("shop_name LIKE ?");params.push(`%${shop}%`)}
    if(status){where.push("status=?");params.push(status)}
    const rows = await query(`SELECT * FROM orders ${where.length?"WHERE "+where.join(" AND "):""} ORDER BY created_at DESC LIMIT 300`, params);
    res.json(rows);
  } catch(err){ res.status(500).json({ error:err.message });}
});

app.get("/api/orders/:id", authRequired, requirePermission("orders:read"), async (req,res) => {
  try {
    const rows = await query("SELECT * FROM orders WHERE id=?", [req.params.id]);
    if(!rows.length) return res.status(404).json({ error:"Order not found" });
    const items = await query("SELECT oi.*, p.sku, p.name, p.image_url FROM order_items oi LEFT JOIN products p ON p.id=oi.product_id WHERE oi.order_id=?", [req.params.id]);
    const shipments = await query("SELECT * FROM order_shipments WHERE order_id=? ORDER BY ship_date DESC, ship_time DESC", [req.params.id]);
    res.json({ ...rows[0], items, shipments });
  } catch(err){ res.status(500).json({ error:err.message });}
});


app.put("/api/orders/:id", authRequired, requirePermission("orders:update"), async (req, res) => {
  try {
    const { order_date, so_number, do_number, promotion_id, tracking_number, customer_id, shop_name, customer_name, status, deadline_ship_date, total, remark } = req.body;
    await pool.execute(
      `UPDATE orders SET order_date=?, so_number=?, do_number=?, promotion_id=?, tracking_number=?, customer_id=?, shop_name=?, customer_name=?, status=?, deadline_ship_date=?, total=?, remark=? WHERE id=?`,
      [order_date || null, so_number || null, do_number || null, promotion_id || null, tracking_number || null, customer_id || null, shop_name || null, customer_name || null, status || "Pending", deadline_ship_date || null, total || 0, remark || null, req.params.id]
    );
    res.json({ success: true });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.post("/api/orders/:id/items", authRequired, requirePermission("orders:update"), async (req, res) => {
  try {
    const { product_id, qty = 1, price = 0, discount = 0, foc = false, item_status = "Pending", shipped_date, remark } = req.body;
    if (!product_id) return res.status(400).json({ error: "product_id is required" });
    const statusRows = await query("SELECT is_shipped FROM order_item_status_options WHERE name=? LIMIT 1", [item_status]);
    const finalShippedDate = statusRows[0]?.is_shipped && !shipped_date ? dayjs().format("YYYY-MM-DD") : shipped_date || null;
    const [result] = await pool.execute(
      "INSERT INTO order_items (order_id,product_id,qty,price,discount,foc,item_status,shipped_date,remark) VALUES (?,?,?,?,?,?,?,?,?)",
      [req.params.id, product_id, qty, price, discount, foc ? 1 : 0, item_status, finalShippedDate, remark || null]
    );
    res.json({ success: true, id: result.insertId });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.put("/api/order-items/:id", authRequired, requirePermission("orders:update"), async (req, res) => {
  try {
    const { qty = 1, price = 0, discount = 0, foc = false, item_status = "Pending", shipped_date, remark } = req.body;
    const statusRows = await query("SELECT is_shipped FROM order_item_status_options WHERE name=? LIMIT 1", [item_status]);
    const currentRows = await query("SELECT shipped_date FROM order_items WHERE id=? LIMIT 1", [req.params.id]);
    const currentShippedDate = currentRows[0]?.shipped_date || null;
    const finalShippedDate = statusRows[0]?.is_shipped && !shipped_date && !currentShippedDate ? dayjs().format("YYYY-MM-DD") : shipped_date || currentShippedDate || null;
    await pool.execute(
      "UPDATE order_items SET qty=?, price=?, discount=?, foc=?, item_status=?, shipped_date=?, remark=? WHERE id=?",
      [qty, price, discount, foc ? 1 : 0, item_status, finalShippedDate, remark || null, req.params.id]
    );
    res.json({ success: true, shipped_date: finalShippedDate });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.delete("/api/order-items/:id", authRequired, requirePermission("orders:update"), async (req, res) => {
  try {
    await pool.execute("DELETE FROM order_items WHERE id=?", [req.params.id]);
    res.json({ success: true });
  } catch (err) { res.status(500).json({ error: err.message }); }
});


app.post("/api/orders/:id/shipments", authRequired, requirePermission("orders:ship"), async (req,res) => {
  try {
    const { tracking_number, ship_date=dayjs().format("YYYY-MM-DD"), ship_time=dayjs().format("HH:mm:ss"), shipped_qty=0, courier } = req.body;
    if(!tracking_number) return res.status(400).json({ error:"Tracking number is required" });
    const [result] = await pool.execute("INSERT INTO order_shipments (order_id,tracking_number,ship_date,ship_time,shipped_qty,courier,created_by) VALUES (?,?,?,?,?,?,?)", [req.params.id,tracking_number,ship_date,ship_time,shipped_qty,courier||null,req.user.id]);
    await query("UPDATE orders SET status='Partial Shipped' WHERE id=?", [req.params.id]);
    res.json({ success:true, id:result.insertId });
  } catch(err){ res.status(500).json({ error:err.message });}
});

const orderMediaStorage = multer.diskStorage({
  destination: (req,file,cb) => {
    const folder = file.mimetype.startsWith("video/") ? "videos" : "photos";
    const dir = path.join(__dirname,"uploads","orders",String(req.params.orderId),"items",String(req.params.orderItemId),folder);
    ensureDir(dir); cb(null,dir);
  },
  filename: (req,file,cb) => cb(null, `${Date.now()}-${file.originalname.replace(/[^a-zA-Z0-9._-]/g,"_")}`)
});
const uploadOrderMedia = multer({ storage:orderMediaStorage, limits:{ fileSize:100*1024*1024 }});
app.post("/api/orders/:orderId/items/:orderItemId/media", authRequired, requirePermission("orders:update"), uploadOrderMedia.array("files",20), async (req,res) => {
  try {
    const saved=[];
    for(const file of req.files || []) {
      const type = file.mimetype.startsWith("video/") ? "video" : "photo";
      const url = file.path.replace(__dirname,"").replace(/\\/g,"/");
      const [r] = await pool.execute("INSERT INTO order_item_media (order_item_id,media_type,file_url,file_name,file_size,mime_type,uploaded_by) VALUES (?,?,?,?,?,?,?)", [req.params.orderItemId,type,url,file.originalname,file.size,file.mimetype,req.user.id]);
      saved.push({ id:r.insertId, file_url:url });
    }
    res.json({ success:true, files:saved });
  } catch(err){ res.status(500).json({ error:err.message });}
});


// ORDER CSV IMPORT / EXPORT
function csvEscape(value) {
  const s = String(value ?? "");
  return `"${s.replace(/"/g, '""')}"`;
}

app.get("/api/orders-template.csv", authRequired, requirePermission("orders:read"), async (req, res) => {
  const headers = [
    "order_id","order_date","so_number","do_number","order_type","tracking_number",
    "customer_name","shop_name","deadline_ship_date","total"
  ];
  res.setHeader("Content-Type", "text/csv; charset=utf-8");
  res.setHeader("Content-Disposition", "attachment; filename=orders-import-template.csv");
  res.send(headers.join(",") + "\\n");
});

app.get("/api/orders-export.csv", authRequired, requirePermission("orders:read"), async (req, res) => {
  try {
    const rows = await query(`SELECT order_id, order_date, so_number, do_number, order_type, tracking_number, customer_name, shop_name, status, deadline_ship_date, total, created_at FROM orders ORDER BY created_at DESC`);
    const headers = ["order_id","order_date","so_number","do_number","order_type","tracking_number","customer_name","shop_name","status","deadline_ship_date","total","created_at"];
    const csv = [headers.join(",")]
      .concat(rows.map(r => headers.map(h => csvEscape(r[h])).join(",")))
      .join("\\n");
    res.setHeader("Content-Type", "text/csv; charset=utf-8");
    res.setHeader("Content-Disposition", "attachment; filename=orders-export.csv");
    res.send(csv);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});


// REPORTS
app.get("/api/reports/shipments", authRequired, requirePermission("reports:read"), async (req,res) => {
  try {
    const { date, date_from, date_to, type, shop } = req.query;
    const where=[], params=[];
    if(date){where.push("s.ship_date=?");params.push(date)}
    if(date_from){where.push("s.ship_date>=?");params.push(date_from)}
    if(date_to){where.push("s.ship_date<=?");params.push(date_to)}
    if(type && type !== "ALL"){where.push("o.order_type=?");params.push(type)}
    if(shop){where.push("o.shop_name LIKE ?");params.push(`%${shop}%`)}
    const rows = await query(`SELECT o.order_id, s.tracking_number, s.ship_date AS date, s.ship_time AS time, o.shop_name, o.order_type, s.courier FROM order_shipments s JOIN orders o ON o.id=s.order_id ${where.length?"WHERE "+where.join(" AND "):""} ORDER BY s.ship_date DESC, s.ship_time DESC`, params);
    res.json({ count:rows.length, rows });
  } catch(err){ res.status(500).json({ error:err.message });}
});

app.get("/api/dashboard/deadline-alerts", authRequired, requirePermission("orders:read"), async (req,res) => {
  try {
    const today = dayjs().format("YYYY-MM-DD");
    const two = dayjs().add(2,"day").format("YYYY-MM-DD");
    const rows = await query("SELECT id,order_id,order_type,shop_name,customer_name,status,deadline_ship_date FROM orders WHERE order_type IN ('SHOPEE','TIKTOK') AND deadline_ship_date BETWEEN ? AND ? AND status NOT IN ('Shipped','Completed','Cancelled') ORDER BY deadline_ship_date ASC", [today,two]);
    res.json({ count:rows.length, rows });
  } catch(err){ res.status(500).json({ error:err.message });}
});

// PRODUCTS + BOM
const productImageStorage = multer.diskStorage({
  destination:(req,file,cb)=>{ const dir=path.join(__dirname,"uploads","products"); ensureDir(dir); cb(null,dir); },
  filename:(req,file,cb)=>cb(null, `${Date.now()}-${file.originalname.replace(/[^a-zA-Z0-9._-]/g,"_")}`)
});
const productUpload = multer({ storage:productImageStorage, limits:{fileSize:10*1024*1024}});
app.get("/api/products", authRequired, requirePermission("products:read"), async (req,res) => {
  try {
    const q=req.query.q; const params=[]; let where="WHERE status='ACTIVE'";
    if(q){ where += " AND (sku LIKE ? OR name LIKE ? OR category LIKE ?)"; params.push(`%${q}%`,`%${q}%`,`%${q}%`); }
    res.json(await query(`SELECT * FROM products ${where} ORDER BY created_at DESC LIMIT 300`, params));
  } catch(err){ res.status(500).json({error:err.message});}
});
app.post("/api/products", authRequired, requirePermission("products:create"), async (req,res) => {
  try {
    const { sku,name,category,vehicle_model,sticker_code,cover_color,price=0,cost=0,image_url,is_component=false } = req.body;
    const [r]=await pool.execute("INSERT INTO products (sku,name,category,vehicle_model,sticker_code,cover_color,price,cost,image_url,is_component) VALUES (?,?,?,?,?,?,?,?,?,?)",[sku,name,category||null,vehicle_model||null,sticker_code||null,cover_color||null,price,cost,image_url||null,is_component?1:0]);
    await pool.execute("INSERT IGNORE INTO inventory (product_id,warehouse_id,qty_on_hand,qty_reserved) SELECT ?, id, 0, 0 FROM warehouses WHERE status='ACTIVE'", [r.insertId]);
    res.json({success:true,id:r.insertId});
  } catch(err){ res.status(500).json({error:err.message});}
});
app.post("/api/products/:id/image", authRequired, requirePermission("products:update"), productUpload.single("image"), async (req,res) => {
  try {
    const url=`/uploads/products/${req.file.filename}`;
    await query("UPDATE products SET image_url=? WHERE id=?", [url,req.params.id]);
    res.json({success:true,image_url:url});
  } catch(err){ res.status(500).json({error:err.message});}
});
app.get("/api/products/:id/bom", authRequired, requirePermission("bom:read"), async (req,res)=>{
  try{
    const product=(await query("SELECT * FROM products WHERE id=?", [req.params.id]))[0];
    const items=await query("SELECT b.*, p.sku component_sku, p.name component_name, p.cost component_cost, (b.quantity*p.cost) line_cost FROM bom_items b JOIN products p ON p.id=b.component_product_id WHERE b.product_id=?", [req.params.id]);
    res.json({product, items, total_cost:items.reduce((s,i)=>s+Number(i.line_cost||0),0)});
  }catch(err){res.status(500).json({error:err.message});}
});
app.post("/api/products/:id/bom", authRequired, requirePermission("bom:update"), async(req,res)=>{
  try{
    const { component_product_id, quantity=1, unit="pcs" }=req.body;
    const [r]=await pool.execute("INSERT INTO bom_items (product_id,component_product_id,quantity,unit) VALUES (?,?,?,?)",[req.params.id,component_product_id,quantity,unit]);
    res.json({success:true,id:r.insertId});
  }catch(err){res.status(500).json({error:err.message});}
});
app.delete("/api/bom-items/:id", authRequired, requirePermission("bom:update"), async(req,res)=>{
  try{ await query("DELETE FROM bom_items WHERE id=?", [req.params.id]); res.json({success:true});}
  catch(err){res.status(500).json({error:err.message});}
});

// INVENTORY
app.get("/api/warehouses", authRequired, requirePermission("inventory:read"), async(req,res)=>{
  try{ res.json(await query("SELECT * FROM warehouses ORDER BY name ASC")); }
  catch(err){res.status(500).json({error:err.message});}
});
app.get("/api/inventory", authRequired, requirePermission("inventory:read"), async(req,res)=>{
  try{
    const { warehouse_id,q,low_stock }=req.query; const where=[],params=[];
    if(warehouse_id){where.push("i.warehouse_id=?");params.push(warehouse_id)}
    if(q){where.push("(p.sku LIKE ? OR p.name LIKE ? OR p.category LIKE ?)");params.push(`%${q}%`,`%${q}%`,`%${q}%`)}
    if(low_stock==="true") where.push("i.qty_available<=10");
    const rows=await query(`SELECT i.id inventory_id,i.product_id,p.sku,p.name product_name,p.category,p.image_url,i.warehouse_id,w.name warehouse_name,w.code warehouse_code,i.qty_on_hand,i.qty_reserved,i.qty_available FROM inventory i JOIN products p ON p.id=i.product_id JOIN warehouses w ON w.id=i.warehouse_id ${where.length?"WHERE "+where.join(" AND "):""} ORDER BY p.name,w.name LIMIT 500`, params);
    res.json(rows);
  }catch(err){res.status(500).json({error:err.message});}
});
app.post("/api/inventory/transfer", authRequired, requirePermission("inventory:transfer"), async(req,res)=>{
  try{
    const { product_id, from_warehouse_id, to_warehouse_id, qty, reference_no }=req.body;
    const conn=await pool.getConnection();
    try{
      await conn.beginTransaction();
      await conn.execute("UPDATE inventory SET qty_on_hand=qty_on_hand-? WHERE product_id=? AND warehouse_id=?", [qty,product_id,from_warehouse_id]);
      await conn.execute("INSERT INTO inventory (product_id,warehouse_id,qty_on_hand,qty_reserved) VALUES (?,?,?,0) ON DUPLICATE KEY UPDATE qty_on_hand=qty_on_hand+VALUES(qty_on_hand)", [product_id,to_warehouse_id,qty]);
      await conn.execute("INSERT INTO stock_movements (product_id,from_warehouse_id,to_warehouse_id,qty,type,reference_no,created_by) VALUES (?,?,?,?, 'TRANSFER', ?, ?)", [product_id,from_warehouse_id,to_warehouse_id,qty,reference_no||null,req.user.id]);
      await conn.commit(); res.json({success:true});
    }catch(e){await conn.rollback(); throw e;} finally{conn.release();}
  }catch(err){res.status(500).json({error:err.message});}
});

// CHAT
app.get("/api/chat/rooms", authRequired, requirePermission("chat:read"), async(req,res)=>{
  try{ res.json(await query("SELECT * FROM chat_rooms ORDER BY created_at DESC")); }
  catch(err){res.status(500).json({error:err.message});}
});
app.post("/api/chat/rooms", authRequired, requirePermission("chat:send"), async(req,res)=>{
  try{ const {room_name,room_type="GENERAL",order_id}=req.body; const [r]=await pool.execute("INSERT INTO chat_rooms (room_name,room_type,order_id) VALUES (?,?,?)",[room_name,room_type,order_id||null]); res.json({success:true,id:r.insertId});}
  catch(err){res.status(500).json({error:err.message});}
});
app.get("/api/chat/rooms/:roomId/messages", authRequired, requirePermission("chat:read"), async(req,res)=>{
  try{ res.json(await query("SELECT m.*, u.name sender_name, u.role sender_role FROM chat_messages m LEFT JOIN users u ON u.id=m.sender_id WHERE room_id=? ORDER BY created_at ASC LIMIT 100", [req.params.roomId]));}
  catch(err){res.status(500).json({error:err.message});}
});
app.post("/api/chat/rooms/:roomId/messages", authRequired, requirePermission("chat:send"), async(req,res)=>{
  try{ const [r]=await pool.execute("INSERT INTO chat_messages (room_id,sender_id,message) VALUES (?,?,?)",[req.params.roomId,req.user.id,req.body.message]); res.json({success:true,id:r.insertId});}
  catch(err){res.status(500).json({error:err.message});}
});

app.listen(PORT, () => console.log(`API running on port ${PORT}`));
