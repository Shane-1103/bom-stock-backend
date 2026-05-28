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

// ORDERS
app.post("/api/orders", authRequired, requirePermission("orders:create"), async (req,res) => {
  try {
    const { order_id, order_type, shop_name, customer_name, status="Pending", deadline_ship_date, warehouse_id, total=0, items=[] } = req.body;
    if (!order_id || !order_type) return res.status(400).json({ error:"ORDER ID and order_type required" });
    const conn = await pool.getConnection();
    try {
      await conn.beginTransaction();
      const [result] = await conn.execute(
        "INSERT INTO orders (order_id,order_type,shop_name,customer_name,status,deadline_ship_date,warehouse_id,total,created_by) VALUES (?,?,?,?,?,?,?,?,?)",
        [order_id,order_type,shop_name||null,customer_name||null,status,deadline_ship_date||null,warehouse_id||null,total,req.user.id]
      );
      for (const item of items) {
        await conn.execute("INSERT INTO order_items (order_id,product_id,qty,price,remark) VALUES (?,?,?,?,?)", [result.insertId,item.product_id,item.qty,item.price||0,item.remark||null]);
      }
      await conn.commit();
      res.json({ success:true, id:result.insertId });
    } catch(e) { await conn.rollback(); throw e; } finally { conn.release(); }
  } catch(err) { res.status(500).json({ error:err.message }); }
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
    const items = await query("SELECT oi.*, p.sku, p.name FROM order_items oi LEFT JOIN products p ON p.id=oi.product_id WHERE oi.order_id=?", [req.params.id]);
    const shipments = await query("SELECT * FROM order_shipments WHERE order_id=? ORDER BY ship_date DESC, ship_time DESC", [req.params.id]);
    res.json({ ...rows[0], items, shipments });
  } catch(err){ res.status(500).json({ error:err.message });}
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
    const { sku,name,category,price=0,cost=0,image_url,is_component=false } = req.body;
    const [r]=await pool.execute("INSERT INTO products (sku,name,category,price,cost,image_url,is_component) VALUES (?,?,?,?,?,?,?)",[sku,name,category||null,price,cost,image_url||null,is_component?1:0]);
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
