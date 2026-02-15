const express = require('express');
const { Pool } = require('pg');
const multer = require('multer');
const path = require('path');
const fs = require('fs');
const cors = require('cors');
const bcrypt = require('bcrypt');
const crypto = require('crypto');
const nodemailer = require('nodemailer');

const app = express();

require('dotenv').config();

const port = process.env.PORT || 3000;

// --------------------
// BASIC MIDDLEWARE
// --------------------
const allowedOrigins = (process.env.CORS_ORIGIN || '')
  .split(',')
  .map(o => o.trim())
  .filter(Boolean);

app.use(cors({
  origin: (origin, cb) => {
    if (!origin || allowedOrigins.length === 0 || allowedOrigins.includes(origin)) return cb(null, true);
    return cb(new Error('Not allowed by CORS'));
  },
  credentials: true
}));
app.use(express.json({ limit: '2mb' }));

// Serve static (optional; fine if you host frontend separately)
app.use(express.static('public'));

// --------------------
// UPLOADS SETUP
// --------------------
const uploadDir = path.join(__dirname, 'uploads');
if (!fs.existsSync(uploadDir)) fs.mkdirSync(uploadDir, { recursive: true });
app.use('/uploads', express.static(uploadDir));

// --------------------
// DATABASE: NEON READY
// --------------------
if (!process.env.DATABASE_URL) {
  console.warn("⚠️ DATABASE_URL is not set. Server will fail DB queries until you set it.");
}

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.DATABASE_URL ? { require: true, rejectUnauthorized: false } : false,
  max: 10,
  idleTimeoutMillis: 15000,
  connectionTimeoutMillis: 30000,
});

pool.on("error", (err) => {
  console.error("❌ Unexpected PG pool error (kept server alive):", err.message);
});

// Quick DB sanity check on boot (helps you catch config problems early)
(async () => {
  try {
    const r = await pool.query('SELECT NOW() as now');
    console.log('✅ DB connected:', r.rows[0].now);
  } catch (e) {
    console.error('❌ DB connection failed:', e.message);
  }
})();

// Simple health endpoint (useful on Render)
app.get('/health', async (req, res) => {
  try {
    await pool.query('SELECT 1');
    res.json({ ok: true });
  } catch (e) {
    res.status(500).json({ ok: false, error: e.message });
  }
});

// --------------------
// EMAIL CONFIG
// --------------------
// NOTE: We keep your current transporter, but make it env-based for hosting.
// If env vars are missing, email will fail and your fallback will still work.
const transporter = nodemailer.createTransport({
  service: 'gmail',
  auth: {
    user: process.env.EMAIL_USER,
    pass: process.env.EMAIL_APP_PASS
  }
});

// --------------------
// MULTER CONFIG
// --------------------
const storage = multer.diskStorage({
  destination: (req, file, cb) => cb(null, uploadDir),
  filename: (req, file, cb) =>
    cb(null, Date.now() + '-' + Math.round(Math.random() * 1e9) + path.extname(file.originalname))
});

const upload = multer({ storage: storage, limits: { files: 15 } });

// =================================================
// 1. AUTHENTICATION & RESET
// =================================================

app.post('/api/auth/signup', async (req, res) => {
  try {
    const { fullName, email, phone, nida, password, role } = req.body;

    const userCheck = await pool.query("SELECT * FROM Users WHERE email = $1", [email.toLowerCase()]);
    if (userCheck.rows.length > 0) return res.status(400).json({ error: "Email already in use." });

    const salt = await bcrypt.genSalt(10);
    const hashedPassword = await bcrypt.hash(password, salt);

    await pool.query(
      `INSERT INTO Users (full_name, email, phone, nida_number, password, role, is_verified_agent, subscription_plan, status) 
       VALUES ($1, $2, $3, $4, $5, $6, FALSE, 'Free', 'Active')`,
      [fullName, email.toLowerCase(), phone, nida, hashedPassword, role || 'Seeker']
    );

    res.json({ message: "Account created!" });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Error creating account" });
  }
});

app.post('/api/auth/login', async (req, res) => {
  try {
    const email = req.body.email.trim().toLowerCase();
    const plainPassword = req.body.password.trim();

    const result = await pool.query("SELECT * FROM Users WHERE LOWER(email) = $1", [email]);
    if (result.rows.length === 0) return res.status(400).json({ error: "Invalid Credentials" });

    const user = result.rows[0];
    const validPassword = await bcrypt.compare(plainPassword, user.password);
    if (!validPassword) return res.status(400).json({ error: "Invalid Credentials" });

    if (user.status === 'Banned') return res.status(403).json({ error: "Account Banned" });

        // Subscription expiry check
    if (user.subscription_plan === 'Pro' && user.subscription_end_date && new Date(user.subscription_end_date) < new Date()) {
      await pool.query("UPDATE Users SET subscription_plan = 'Free', is_verified_agent = FALSE WHERE user_id = $1", [user.user_id]);
      user.subscription_plan = 'Free';
    }

    res.json({
      message: "Success",
      user: { id: user.user_id, name: user.full_name, role: user.role, plan: user.subscription_plan, phone: user.phone }
    });
  } catch (err) {
    res.status(500).json({ error: "Server Error" });
  }
});

// --- FORGOT PASSWORD ROUTE ---
app.post('/api/auth/forgot-password', async (req, res) => {
  try {
    const { email } = req.body;
    const user = await pool.query("SELECT * FROM Users WHERE email = $1", [email.toLowerCase()]);

    if (user.rows.length === 0) {
      return res.status(404).json({ error: "Email not found" });
    }

    // 1. Generate Token
    const token = crypto.randomBytes(20).toString('hex');
    const expires = new Date(Date.now() + 3600000); // 1 hour

    // 2. Save Token to Database
    await pool.query(
      "UPDATE Users SET reset_token = $1, reset_expires = $2 WHERE email = $3",
      [token, expires, email.toLowerCase()]
    );

    // 3. Create Link (hosting-safe)
    const frontendBase = (process.env.FRONTEND_URL || "http://127.0.0.1:3000").replace(/\/$/, "");
    const resetLink = `${frontendBase}/reset-password.html?token=${token}`;

    // 4. Try to Send Email
    try {
      const mailOptions = {
        from: `"InzuLink Security" <${process.env.EMAIL_USER || 'ephremdushime250@gmail.com'}>`,
        to: email,
        subject: 'Password Reset Request - InzuLink',
        html: `
          <h3>Reset Your Password</h3>
          <p>Click the link below to set a new password:</p>
          <a href="${resetLink}" style="padding:10px 20px; background:#0f172a; color:white; text-decoration:none; border-radius:5px;">Reset Password</a>
          <p>If you didn't ask for this, please ignore this email.</p>
        `
      };

      await transporter.sendMail(mailOptions);
      console.log(`✅ EMAIL SENT to ${email}`);
      res.json({ message: "Reset link sent to your email!" });

    } catch (emailError) {
      console.log("-------------------------------------------------------");
      console.log("⚠️ EMAIL ERROR: Could not send email (Check App Password)");
      console.log(`🔗 USE THIS LINK TO RESET: ${resetLink}`);
      console.log("-------------------------------------------------------");

      res.json({ message: "Simulation Mode: Check Server Console for Link!" });
    }

  } catch (e) {
    console.error(e);
    res.status(500).json({ error: "Server Error" });
  }
});

app.post('/api/auth/reset-password', async (req, res) => {
  try {
    const { token } = req.body;
    const newPassword = req.body.newPassword || req.body.password; // accept both

    const user = await pool.query("SELECT * FROM Users WHERE reset_token = $1 AND reset_expires > NOW()", [token]);
    if (user.rows.length === 0) return res.status(400).json({ error: "Invalid or expired token" });

    if (!newPassword || String(newPassword).length < 8) {
      return res.status(400).json({ error: "Password must be at least 8 characters" });
    }

    const salt = await bcrypt.genSalt(10);
    const hashedPassword = await bcrypt.hash(newPassword, salt);

    await pool.query(
      "UPDATE Users SET password = $1, reset_token = NULL, reset_expires = NULL WHERE user_id = $2",
      [hashedPassword, user.rows[0].user_id]
    );

    res.json({ message: "Password updated successfully!" });
  } catch (e) {
    res.status(500).json({ error: "Server Error" });
  }
});

// =================================================
// 2. PROPERTIES & FEED
// =================================================

app.post('/api/properties', upload.fields([{ name: 'photos', maxCount: 10 }, { name: 'video', maxCount: 1 }]), async (req, res) => {
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    const { owner_id, district, sector, cell, village, price, bedrooms, listing_type, category, upi, land_size, description, phone, lat, lng, payerPhone } = req.body;

    let videoPath = null;
    if (req.files['video'] && req.files['video'][0]) videoPath = req.files['video'][0].path;

    const userRes = await client.query("SELECT subscription_plan FROM Users WHERE user_id = $1", [owner_id]);

    if (userRes.rows.length === 0) {
      await client.query('ROLLBACK');
      if (videoPath) fs.unlink(videoPath, () => {});
      return res.status(401).json({ error: "Session Invalid. Please Logout and Login again." });
    }

    if (userRes.rows[0].subscription_plan === 'Free') {
      const countRes = await client.query("SELECT COUNT(*) FROM Properties WHERE owner_id = $1 AND status = 'Available'", [owner_id]);
      if (parseInt(countRes.rows[0].count) >= 4) {
        await client.query('ROLLBACK');
        if (videoPath) fs.unlink(videoPath, () => {});
        return res.status(403).json({ error: "LIMIT_REACHED" });
      }
    }

    const promoStatus = payerPhone ? 'Pending' : 'None';
    const autoTitle = category === 'Land'
      ? `${category} for ${listing_type} in ${sector}`
      : `${bedrooms || 0} Bedroom ${category} in ${sector}`;

    const insertRes = await client.query(`
      INSERT INTO Properties (district, sector, cell, village, price_per_month, bedrooms, title, description, status, listing_type, category, upi, land_size, contact_phone, owner_id, latitude, longitude, status_updated_at, views_count, is_featured, promotion_status, payer_phone, video_path) 
      VALUES ($1, $2, $3, $4, $5, $6, $7, $8, 'Available', $9, $10, $11, $12, $13, $14, $15, $16, NOW(), 0, FALSE, $17, $18, $19)
      RETURNING property_id
    `,
    [district, sector, cell, village, price, bedrooms || 0, autoTitle, description, listing_type, category, upi, land_size || 0, phone, owner_id, lat || null, lng || null, promoStatus, payerPhone || null, videoPath]);

    const pid = insertRes.rows[0].property_id;

    if (req.files['photos']) {
      for (const file of req.files['photos']) {
        await client.query("INSERT INTO PropertyImages (property_id, image_path) VALUES ($1, $2)", [pid, file.path]);
      }
    }

    await client.query('COMMIT');
    res.json({ message: "Success" });

  } catch (e) {
    await client.query('ROLLBACK');
    console.error(e);
    res.status(500).json({ error: "Server Error" });
  } finally {
    client.release();
  }
});

app.get('/api/properties', async (req, res) => {
  try {
    const result = await pool.query(`
      SELECT p.*, u.is_verified_agent, 
      COALESCE(json_agg(DISTINCT pi.image_path) FILTER (WHERE pi.image_path IS NOT NULL), '[]') as images,
      COALESCE(AVG(r.rating), 0) as avg_rating, COUNT(DISTINCT r.id) as review_count
      FROM Properties p JOIN Users u ON p.owner_id = u.user_id
      LEFT JOIN PropertyImages pi ON p.property_id = pi.property_id
      LEFT JOIN Reviews r ON p.property_id = r.property_id
      WHERE p.status = 'Available' OR (p.status = 'Sold' AND p.status_updated_at > NOW() - INTERVAL '24 HOURS')
      GROUP BY p.property_id, u.is_verified_agent
      ORDER BY p.is_featured DESC, p.property_id DESC
    `);

    const rows = result.rows.map(row => ({
      ...row,
      avg_rating: parseFloat(row.avg_rating).toFixed(1),
      review_count: parseInt(row.review_count)
    }));

    res.json(rows);
  } catch (e) {
    res.status(500).json([]);
  }
});

app.get('/api/my-properties/:id', async (req, res) => {
  try {
    const r = await pool.query(`
      SELECT p.*, COALESCE(json_agg(pi.image_path) FILTER (WHERE pi.image_path IS NOT NULL), '[]') as images
      FROM Properties p
      LEFT JOIN PropertyImages pi ON p.property_id = pi.property_id
      WHERE p.owner_id = $1
      GROUP BY p.property_id
      ORDER BY p.property_id DESC
    `, [req.params.id]);

    res.json(r.rows);
  } catch (e) {
    res.status(500).json([]);
  }
});

app.delete('/api/properties/:id', async (req, res) => {
  try {
    const propId = req.params.id;
    const imgResult = await pool.query("SELECT image_path FROM PropertyImages WHERE property_id = $1", [propId]);
    const vidResult = await pool.query("SELECT video_path FROM Properties WHERE property_id = $1", [propId]);

    await pool.query('DELETE FROM Properties WHERE property_id=$1', [propId]);

    imgResult.rows.forEach(img => { if (img.image_path) fs.unlink(img.image_path, () => {}); });
    if (vidResult.rows.length > 0 && vidResult.rows[0].video_path) fs.unlink(vidResult.rows[0].video_path, () => {});

    res.json({ msg: "Deleted" });
  } catch (e) {
    res.status(500).json({ error: "Error deleting" });
  }
});

app.put('/api/properties/:id/status', async (req, res) => {
  await pool.query('UPDATE Properties SET status=$1, status_updated_at=NOW() WHERE property_id=$2', [req.body.status, req.params.id]);
  res.json({ msg: "Updated" });
});

app.post('/api/properties/:id/click', async (req, res) => {
  await pool.query('UPDATE Properties SET views_count=COALESCE(views_count,0)+1 WHERE property_id=$1', [req.params.id]);
  res.sendStatus(200);
});

// =================================================
// 3. REVIEWS & RATINGS
// =================================================

app.post('/api/reviews', async (req, res) => {
  try {
    const { property_id, user_id, rating, comment } = req.body;
    const check = await pool.query("SELECT * FROM Reviews WHERE property_id = $1 AND user_id = $2", [property_id, user_id]);
    if (check.rows.length > 0) return res.status(400).json({ error: "Already reviewed." });

    await pool.query("INSERT INTO Reviews (property_id, user_id, rating, comment) VALUES ($1, $2, $3, $4)", [property_id, user_id, rating, comment]);
    res.json({ message: "Review posted!" });
  } catch (e) {
    res.status(500).json({ error: "Server Error" });
  }
});

app.get('/api/reviews/:propId', async (req, res) => {
  try {
    const result = await pool.query(
      "SELECT r.*, u.full_name FROM Reviews r JOIN Users u ON r.user_id = u.user_id WHERE r.property_id = $1 ORDER BY r.created_at DESC",
      [req.params.propId]
    );
    res.json(result.rows);
  } catch (e) {
    res.status(500).json([]);
  }
});

// =================================================
// 4. ADMIN, CONTRACTS & PAYMENTS
// =================================================

app.post('/api/contracts', async (req, res) => {
  try {
    const { lName, tName, tID, district, rent } = req.body;
    await pool.query(
      "INSERT INTO ContractLogs (landlord_name, tenant_name, tenant_id, property_district, rent_amount) VALUES ($1, $2, $3, $4, $5)",
      [lName, tName, tID, district, rent]
    );
    res.json({ status: 'Logged' });
  } catch (e) {
    res.status(500).json({ error: "Error" });
  }
});

app.get('/api/admin/contracts', async (req, res) => {
  try {
    const r = await pool.query("SELECT * FROM ContractLogs ORDER BY generated_at DESC");
    res.json(r.rows);
  } catch (e) {
    res.status(500).json([]);
  }
});

// PAYMENT SIMULATION
app.post('/api/payment/pay', async (req, res) => {
  const { userId, amount, phoneNumber, type, propertyId } = req.body;
  console.log(`💸 Processing: ${amount} RWF - ${phoneNumber}`);

  setTimeout(async () => {
    try {
      if (type === 'ProSubscription') {
        const expiry = new Date(); expiry.setDate(expiry.getDate() + 30);
        await pool.query(
          "UPDATE Users SET subscription_plan='Pro', is_verified_agent=TRUE, pro_request_status='Approved', subscription_end_date=$1 WHERE user_id=$2",
          [expiry, userId]
        );
      } else if (type === 'PropertyBoost') {
        await pool.query("UPDATE Properties SET is_featured=TRUE, promotion_status='Approved' WHERE property_id=$1", [propertyId]);
      }

      await pool.query(
        "INSERT INTO Transactions (user_id, amount, phone_number, payment_type, status) VALUES ($1, $2, $3, $4, 'Success')",
        [userId, amount, phoneNumber, type]
      );

      res.json({ success: true, message: "Payment Successful!" });
    } catch (e) {
      console.error(e);
      res.status(500).json({ success: false });
    }
  }, 2000);
});

app.get('/api/admin/transactions', async (req, res) => {
  try {
    const r = await pool.query(`SELECT t.*, u.full_name FROM Transactions t LEFT JOIN Users u ON t.user_id = u.user_id ORDER BY t.created_at DESC`);
    res.json(r.rows);
  } catch (e) {
    res.status(500).json([]);
  }
});

// ADMIN - PRO REQUESTS
app.post('/api/users/:id/request-pro', async (req, res) => {
  await pool.query("UPDATE Users SET pro_request_status='Pending', pro_payment_phone=$1 WHERE user_id=$2", [req.body.payerPhone, req.params.id]);
  res.json({ message: "Sent" });
});

app.get('/api/admin/pro-requests', async (req, res) => {
  const r = await pool.query("SELECT user_id, full_name, pro_payment_phone FROM Users WHERE pro_request_status='Pending'");
  res.json(r.rows);
});

app.put('/api/users/:id/approve-pro', async (req, res) => {
  const expiry = new Date(); expiry.setDate(expiry.getDate() + 30);
  await pool.query(
    "UPDATE Users SET subscription_plan='Pro', is_verified_agent=TRUE, pro_request_status='Approved', subscription_end_date=$1 WHERE user_id=$2",
    [expiry, req.params.id]
  );
  res.json({ message: "Approved" });
});

// ADMIN - PROPERTY PROMOTIONS
app.put('/api/properties/:id/feature', async (req, res) => {
  const { isFeatured, isRejection } = req.body;
  let q = isRejection
    ? "UPDATE Properties SET promotion_status='Rejected', is_featured=FALSE WHERE property_id=$1"
    : "UPDATE Properties SET is_featured=$1, promotion_status='Approved' WHERE property_id=$2";

  if (isRejection) {
    await pool.query(q, [req.params.id]);
  } else {
    await pool.query(q, [isFeatured, req.params.id]);
  }
  res.json({ msg: "Ok" });
});

app.post('/api/properties/:id/request-promo', async (req, res) => {
  await pool.query("UPDATE Properties SET promotion_status='Pending', payer_phone=$1 WHERE property_id=$2", [req.body.payerPhone, req.params.id]);
  res.json({ msg: "Ok" });
});

app.get('/api/admin/pending-payments', async (req, res) => {
  const r = await pool.query("SELECT property_id, title, payer_phone FROM Properties WHERE promotion_status='Pending'");
  res.json(r.rows);
});

// ADMIN - ANALYTICS & USERS
app.get('/api/admin/reports', async (req, res) => {
  try {
    const avgPrice = await pool.query(`
      SELECT district, ROUND(AVG(price_per_month)) as avg_price 
      FROM Properties 
      WHERE listing_type='Rent' AND status='Available' 
      GROUP BY district 
      ORDER BY avg_price DESC
    `);

    const popCat = await pool.query(`SELECT category, COUNT(*) as count FROM Properties WHERE status='Available' GROUP BY category`);
    const trends = await pool.query(`SELECT term, COUNT(*) as searches FROM SearchLogs GROUP BY term ORDER BY searches DESC LIMIT 5`);

    res.json({ pricing: avgPrice.rows, inventory: popCat.rows, demand: trends.rows || [] });
  } catch (e) {
    res.json({ pricing: [], inventory: [], demand: [] });
  }
});

app.get('/api/analytics/stats', async (req, res) => {
  const r = await pool.query(`
    SELECT
      (SELECT COUNT(*) FROM Users) as users,
      (SELECT COUNT(*) FROM Properties) as props,
      (SELECT SUM(views_count) FROM Properties) as leads,
      (SELECT COALESCE(AVG(price_per_month),0) FROM Properties WHERE listing_type='Rent') as avg
  `);
  res.json({ users: r.rows[0].users, properties: r.rows[0].props, leads: r.rows[0].leads || 0, avgRent: Math.round(r.rows[0].avg) });
});

app.get('/api/users', async (req, res) => {
  const r = await pool.query("SELECT * FROM Users ORDER BY user_id DESC");
  res.json(r.rows);
});

app.put('/api/users/:id/ban', async (req, res) => {
  await pool.query("UPDATE Users SET status='Banned' WHERE user_id=$1", [req.params.id]);
  res.json({});
});

app.put('/api/users/:id/activate', async (req, res) => {
  await pool.query("UPDATE Users SET status='Active' WHERE user_id=$1", [req.params.id]);
  res.json({});
});

// currently a no-op but kept for compatibility
app.post('/api/analytics/search', async (req, res) => {
  res.sendStatus(200);
});

// =================================================
// 5. JOBS & FAVORITES
// =================================================

app.get('/api/jobs', async (req, res) => {
  try {
    const result = await pool.query("SELECT * FROM Jobs WHERE status = 'Open' ORDER BY created_at DESC");
    res.json(result.rows);
  } catch (e) {
    res.status(500).json([]);
  }
});

app.post('/api/jobs', async (req, res) => {
  try {
    const { title, description, link } = req.body;
    await pool.query("INSERT INTO Jobs (title, description, application_link) VALUES ($1, $2, $3)", [title, description, link]);
    res.json({ message: "Job Posted" });
  } catch (e) {
    res.status(500).json({ error: "Error" });
  }
});

app.delete('/api/jobs/:id', async (req, res) => {
  try {
    await pool.query("DELETE FROM Jobs WHERE job_id = $1", [req.params.id]);
    res.json({ message: "Job Deleted" });
  } catch (e) {
    res.status(500).json({ error: "Error" });
  }
});

app.post('/api/favorites', async (req, res) => {
  try {
    const { userId, propertyId } = req.body;
    const check = await pool.query("SELECT * FROM Favorites WHERE user_id = $1 AND property_id = $2", [userId, propertyId]);

    if (check.rows.length > 0) {
      await pool.query("DELETE FROM Favorites WHERE user_id = $1 AND property_id = $2", [userId, propertyId]);
      res.json({ message: "Removed from Wishlist", action: "removed" });
    } else {
      await pool.query("INSERT INTO Favorites (user_id, property_id) VALUES ($1, $2)", [userId, propertyId]);
      res.json({ message: "Added to Wishlist!", action: "added" });
    }
  } catch (e) {
    res.status(500).json({ error: "Error" });
  }
});

app.get('/api/favorites/:userId', async (req, res) => {
  try {
    const r = await pool.query(`
      SELECT p.*, COALESCE(json_agg(pi.image_path) FILTER (WHERE pi.image_path IS NOT NULL), '[]') as images
      FROM Favorites f
      JOIN Properties p ON f.property_id = p.property_id
      LEFT JOIN PropertyImages pi ON p.property_id = pi.property_id
      WHERE f.user_id = $1
      GROUP BY p.property_id, f.saved_at
      ORDER BY f.saved_at DESC
    `, [req.params.userId]);

    res.json(r.rows);
  } catch (e) {
    res.status(500).json([]);
  }
});

// =========================
// ADMIN: TIME-SERIES (Last N days)
// =========================
// GET /api/admin/timeseries?days=30
app.get('/api/admin/timeseries', async (req, res) => {
  try {
    const daysRaw = parseInt(req.query.days || '30', 10);
    const days = Number.isFinite(daysRaw) ? Math.min(Math.max(daysRaw, 7), 365) : 30;

    const q = `
      WITH dates AS (
        SELECT generate_series(
          CURRENT_DATE - ($1::int - 1),
          CURRENT_DATE,
          interval '1 day'
        )::date AS day
      ),
      u AS (
        SELECT created_at::date AS day, COUNT(*)::int AS cnt
        FROM Users
        GROUP BY 1
      ),
      p AS (
        SELECT created_at::date AS day, COUNT(*)::int AS cnt
        FROM Properties
        GROUP BY 1
      ),
      t AS (
        SELECT created_at::date AS day, COUNT(*)::int AS cnt
        FROM Transactions
        GROUP BY 1
      ),
      c AS (
        SELECT generated_at::date AS day, COUNT(*)::int AS cnt
        FROM ContractLogs
        GROUP BY 1
      )
      SELECT
        d.day,
        COALESCE(u.cnt, 0) AS users,
        COALESCE(p.cnt, 0) AS properties,
        COALESCE(t.cnt, 0) AS transactions,
        COALESCE(c.cnt, 0) AS contracts
      FROM dates d
      LEFT JOIN u ON u.day = d.day
      LEFT JOIN p ON p.day = d.day
      LEFT JOIN t ON t.day = d.day
      LEFT JOIN c ON c.day = d.day
      ORDER BY d.day ASC;
    `;

    const result = await pool.query(q, [days]);
    res.json({ days, series: result.rows });
  } catch (e) {
    console.error(e);
    res.status(500).json({ days: 30, series: [] });
  }
});

// =========================
// ADMIN: Featured Listings
// =========================

// Get all featured properties
app.get('/api/admin/featured-properties', async (req, res) => {
  try {
    const q = `
      SELECT
        property_id, title, location, district, price, category,
        is_featured, created_at, landlord_id
      FROM Properties
      WHERE is_featured = TRUE
      ORDER BY created_at DESC
      LIMIT 200;
    `;
    const result = await pool.query(q);
    res.json(result.rows);
  } catch (e) {
    console.error(e);
    res.status(500).json([]);
  }
});

// Toggle featured/unfeatured
app.put('/api/admin/featured-properties/:propertyId', async (req, res) => {
  try {
    const propertyId = parseInt(req.params.propertyId, 10);
    const { isFeatured } = req.body || {};

    if (!Number.isFinite(propertyId)) {
      return res.status(400).json({ error: "Invalid propertyId" });
    }
    if (typeof isFeatured !== "boolean") {
      return res.status(400).json({ error: "isFeatured must be boolean" });
    }

    const q = `
      UPDATE Properties
      SET is_featured = $1
      WHERE property_id = $2
      RETURNING property_id, title, is_featured;
    `;
    const result = await pool.query(q, [isFeatured, propertyId]);
    res.json(result.rows[0] || null);
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: "Server error" });
  }
});

// =========================
// ADMIN: Property Moderation
// =========================

// List properties for moderation
// GET /api/admin/properties?status=Pending&limit=100
app.get('/api/admin/properties', async (req, res) => {
  try {
    const status = (req.query.status || "Pending").toString();
    const limitRaw = parseInt(req.query.limit || "100", 10);
    const limit = Number.isFinite(limitRaw) ? Math.min(Math.max(limitRaw, 10), 300) : 100;

    const q = `
      SELECT
        p.property_id, p.title, p.location, p.district, p.price, p.category,
        p.status, p.rejection_reason, p.is_featured, p.is_deleted,
        p.created_at, p.landlord_id,
        u.full_name AS landlord_name, u.phone AS landlord_phone
      FROM Properties p
      LEFT JOIN Users u ON u.user_id = p.landlord_id
      WHERE p.is_deleted = FALSE
        AND p.status = $1
      ORDER BY p.created_at DESC
      LIMIT $2;
    `;
    const r = await pool.query(q, [status, limit]);
    res.json(r.rows);
  } catch (e) {
    console.error(e);
    res.status(500).json([]);
  }
});

// Approve property
app.put('/api/admin/properties/:propertyId/approve', async (req, res) => {
  try {
    const propertyId = parseInt(req.params.propertyId, 10);
    if (!Number.isFinite(propertyId)) return res.status(400).json({ error: "Invalid propertyId" });

    const q = `
      UPDATE Properties
      SET status='Approved', rejection_reason=NULL
      WHERE property_id=$1
      RETURNING property_id, title, status;
    `;
    const r = await pool.query(q, [propertyId]);
    res.json(r.rows[0] || null);
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: "Server error" });
  }
});

// Reject property (reason required)
app.put('/api/admin/properties/:propertyId/reject', async (req, res) => {
  try {
    const propertyId = parseInt(req.params.propertyId, 10);
    const reason = (req.body?.reason || "").toString().trim();

    if (!Number.isFinite(propertyId)) return res.status(400).json({ error: "Invalid propertyId" });
    if (!reason || reason.length < 3) return res.status(400).json({ error: "Reason is required" });

    const q = `
      UPDATE Properties
      SET status='Rejected', rejection_reason=$2
      WHERE property_id=$1
      RETURNING property_id, title, status, rejection_reason;
    `;
    const r = await pool.query(q, [propertyId, reason]);
    res.json(r.rows[0] || null);
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: "Server error" });
  }
});

// Soft delete (remove from platform)
app.delete('/api/admin/properties/:propertyId', async (req, res) => {
  try {
    const propertyId = parseInt(req.params.propertyId, 10);
    if (!Number.isFinite(propertyId)) return res.status(400).json({ error: "Invalid propertyId" });

    const q = `
      UPDATE Properties
      SET is_deleted=TRUE
      WHERE property_id=$1
      RETURNING property_id, title, is_deleted;
    `;
    const r = await pool.query(q, [propertyId]);
    res.json(r.rows[0] || null);
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: "Server error" });
  }
});

app.post('/api/auth/seed-admin', async (req, res) => {
  try {
    const { secret, fullName, email, phone, nida, password } = req.body || {};

    if (!process.env.ADMIN_SEED_SECRET) {
      return res.status(500).json({ error: "ADMIN_SEED_SECRET not set" });
    }
    if (!secret || secret !== process.env.ADMIN_SEED_SECRET) {
      return res.status(401).json({ error: "Unauthorized" });
    }

    const adminEmail = String(email || "admin@inzulink.rw").trim().toLowerCase();

    const exists = await pool.query("SELECT user_id, email, role FROM Users WHERE LOWER(email)=$1", [adminEmail]);
    if (exists.rows.length) {
      return res.json({ message: "Admin already exists", admin: exists.rows[0] });
    }

    const pass = String(password || "Admin@1234");
    if (pass.length < 8) return res.status(400).json({ error: "Password too short" });

    const hashed = await bcrypt.hash(pass, 10);

    const r = await pool.query(`
      INSERT INTO Users (full_name, email, phone, nida_number, password, role, is_verified_agent, subscription_plan, status)
      VALUES ($1,$2,$3,$4,$5,'Admin',TRUE,'Pro','Active')
      RETURNING user_id, email, role
    `, [
      fullName || "InzuLink Admin",
      adminEmail,
      phone || "0780000000",
      nida || "1199000000000000",
      hashed
    ]);

    res.json({ message: "Admin created", admin: r.rows[0] });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: "Server Error" });
  }
});

// START SERVER
app.listen(port, () => console.log(`🚀 Server running on port ${port}`));
