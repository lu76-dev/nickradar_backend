require('dotenv').config();
const express = require('express');
const cors = require('cors');
const rateLimit = require('express-rate-limit');
const { Pool } = require('pg');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const nodemailer = require('nodemailer');
const crypto = require('crypto');
const cron = require('node-cron');

const app = express();
const PORT = process.env.PORT || 3000;

const JWT_SECRET = process.env.JWT_SECRET;
if (!JWT_SECRET) { console.error('FATAL: JWT_SECRET not set'); process.exit(1); }

const ADMIN_KEY = process.env.ADMIN_KEY;
if (!ADMIN_KEY) { console.error('FATAL: ADMIN_KEY not set'); process.exit(1); }

const APP_URL = process.env.APP_URL || 'https://events.nickradar.com';

const transporter = nodemailer.createTransport({
  host: process.env.EMAIL_HOST,
  port: parseInt(process.env.EMAIL_PORT || '465'),
  secure: true,
  auth: { user: process.env.EMAIL_USER, pass: process.env.EMAIL_PASS },
});

async function sendEmail(to, subject, text) {
  try {
    await transporter.sendMail({
      from: `"nickradar" <${process.env.EMAIL_USER}>`,
      to, subject, text
    });
  } catch (err) {
    console.error('Email error:', err.message);
  }
}

const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, max: 20,
  message: { success: false, error: 'too many attempts, try again in 15 minutes' },
  standardHeaders: true, legacyHeaders: false,
});

const codeLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, max: 30,
  message: { success: false, error: 'too many attempts, try again in 15 minutes' },
  standardHeaders: true, legacyHeaders: false,
});

function requireAdminKey(req, res, next) {
  const key = req.headers['x-admin-key'];
  if (!key || key !== ADMIN_KEY) return res.status(403).json({ success: false, error: 'forbidden' });
  next();
}

function requireEventAdminAuth(req, res, next) {
  const auth = req.headers['authorization'];
  const queryToken = req.query.token;
  const tokenStr = auth ? auth.slice(7) : queryToken;
  if (!tokenStr) return res.status(401).json({ success: false, error: 'unauthorized' });
  try {
    const decoded = jwt.verify(tokenStr, JWT_SECRET);
    req.adminId = decoded.id;
    next();
  } catch {
    return res.status(401).json({ success: false, error: 'invalid token' });
  }
}

async function requireParticipantSession(req, res, next) {
  const token = req.headers['x-session-token'];
  if (!token) return res.status(401).json({ success: false, error: 'no session' });
  try {
    const result = await pool.query(
      `SELECT s.*, st.nickname, st.event_id, st.id as sticker_id, e.ends_at, e.start_at, e.status as event_status, e.event_name, e.org_name, e.timezone
       FROM session s
       JOIN sticker st ON s.sticker_id = st.id
       JOIN event e ON s.event_id = e.id
       WHERE s.token = $1 AND s.expires_at > NOW()`,
      [token]
    );
    if (result.rows.length === 0) return res.status(401).json({ success: false, error: 'session expired' });
    const s = result.rows[0];
    if (s.event_status === 'stopped' || s.event_status === 'finished') {
      return res.status(401).json({ success: false, error: 'event ended' });
    }
    req.session = s;
    await pool.query('UPDATE session SET last_seen_at = NOW() WHERE token = $1', [token]);
    next();
  } catch (err) {
    console.error('Session check error:', err);
    return res.status(500).json({ success: false, error: 'server error' });
  }
}

app.use(cors({
  origin: [
    'https://nickradar.com', 'https://www.nickradar.com',
    'https://app.nickradar.com', 'https://events.nickradar.com',
    'https://admin.nickradar.com'
  ],
  methods: ['GET', 'POST', 'PUT', 'DELETE'],
  allowedHeaders: ['Content-Type', 'Authorization', 'x-admin-key', 'x-session-token'],
}));
app.set('trust proxy', 1);
app.use(express.json({ limit: '5mb' }));

const pool = new Pool({
  host: process.env.DB_HOST,
  port: process.env.DB_PORT,
  user: process.env.DB_USER,
  password: process.env.DB_PASSWORD,
  database: process.env.DB_NAME,
});

pool.connect((err, client, release) => {
  if (err) { console.error('DB connection error:', err.stack); }
  else { console.log('Connected to PostgreSQL'); release(); }
});

function getClientIP(req) {
  return req.headers['x-forwarded-for']?.split(',')[0].trim()
    || req.headers['x-real-ip']
    || req.connection.remoteAddress
    || 'unknown';
}

const NICKNAMES = [
  'WOLF','HAWK','TITAN','REX','BLADE','STORM','IRON','HUNTER','FLEX','SPIKE',
  'LUNA','IRIS','NOVA','JADE','STELLA','PEARL','AURORA','ROSE','IVY','SKYE',
  'ECHO','PIXEL','GHOST','EMBER','RAVEN','FLUX','SPARK','CIPHER','DRIFT','VIBE',
  'VIPER','LYNX','RIDGE','BLAZE','FLINT','RAZOR','DUSK','STEEL','FORGE','APEX',
  'MIST','GLOW','VELVET','AMBER','SAGE','FERN','OPAL','REED','WREN','CORAL',
  'NEXUS','GLITCH','BYTE','GRID','NODE','PULSE','VECTOR','SIGNAL','CORE','ORBIT',
  'ZARA','LENA','NORA','SUKI','MIRA','TARA','LILA','EDEN','ARIA','ELSA',
  'CROW','BEAR','FOX','OWL','KITE','IBIS','SWIFT','CRANE',
  'HAZE','GALE','FROST','SLEET','MOOR','VALE','CREST','FORD','GLEN','HOLM',
  'ACE','JOLT','RIOT','DASH','VOLT','GRIT','ZEAL','BOLT','RUSH','FURY',
  'ONYX','SLATE','COAL','MICA','QUARTZ','BASALT','CHALK','SHALE','CLAY',
  'MYTH','LORE','RUNE','OMEN','TOTEM','SIGIL','ORACLE','DRUID','SEER','SHADE',
  'CHROME','COBALT','INDIGO','TEAL','AZURE','OCHRE','SIENNA','IVORY',
  'ZERO','AXIOM','NULL','DELTA','OMEGA','SIGMA','THETA','KAPPA','LAMBDA','ZETA',
  'BISON','DINGO','GECKO','JACKAL','LEMUR','MANTA','OSPREY','PANDA','QUOKKA','TAPIR',
  'ALTO','BASS','CHORD','NOTE','TEMPO','PITCH','SCALE','TREBLE','BEAT','TUNE',
  'ARCH','DOME','SPIRE','GABLE','LEDGE','NICHE','PORCH','VAULT','ALCOVE','TOWER',
  'COLT','FAWN','FOAL','HARE','LAMB','WHELP','KITTEN','PONY','CHICK','FILLY',
  'BROOK','CREEK','FALLS','GORGE','INLET','MARSH','MESA','SHOAL','STEPPE',
  'BLINK','FLASH','FLARE','GLEAM','GLINT','SHIMMER','BEAM','SHINE'
];

function generateNicknames(count) {
  const p = [...NICKNAMES];
  for (let i = p.length - 1; i > 0; i--) {
    const j = Math.floor(Math.random() * (i + 1));
    [p[i], p[j]] = [p[j], p[i]];
  }
  const result = [];
  let i = 0;
  while (result.length < count) {
    result.push(p[i % p.length] + (i >= p.length ? '_' + Math.floor(i / p.length) : ''));
    i++;
  }
  return result;
}

function generateCode() {
  return String(Math.floor(1000 + Math.random() * 9000));
}

function localToUTC(localDateStr, timezone) {
  const [datePart, timePart] = localDateStr.split('T');
  const [year, month, day] = datePart.split('-').map(Number);
  const [hour, minute] = (timePart || '00:00').split(':').map(Number);
  let utc = Date.UTC(year, month - 1, day, hour, minute);
  for (let i = 0; i < 2; i++) {
    const local = new Date(utc).toLocaleString('en-US', {
      timeZone: timezone,
      year: 'numeric', month: '2-digit', day: '2-digit',
      hour: '2-digit', minute: '2-digit', hour12: false
    });
    const p = local.match(/(\d+)\/(\d+)\/(\d+),\s+(\d+):(\d+)/);
    const localUTC = Date.UTC(+p[3], +p[1] - 1, +p[2], +p[4] % 24, +p[5]);
    utc += Date.UTC(year, month - 1, day, hour, minute) - localUTC;
  }
  return new Date(utc);
}

const TZ_ABBR = {
  'Europe/Vienna':'CET/CEST','Europe/Berlin':'CET/CEST','Europe/London':'GMT/BST',
  'Europe/Paris':'CET/CEST','Europe/Rome':'CET/CEST','Europe/Madrid':'CET/CEST',
  'Europe/Amsterdam':'CET/CEST','Europe/Zurich':'CET/CEST','Europe/Warsaw':'CET/CEST',
  'Europe/Stockholm':'CET/CEST','Europe/Helsinki':'EET/EEST','Europe/Athens':'EET/EEST',
  'Europe/Lisbon':'WET/WEST','Europe/Moscow':'MSK','Europe/Istanbul':'TRT',
  'America/New_York':'ET','America/Chicago':'CT','America/Denver':'MT',
  'America/Los_Angeles':'PT','America/Toronto':'ET','America/Vancouver':'PT',
  'America/Mexico_City':'CT','America/Sao_Paulo':'BRT','America/Buenos_Aires':'ART',
  'America/Bogota':'COT','Asia/Dubai':'GST','Asia/Kolkata':'IST',
  'Asia/Bangkok':'ICT','Asia/Singapore':'SGT','Asia/Shanghai':'CST',
  'Asia/Tokyo':'JST','Asia/Seoul':'KST','Australia/Sydney':'AEST/AEDT',
  'Pacific/Auckland':'NZST/NZDT','Africa/Cairo':'EET','Africa/Johannesburg':'SAST',
  'Africa/Lagos':'WAT','Africa/Nairobi':'EAT'
};

function tzAbbr(tz) { return TZ_ABBR[tz] || tz; }

async function getNextInvoiceNumber() {
  const result = await pool.query(
    "SELECT MAX(CAST(SUBSTRING(invoice_number FROM 5) AS INTEGER)) as max_num FROM invoice WHERE invoice_number LIKE 'EAR-%'"
  );
  const n = (parseInt(result.rows[0].max_num) || 0) + 1;
  return 'EAR-' + String(n).padStart(8, '0');
}

function formatCustomerId(id) {
  return 'EA-' + String(id).padStart(4, '0');
}

function formatEventId(id) {
  return 'EV-' + String(id).padStart(8, '0');
}

function calcPrice(count) {
  if (count >= 5000) return count * 0.40;
  if (count >= 2000) return count * 0.50;
  if (count >= 1000) return count * 0.60;
  if (count >= 500)  return count * 0.70;
  if (count >= 200)  return count * 0.80;
  if (count >= 100)  return count * 0.90;
  return count * 1.00;
}

function unitPrice(count) {
  if (count >= 5000) return 0.40;
  if (count >= 2000) return 0.50;
  if (count >= 1000) return 0.60;
  if (count >= 500)  return 0.70;
  if (count >= 200)  return 0.80;
  if (count >= 100)  return 0.90;
  return 1.00;
}

async function generateUniqueCodes(eventId, count) {
  const globalUsed = await pool.query(
    `SELECT code FROM sticker s JOIN event e ON s.event_id = e.id
     WHERE e.status IN ('active','pending') AND s.event_id != $1`,
    [eventId]
  );
  const globalSet = new Set(globalUsed.rows.map(r => r.code));
  const existing = await pool.query('SELECT code FROM sticker WHERE event_id = $1', [eventId]);
  existing.rows.forEach(r => globalSet.add(r.code));
  const unique = [];
  let attempts = 0;
  while (unique.length < count && attempts < 100000) {
    attempts++;
    const c = generateCode();
    if (!globalSet.has(c)) { globalSet.add(c); unique.push(c); }
  }
  return unique;
}

async function bulkInsertStickers(eventId, nicknames, codes) {
  const count = nicknames.length;
  const eventIds = Array(count).fill(eventId);
  const statuses = Array(count).fill('unused');
  await pool.query(
    `INSERT INTO sticker (event_id, nickname, code, status, created_at)
     SELECT unnest($1::int[]), unnest($2::text[]), unnest($3::text[]), unnest($4::text[]), NOW()`,
    [eventIds, nicknames, codes, statuses]
  );
}

// ============================================================
// EVENT ADMIN AUTH
// ============================================================

app.post('/api/event-admin/register', loginLimiter, async (req, res) => {
  const { org_name, contact_name, business_type, country, email, password, confirm_password } = req.body;
  if (!org_name || !contact_name || !email || !password || !confirm_password) {
    return res.status(400).json({ success: false, error: 'all required fields must be filled' });
  }
  if (password.length < 8) {
    return res.status(400).json({ success: false, error: 'password must be at least 8 characters' });
  }
  if (password !== confirm_password) {
    return res.status(400).json({ success: false, error: 'passwords do not match' });
  }
  const mail = email.trim().toLowerCase();
  try {
    const check = await pool.query('SELECT id FROM event_admin WHERE email = $1', [mail]);
    if (check.rows.length > 0) return res.status(409).json({ success: false, error: 'email already registered' });

    const hash = await bcrypt.hash(password, 10);
    const verificationToken = crypto.randomBytes(32).toString('hex');
    const tokenExpires = new Date(Date.now() + 24 * 60 * 60 * 1000);

    await pool.query(
      `INSERT INTO event_admin (org_name, contact_name, business_type, country, email, password_hash, status, email_verified, verification_token, verification_token_expires_at, created_at)
       VALUES ($1, $2, $3, $4, $5, $6, 'pending', FALSE, $7, $8, NOW())`,
      [org_name.trim(), contact_name.trim(), business_type || null, country || null, mail, hash, verificationToken, tokenExpires]
    );

    const verifyUrl = `${APP_URL}/verify?token=${verificationToken}`;
    sendEmail(
      mail,
      'nickradar — Please verify your email',
      `Hello ${org_name},\n\nThank you for registering with nickradar.\n\nPlease verify your email address by clicking the link below:\n\n${verifyUrl}\n\nThis link expires in 24 hours.\n\nnickradar`
    );

    res.status(201).json({ success: true, message: 'registration received — please check your email to verify your account' });
  } catch (err) {
    console.error('Event admin register error:', err);
    res.status(500).json({ success: false, error: 'server error' });
  }
});

app.post('/api/event-admin/verify', loginLimiter, async (req, res) => {
  const { token } = req.body;
  if (!token) return res.status(400).json({ success: false, error: 'token required' });
  try {
    const result = await pool.query(
      'SELECT * FROM event_admin WHERE verification_token = $1 AND verification_token_expires_at > NOW()',
      [token]
    );
    if (result.rows.length === 0) {
      return res.status(400).json({ success: false, error: 'invalid or expired verification link' });
    }
    await pool.query(
      "UPDATE event_admin SET email_verified = TRUE, status = 'active', verification_token = NULL, verification_token_expires_at = NULL WHERE id = $1",
      [result.rows[0].id]
    );
    res.json({ success: true, message: 'email verified — you can now log in' });
  } catch (err) {
    console.error('Verify error:', err);
    res.status(500).json({ success: false, error: 'server error' });
  }
});

app.post('/api/event-admin/login', loginLimiter, async (req, res) => {
  const { email, password } = req.body;
  if (!email || !password) return res.status(400).json({ success: false, error: 'email and password required' });
  const mail = email.trim().toLowerCase();
  try {
    const result = await pool.query('SELECT * FROM event_admin WHERE email = $1', [mail]);
    if (result.rows.length === 0) return res.status(401).json({ success: false, error: 'invalid credentials' });
    const admin = result.rows[0];
    if (!admin.email_verified) return res.status(403).json({ success: false, error: 'please verify your email first' });
    if (admin.status === 'blocked') return res.status(403).json({ success: false, error: 'account blocked' });
    if (admin.status === 'deleted') return res.status(403).json({ success: false, error: 'account not found' });
    const match = await bcrypt.compare(password, admin.password_hash);
    if (!match) return res.status(401).json({ success: false, error: 'invalid credentials' });
    await pool.query('UPDATE event_admin SET last_login_at = NOW() WHERE id = $1', [admin.id]);
    const token = jwt.sign({ id: admin.id }, JWT_SECRET, { expiresIn: '30d' });
    res.json({ success: true, token, admin: { id: admin.id, org_name: admin.org_name, contact_name: admin.contact_name, email: admin.email } });
  } catch (err) {
    console.error('Event admin login error:', err);
    res.status(500).json({ success: false, error: 'server error' });
  }
});

app.get('/api/event-admin/me', requireEventAdminAuth, async (req, res) => {
  try {
    const result = await pool.query(
      `SELECT id, org_name, contact_name, business_type, country, street, street_number, postal_code, city, vat,
              email, status, created_at
       FROM event_admin WHERE id = $1`,
      [req.adminId]
    );
    if (result.rows.length === 0) return res.status(404).json({ success: false, error: 'not found' });
    res.json({ success: true, admin: result.rows[0] });
  } catch (err) {
    res.status(500).json({ success: false, error: 'server error' });
  }
});

app.put('/api/event-admin/profile', requireEventAdminAuth, async (req, res) => {
  const { street, street_number, postal_code, city, vat } = req.body;
  try {
    const current = await pool.query('SELECT street, street_number, postal_code, city, vat FROM event_admin WHERE id = $1', [req.adminId]);
    if (current.rows.length === 0) return res.status(404).json({ success: false, error: 'not found' });
    const c = current.rows[0];
    await pool.query(
      'UPDATE event_admin SET street=$1, street_number=$2, postal_code=$3, city=$4, vat=$5 WHERE id=$6',
      [
        c.street || street || null,
        c.street_number || street_number || null,
        c.postal_code || postal_code || null,
        c.city || city || null,
        c.vat || vat || null,
        req.adminId
      ]
    );
    res.json({ success: true });
  } catch (err) {
    console.error('Profile update error:', err);
    res.status(500).json({ success: false, error: 'server error' });
  }
});


app.put('/api/event-admin/password', requireEventAdminAuth, async (req, res) => {
  const { new_password, confirm_password } = req.body;
  if (!new_password || !confirm_password) return res.status(400).json({ success: false, error: 'new_password and confirm_password required' });
  if (new_password.length < 8) return res.status(400).json({ success: false, error: 'password min. 8 characters' });
  if (new_password !== confirm_password) return res.status(400).json({ success: false, error: 'passwords do not match' });
  try {
    const hash = await bcrypt.hash(new_password, 10);
    await pool.query('UPDATE event_admin SET password_hash = $1 WHERE id = $2', [hash, req.adminId]);
    res.json({ success: true });
  } catch (err) {
    console.error('Password change error:', err);
    res.status(500).json({ success: false, error: 'server error' });
  }
});

app.delete('/api/event-admin/account', requireEventAdminAuth, async (req, res) => {
  try {
    await pool.query(
      "UPDATE event_admin SET status='deleted', email=CONCAT(email,'_deleted_',id) WHERE id=$1",
      [req.adminId]
    );
    res.json({ success: true });
  } catch (err) {
    console.error('Account delete error:', err);
    res.status(500).json({ success: false, error: 'server error' });
  }
});

// ============================================================
// EVENTS
// ============================================================

app.post('/api/events', requireEventAdminAuth, async (req, res) => {
  const { event_name, org_name, start_at, sticker_count, timezone, terms_accepted_at, terms_version } = req.body;
  if (!event_name || !start_at || !sticker_count) {
    return res.status(400).json({ success: false, error: 'event_name, start_at, sticker_count required' });
  }
  if (!terms_accepted_at) {
    return res.status(400).json({ success: false, error: 'terms acceptance required' });
  }
  const count = parseInt(sticker_count);
  if (count < 24) return res.status(400).json({ success: false, error: 'minimum 24 stickers' });
  if (count > 10000) return res.status(400).json({ success: false, error: 'maximum 10000 stickers' });

  const tz = timezone || 'Europe/Vienna';
  const termsIp = getClientIP(req);
  const termsVer = terms_version || 'v1.0';

  try {
    const adminResult = await pool.query('SELECT * FROM event_admin WHERE id = $1', [req.adminId]);
    if (adminResult.rows.length === 0) return res.status(404).json({ success: false, error: 'admin not found' });
    const admin = adminResult.rows[0];

    const startDate = localToUTC(start_at, tz);
    const endsAt = new Date(startDate.getTime() + 8 * 60 * 60 * 1000);

    const eventResult = await pool.query(
      `INSERT INTO event (admin_id, event_name, org_name, start_at, ends_at, timezone, status, paid, sticker_count, activated_count, connection_count, terms_accepted_at, terms_accepted_ip, terms_version, created_at)
       VALUES ($1, $2, $3, $4, $5, $6, 'pending', FALSE, $7, 0, 0, $8, $9, $10, NOW()) RETURNING *`,
      [req.adminId, event_name.trim(), (org_name || admin.org_name).trim(), startDate, endsAt, tz, count, new Date(terms_accepted_at), termsIp, termsVer]
    );
    const event = eventResult.rows[0];

    const nicknames = generateNicknames(count);
    const codes = await generateUniqueCodes(event.id, count);

    await bulkInsertStickers(event.id, nicknames, codes);

    const up = unitPrice(count);
    await pool.query(
      `INSERT INTO sticker_package (event_id, quantity, unit_price, created_at) VALUES ($1, $2, $3, NOW())`,
      [event.id, count, up]
    );

    const totalPrice = calcPrice(count).toFixed(2);
    const startFormatted = startDate.toLocaleDateString('de-AT',{day:'2-digit',month:'2-digit',year:'numeric',timeZone:tz}) + ' ' + startDate.toLocaleTimeString('de-AT',{hour:'2-digit',minute:'2-digit',timeZone:tz}) + ' ' + tzAbbr(tz);
    const emailLines = [
      'Hello ' + admin.org_name + ',',
      '',
      'Your event has been successfully created.',
      '',
      'EVENT DETAILS',
      'Event Name: ' + event_name.trim(),
      'Event ID: ' + formatEventId(event.id),
      'Date & Start: ' + startFormatted,
      'Timezone: ' + tz,
      'Stickers ordered: ' + count,
      'Total amount: EUR ' + totalPrice,
      '',
      'PAYMENT',
      'Payment is due before the event can be activated. You will receive further instructions shortly.',
      '',
      'TERMS ACCEPTANCE',
      'You confirmed the following at ' + new Date(terms_accepted_at).toISOString() + ' (IP: ' + termsIp + '):',
      '- Terms & Conditions and Privacy Policy accepted',
      'Terms version: ' + termsVer,
      '',
      'This email serves as your order confirmation. Please keep it for your records.',
      '',
      'nickradar',
      'events.nickradar.com'
    ];
    sendEmail(admin.email, 'nickradar - Event Order Confirmation', emailLines.join('\n'));

    res.status(201).json({ success: true, event });
  } catch (err) {
    console.error('Create event error:', err);
    res.status(500).json({ success: false, error: 'server error' });
  }
});


app.get('/api/events', requireEventAdminAuth, async (req, res) => {
  try {
    const result = await pool.query(
      'SELECT * FROM event WHERE admin_id = $1 ORDER BY created_at DESC',
      [req.adminId]
    );
    res.json({ success: true, events: result.rows });
  } catch (err) {
    res.status(500).json({ success: false, error: 'server error' });
  }
});

app.get('/api/events/invoices', requireEventAdminAuth, async (req, res) => {
  try {
    const result = await pool.query(
      `SELECT
         MIN(i.invoice_number) as invoice_number,
         i.event_id,
         e.event_name,
         SUM(i.quantity) as total_quantity,
         SUM(i.total) as grand_total,
         MIN(i.created_at) as created_at
       FROM invoice i
       JOIN event e ON i.event_id = e.id
       WHERE i.admin_id = $1
       GROUP BY i.event_id, e.event_name
       ORDER BY MIN(i.created_at) DESC`,
      [req.adminId]
    );
    res.json({ success: true, invoices: result.rows });
  } catch (err) {
    res.status(500).json({ success: false, error: 'server error' });
  }
});

app.get('/api/events/:id', requireEventAdminAuth, async (req, res) => {
  try {
    const event = await pool.query(
      'SELECT * FROM event WHERE id = $1 AND admin_id = $2',
      [req.params.id, req.adminId]
    );
    if (event.rows.length === 0) return res.status(404).json({ success: false, error: 'not found' });

    const stickers = await pool.query(
      'SELECT * FROM sticker WHERE event_id = $1 ORDER BY id ASC',
      [req.params.id]
    );

    res.json({ success: true, event: event.rows[0], stickers: stickers.rows });
  } catch (err) {
    res.status(500).json({ success: false, error: 'server error' });
  }
});

app.get('/api/events/:id/connections', requireEventAdminAuth, async (req, res) => {
  try {
    const event = await pool.query(
      'SELECT * FROM event WHERE id = $1 AND admin_id = $2',
      [req.params.id, req.adminId]
    );
    if (event.rows.length === 0) return res.status(404).json({ success: false, error: 'not found' });

    const result = await pool.query(
      `SELECT c.seeker_id, c.target_id, s1.nickname as seeker_nick, s2.nickname as target_nick
       FROM chat c
       JOIN sticker s1 ON c.seeker_id = s1.id
       JOIN sticker s2 ON c.target_id = s2.id
       WHERE c.event_id = $1 AND c.status = 'active'`,
      [req.params.id]
    );
    res.json({ success: true, connections: result.rows });
  } catch (err) {
    res.status(500).json({ success: false, error: 'server error' });
  }
});

app.post('/api/events/:id/stop', requireEventAdminAuth, async (req, res) => {
  try {
    const event = await pool.query(
      'SELECT * FROM event WHERE id = $1 AND admin_id = $2',
      [req.params.id, req.adminId]
    );
    if (event.rows.length === 0) return res.status(404).json({ success: false, error: 'not found' });
    await finishEvent(parseInt(req.params.id), 'event_admin');
    res.json({ success: true });
  } catch (err) {
    res.status(500).json({ success: false, error: 'server error' });
  }
});

app.post('/api/events/:id/stickers/add', requireEventAdminAuth, async (req, res) => {
  const { quantity } = req.body;
  const count = parseInt(quantity);
  if (!count || count < 5) return res.status(400).json({ success: false, error: 'minimum 5 stickers' });

  try {
    const event = await pool.query(
      'SELECT * FROM event WHERE id = $1 AND admin_id = $2',
      [req.params.id, req.adminId]
    );
    if (event.rows.length === 0) return res.status(404).json({ success: false, error: 'not found' });

    const nicknames = generateNicknames(count);
    const codes = await generateUniqueCodes(req.params.id, count);

    await bulkInsertStickers(req.params.id, nicknames, codes);

    await pool.query(
      'UPDATE event SET sticker_count = sticker_count + $1 WHERE id = $2',
      [count, req.params.id]
    );

    const up = unitPrice(count);
    await pool.query(
      `INSERT INTO sticker_package (event_id, quantity, unit_price, created_at) VALUES ($1, $2, $3, NOW())`,
      [req.params.id, count, up]
    );

    res.json({ success: true, added: count });
  } catch (err) {
    console.error('Add stickers error:', err);
    res.status(500).json({ success: false, error: 'server error' });
  }
});

// ============================================================
// STICKERS
// ============================================================

app.post('/api/stickers/:id/invalidate', requireEventAdminAuth, async (req, res) => {
  try {
    const sticker = await pool.query(
      'SELECT s.* FROM sticker s JOIN event e ON s.event_id = e.id WHERE s.id = $1 AND e.admin_id = $2',
      [req.params.id, req.adminId]
    );
    if (sticker.rows.length === 0) return res.status(404).json({ success: false, error: 'not found' });
    await pool.query(
      "UPDATE sticker SET status = 'invalidated', invalidated_at = NOW(), invalidated_by = 'event_admin' WHERE id = $1",
      [req.params.id]
    );
    await pool.query("UPDATE session SET expires_at = NOW() WHERE sticker_id = $1", [req.params.id]);
    res.json({ success: true });
  } catch (err) {
    res.status(500).json({ success: false, error: 'server error' });
  }
});

app.get('/api/events/:id/print', requireEventAdminAuth, async (req, res) => {
  try {
    const event = await pool.query(
      'SELECT * FROM event WHERE id = $1 AND admin_id = $2',
      [req.params.id, req.adminId]
    );
    if (event.rows.length === 0) return res.status(404).json({ success: false, error: 'not found' });
    const e = event.rows[0];

    const stickers = await pool.query(
      'SELECT * FROM sticker WHERE event_id = $1 ORDER BY id ASC',
      [req.params.id]
    );

    const tz = e.timezone || 'Europe/Vienna';
    const startStr = new Date(e.start_at).toLocaleDateString('en-GB', { day: '2-digit', month: '2-digit', year: '2-digit', timeZone: tz });
    const startTime = new Date(e.start_at).toLocaleTimeString('en-GB', { hour: '2-digit', minute: '2-digit', timeZone: tz });
    const endTime = new Date(e.ends_at).toLocaleTimeString('en-GB', { hour: '2-digit', minute: '2-digit', timeZone: tz });
    const dateTime = `${startStr} · ${startTime} – ${endTime}`;
    const fee = (req.query.fee || '').trim().slice(0, 20);

    const perPage = 12;
    const total = stickers.rows.length;
    const pages = Math.ceil(total / perPage);

    let sheetsHtml = '';
    for (let p = 0; p < pages; p++) {
      const pageStickers = stickers.rows.slice(p * perPage, (p + 1) * perPage);
      while (pageStickers.length < perPage) pageStickers.push(null);
      let cells = '';
      for (const s of pageStickers) {
        if (s) {
          cells += `<div class="sticker">
              <div class="sticker-top">
                <div class="code">${s.code}</div>
                ${fee ? `<div class="fee">${fee}</div>` : ''}
                <div class="bottom">${dateTime}</div>
                <div class="bottom">${e.org_name} · ${e.event_name}</div>
              </div>
              <div class="nick">${s.nickname}</div>
              <div class="sticker-bottom">
                <img class="sticker-logo" src="https://app.nickradar.com/nr_logo.png" alt="" /><span class="sticker-brand">nickradar</span>
              </div>
            </div>`;
        } else {
          cells += `<div class="sticker empty"></div>`;
        }
      }
      sheetsHtml += `<div class="page">${cells}</div>`;
    }

    const html = `<!DOCTYPE html><html><head><meta charset="UTF-8"><title>nickradar stickers — ${e.event_name}</title><style>*{margin:0;padding:0;box-sizing:border-box;}body{background:#e0e0e0;font-family:'Courier New',monospace;}.info{padding:12px 20px;font-size:12px;color:#555;}.page{width:210mm;height:297mm;background:white;margin:20px auto;display:grid;grid-template-columns:repeat(2,1fr);grid-template-rows:repeat(6,1fr);}.sticker{border-right:1px solid #999;border-bottom:1px solid #999;display:flex;flex-direction:column;align-items:center;justify-content:space-between;padding:7mm 3mm;}.sticker:nth-child(2n){border-right:none;}.sticker:nth-child(n+11){border-bottom:none;}.sticker.empty{background:#f9f9f9;}.sticker-top{width:100%;text-align:center;}.sticker-bottom{display:flex;align-items:center;justify-content:center;gap:4px;width:100%;}.nick{font-size:58px;font-weight:900;letter-spacing:1px;color:#000;text-align:center;line-height:1;font-family:'Arial Black','Arial Bold',Impact,sans-serif;flex:1;display:flex;align-items:center;justify-content:center;}.code{font-size:13px;letter-spacing:3px;color:#00aa2a;font-weight:bold;text-align:center;margin-bottom:1px;}.fee{font-size:11px;font-weight:900;color:#000;text-align:center;letter-spacing:2px;margin-top:2px;font-family:'Arial Black',sans-serif;}.fee{font-size:11px;font-weight:900;color:#000;text-align:center;letter-spacing:2px;margin-top:2px;font-family:'Arial Black','Arial Bold',sans-serif;}.bottom{font-size:6px;letter-spacing:1px;color:#bbb;text-align:center;}.sticker-logo{height:9px;width:auto;opacity:0.5;}.sticker-brand{font-size:8px;font-weight:bold;letter-spacing:2px;color:#bbb;font-family:'Courier New',monospace;}@media print{body{background:white;}.info{display:none;}.page{margin:0;box-shadow:none;}}</style></head><body><div class="info">nickradar · ${e.event_name} · ${total} stickers · ${pages} page(s) · <a href="javascript:window.print()">Print</a></div>${sheetsHtml}</body></html>`;

    res.setHeader('Content-Type', 'text/html');
    res.send(html);
  } catch (err) {
    console.error('Print error:', err);
    res.status(500).json({ success: false, error: 'server error' });
  }
});

app.get('/api/events/:id/print-back', requireEventAdminAuth, async (req, res) => {
  try {
    const event = await pool.query('SELECT * FROM event WHERE id = $1 AND admin_id = $2', [req.params.id, req.adminId]);
    if (event.rows.length === 0) return res.status(404).json({ success: false, error: 'not found' });
    const e = event.rows[0];
    const stickers = await pool.query('SELECT * FROM sticker WHERE event_id = $1 ORDER BY id ASC', [req.params.id]);
    const total = stickers.rows.length;
    const perPage = 12;
    const pages = Math.ceil(total / perPage);
    const QR_URL = 'https://api.qrserver.com/v1/create-qr-code/?size=100x100&data=https%3A%2F%2Fapp.nickradar.com&bgcolor=ffffff&color=000000&margin=2';
    const instrCell = `<div class="instr"><div class="instr-top"><div class="instr-left"><img class="instr-logo" src="https://app.nickradar.com/nr_logo.png" alt="" /><div class="instr-brand">nickradar</div></div><img class="instr-qr" src="${QR_URL}" alt="QR" /></div><div class="instr-steps"><div class="step"><span class="sn">1.</span>open app.nickradar.com</div><div class="step"><span class="sn">2.</span>enter your 4-digit code</div><div class="step"><span class="sn">3.</span>stick it &mdash; stay visible</div><div class="step"><span class="sn">4.</span>search nicknames &middot; connect</div></div></div>`;
    let sheetsHtml = '';
    for (let p = 0; p < pages; p++) {
      const pageStickers = stickers.rows.slice(p * perPage, (p + 1) * perPage);
      while (pageStickers.length < perPage) pageStickers.push(null);
      let cells = '';
      for (const s of pageStickers) {
        cells += s !== null
          ? `<div class="cell">${instrCell}</div>`
          : `<div class="cell empty"></div>`;
      }
      sheetsHtml += `<div class="page">${cells}</div>`;
    }
    const css = `*{margin:0;padding:0;box-sizing:border-box;}body{background:#e0e0e0;font-family:'Courier New',monospace;}.info{padding:12px 20px;font-size:12px;color:#555;}.page{width:210mm;height:297mm;background:white;margin:20px auto;display:grid;grid-template-columns:repeat(2,1fr);grid-template-rows:repeat(6,1fr);}.cell{border-right:1px solid #999;border-bottom:1px solid #999;display:flex;align-items:center;justify-content:center;padding:2mm 6mm;}.cell:nth-child(2n){border-right:none;}.cell:nth-child(n+11){border-bottom:none;}.cell.empty{background:#f9f9f9;}.instr{display:flex;flex-direction:column;gap:3px;width:100%;}.instr-top{display:flex;align-items:center;justify-content:space-between;width:100%;}.instr-left{display:flex;flex-direction:column;align-items:flex-start;gap:2px;}.instr-logo{height:12px;width:auto;opacity:0.7;}.instr-brand{font-size:11px;font-weight:900;letter-spacing:3px;color:#000;}.instr-qr{width:44px;height:44px;flex-shrink:0;}.instr-steps{display:flex;flex-direction:column;gap:4px;width:100%;}.step{font-size:10px;letter-spacing:0.2px;color:#000;font-weight:900;font-family:'Arial Black','Arial Bold',Impact,sans-serif;display:flex;align-items:center;gap:3px;white-space:nowrap;}.sn{color:#000;font-size:10px;font-weight:900;font-family:'Arial Black','Arial Bold',Impact,sans-serif;flex-shrink:0;}@media print{body{background:white;}.info{display:none;}.page{margin:0;box-shadow:none;}}`;
    const html = `<!DOCTYPE html><html><head><meta charset="UTF-8"><title>nickradar back — ${e.event_name}</title><style>${css}</style></head><body><div class="info">nickradar · ${e.event_name} · BACK SIDE · ${total} stickers · ${pages} page(s) · <a href="javascript:window.print()">Print</a></div>${sheetsHtml}</body></html>`;
    res.setHeader('Content-Type', 'text/html');
    res.send(html);
  } catch (err) {
    console.error('Print back error:', err);
    res.status(500).json({ success: false, error: 'server error' });
  }
});

app.get('/api/events/:id/invoice', requireEventAdminAuth, async (req, res) => {
  try {
    const eventResult = await pool.query('SELECT * FROM event WHERE id = $1 AND admin_id = $2', [req.params.id, req.adminId]);
    if (eventResult.rows.length === 0) return res.status(404).json({ success: false, error: 'not found' });
    const e = eventResult.rows[0];
    const adminResult = await pool.query('SELECT * FROM event_admin WHERE id = $1', [req.adminId]);
    const a = adminResult.rows[0];
    const invoiceResult = await pool.query('SELECT * FROM invoice WHERE event_id = $1 AND admin_id = $2 ORDER BY created_at ASC', [req.params.id, req.adminId]);
    if (invoiceResult.rows.length === 0) return res.status(404).json({ success: false, error: 'no invoice found' });
    const inv = invoiceResult.rows[0];
    const packagesResult = await pool.query('SELECT * FROM sticker_package WHERE event_id = $1 ORDER BY created_at ASC', [req.params.id]);
    const packages = packagesResult.rows;
    const tz = e.timezone || 'Europe/Vienna';
    const tzLabel = tzAbbr(tz);
    const effStart = e.effective_start_at || e.start_at;
    const effEnd = e.effective_end_at || e.ends_at;
    const startDateStr = new Date(effStart).toLocaleDateString('de-AT', { day: '2-digit', month: '2-digit', year: 'numeric', timeZone: tz });
    const startTime = new Date(effStart).toLocaleTimeString('de-AT', { hour: '2-digit', minute: '2-digit', timeZone: tz });
    const endDateStr = new Date(effEnd).toLocaleDateString('de-AT', { day: '2-digit', month: '2-digit', year: 'numeric', timeZone: tz });
    const endTime = new Date(effEnd).toLocaleTimeString('de-AT', { hour: '2-digit', minute: '2-digit', timeZone: tz });
    const invoiceDate = new Date(inv.created_at).toLocaleDateString('de-AT', { day: '2-digit', month: '2-digit', year: 'numeric' });
    const durationMs = new Date(effEnd) - new Date(effStart);
    const durationH = Math.floor(durationMs / 3600000);
    const durationM = Math.floor((durationMs % 3600000) / 60000);
    const durationS = Math.floor((durationMs % 60000) / 1000);
    const durationStr = String(durationH).padStart(2, '0') + ':' + String(durationM).padStart(2, '0') + ':' + String(durationS).padStart(2, '0');
    const stoppedByMap = { time_expired: 'Time expired', event_admin: 'Event Admin', nickradar_admin: 'nickradar Admin' };
    const stoppedAtStr = '';
    const stoppedByStr = stoppedByMap[e.stopped_by] || '—';
    const paymentStatus = inv.paid_at ? `<span style="color:green;font-weight:bold;">✓ Bezahlt / Paid &nbsp;·&nbsp; Stripe &nbsp;·&nbsp; Kreditkarte${inv.payment_id ? ' ···· ' + inv.payment_id.slice(-4) : ''} &nbsp;·&nbsp; ${new Date(inv.paid_at).toLocaleDateString('de-AT')}</span>` : `<span style="color:#cc6600;font-weight:bold;">⏳ Ausstehend / Pending &nbsp;·&nbsp; Stripe-Integration in Bearbeitung</span>`;
    let grandTotal = 0;
    let posRows = '';
    packages.forEach(function(p, i) {
      const qty = p.quantity;
      const lineTotal = calcPrice(qty);
      const up = lineTotal / qty;
      grandTotal += lineTotal;
      const pkgDate = new Date(p.created_at).toLocaleDateString('de-AT', { day: '2-digit', month: '2-digit', year: 'numeric', timeZone: tz });
      const pkgTime = new Date(p.created_at).toLocaleTimeString('de-AT', { hour: '2-digit', minute: '2-digit', timeZone: tz });
      const desc = i === 0 ? 'Nickname Sticker Package &nbsp;·&nbsp; Initial Order' : 'Nickname Sticker Package &nbsp;·&nbsp; Additional Order';
      posRows += `<tr><td>${i + 1}</td><td>${desc}<br><small style="color:#999;">${e.event_name} &nbsp;·&nbsp; ${pkgDate} ${pkgTime}</small></td><td style="text-align:right;">${qty}</td><td style="text-align:right;">€${up.toFixed(2)}</td><td style="text-align:right;font-weight:bold;">€${lineTotal.toFixed(2)}</td></tr>`;
    });
    const html = `<!DOCTYPE html><html lang="de"><head><meta charset="UTF-8"><title>Rechnung / Invoice ${inv.invoice_number}</title><link href="https://fonts.googleapis.com/css2?family=Share+Tech+Mono&display=swap" rel="stylesheet"><style>*{margin:0;padding:0;box-sizing:border-box;}body{font-family:'Share Tech Mono','Courier New',monospace;font-size:12px;color:#000;background:#fff;padding:20mm;max-width:210mm;margin:0 auto;}.header{display:flex;justify-content:space-between;align-items:flex-start;margin-bottom:12mm;}.logo-wrap{display:flex;align-items:center;gap:10px;}.logo-img{height:38px;width:auto;}.logo-text{font-size:22px;font-weight:bold;letter-spacing:4px;}.sender-info{font-size:10px;color:#999;margin-top:8px;line-height:1.8;}.invoice-meta{text-align:right;font-size:11px;line-height:1.8;}.inv-title{font-size:18px;font-weight:bold;letter-spacing:3px;margin-bottom:2px;}.inv-sub{font-size:10px;color:#999;letter-spacing:2px;margin-bottom:8px;}.addresses{margin-bottom:10mm;}.address-block{font-size:11px;line-height:1.8;}.label{font-size:9px;letter-spacing:2px;color:#999;text-transform:uppercase;margin-bottom:4px;}.event-info{background:#f5f5f5;padding:8px 12px;margin-bottom:8mm;font-size:11px;line-height:1.8;border-left:3px solid #000;}table{width:100%;border-collapse:collapse;margin-bottom:8mm;}thead tr{background:#000;color:#fff;}th{padding:7px 10px;text-align:left;font-size:10px;letter-spacing:1px;text-transform:uppercase;}th:nth-child(3),th:nth-child(4),th:nth-child(5){text-align:right;}td{padding:8px 10px;border-bottom:1px solid #eee;vertical-align:top;font-size:11px;}td small{font-size:10px;}.total-box{display:flex;justify-content:flex-end;margin-bottom:8mm;}.total-table{width:220px;}.total-table td{padding:4px 10px;border:none;font-size:11px;}.total-table .grand{font-weight:bold;font-size:14px;border-top:2px solid #000;padding-top:8px;}.payment-box{border:1px solid #eee;padding:10px 14px;margin-bottom:8mm;font-size:11px;line-height:1.8;}.footer{border-top:1px solid #eee;padding-top:6mm;font-size:10px;color:#999;line-height:1.7;}.print-btn{position:fixed;top:16px;right:16px;background:#000;color:#fff;border:none;padding:8px 20px;font-family:inherit;font-size:11px;cursor:pointer;letter-spacing:2px;}@media print{.print-btn{display:none;}body{padding:15mm;}}</style></head><body><button class="print-btn" onclick="window.print()">Drucken / Print</button><div class="header"><div><div class="logo-wrap"><img class="logo-img" src="https://app.nickradar.com/nr_logo.png" alt="nickradar" /><span class="logo-text">nickradar</span></div><div class="sender-info">Badhausstrasse 3<br>6080 Innsbruck-Igls&#8239;·&#8239;Austria<br>info@nickradar.com&#8239;·&#8239;nickradar.com</div></div><div class="invoice-meta"><div class="inv-title">RECHNUNG</div><div class="inv-sub">INVOICE</div><div style="font-weight:bold;letter-spacing:2px;">${inv.invoice_number}</div><div style="margin-top:6px;color:#999;">Date: ${invoiceDate}</div><div style=\"margin-top:4px;color:#999;\">Customer ID: ${formatCustomerId(a.id)}</div></div></div><div class="addresses"><div class="address-block"><div class="label">Rechnungsempfänger / Bill To</div><strong>${a.org_name || ''}</strong><br>${a.street ? a.street + (a.street_number ? ' ' + a.street_number : '') + '<br>' : ''}${a.postal_code || a.city ? (a.postal_code || '') + ' ' + (a.city || '') + '<br>' : ''}${a.country ? a.country + '<br>' : ''}${a.vat ? 'UID / VAT: ' + a.vat : ''}</div></div><div class="event-info"><div style="margin-bottom:6px;"><span style="color:#999;">Event ID:</span> ${formatEventId(e.id)} &nbsp;·&nbsp; <span style="color:#999;">Event Name:</span> ${e.event_name}</div><table style="width:100%;border:none;margin:0 0 6px;font-size:11px;"><tr><td style="border:none;padding:1px 0;color:#999;white-space:nowrap;">Ordered Event Times:</td><td style="border:none;padding:1px 0 1px 12px;"><strong>${new Date(e.start_at).toLocaleDateString('de-AT',{day:'2-digit',month:'2-digit',year:'numeric',timeZone:tz})} ${new Date(e.start_at).toLocaleTimeString('de-AT',{hour:'2-digit',minute:'2-digit',timeZone:tz})} &ndash; ${new Date(e.ends_at).toLocaleDateString('de-AT',{day:'2-digit',month:'2-digit',year:'numeric',timeZone:tz})} ${new Date(e.ends_at).toLocaleTimeString('de-AT',{hour:'2-digit',minute:'2-digit',timeZone:tz})}</strong></td></tr><tr><td style="border:none;padding:1px 0;color:#999;white-space:nowrap;">Effective Event Times:</td><td style="border:none;padding:1px 0 1px 12px;"><strong>${startDateStr} ${startTime} &ndash; ${endDateStr} ${endTime}</strong></td></tr><tr><td style="border:none;padding:1px 0;color:#999;white-space:nowrap;">Effective Duration:</td><td style="border:none;padding:1px 0 1px 12px;"><strong>${durationStr}</strong> &nbsp;&nbsp; <span style="color:#999;">Timezone:</span> ${tzLabel} &nbsp;&nbsp; <span style="color:#999;">Ended by:</span> ${stoppedByMap[e.stopped_by]||'—'}</td></tr></table></div><table><thead><tr><th style="width:30px;">Pos.</th><th>Beschreibung / Description</th><th style="width:60px;">Menge / Qty</th><th style="width:90px;">Preis/Stk / Unit</th><th style="width:90px;">Gesamt / Total</th></tr></thead><tbody>${posRows}</tbody></table><div class="total-box"><table class="total-table"><tr><td>Zwischensumme / Subtotal</td><td style="text-align:right;">€${grandTotal.toFixed(2)}</td></tr><tr><td style="font-size:10px;color:#999;">MwSt. / VAT (0%)*</td><td style="text-align:right;font-size:10px;color:#999;">€0.00</td></tr><tr class="grand"><td>Gesamtbetrag / Total</td><td style="text-align:right;">€${grandTotal.toFixed(2)}</td></tr></table></div><div class="payment-box"><div class="label">Zahlungsinformation / Payment Info</div>${paymentStatus}</div><div class="footer">* Gemäß §6 Abs. 1 Z 27 UStG wird keine Umsatzsteuer berechnet (Kleinunternehmerregelung).<br>&nbsp;&nbsp;In accordance with §6 para. 1 no. 27 Austrian VAT Act, no VAT is charged (small business regulation).</div></body></html>`;
    res.setHeader('Content-Type', 'text/html');
    res.send(html);
  } catch (err) {
    console.error('Invoice error:', err);
    res.status(500).json({ success: false, error: 'server error' });
  }
});

// ============================================================
// PARTICIPANT
// ============================================================

app.post('/api/participant/login', codeLimiter, async (req, res) => {
  const { code } = req.body;
  if (!code) return res.status(400).json({ success: false, error: 'code required' });
  const ip = getClientIP(req);
  try {
    const stickerResult = await pool.query(
      `SELECT s.*, e.event_name, e.org_name, e.start_at, e.ends_at, e.status as event_status, e.id as eid, e.paid
       FROM sticker s JOIN event e ON s.event_id = e.id
       WHERE s.code = $1
       ORDER BY CASE e.status WHEN 'active' THEN 0 WHEN 'pending' THEN 1 ELSE 2 END, e.start_at DESC
       LIMIT 1`,
      [code.trim()]
    );
    if (stickerResult.rows.length === 0) return res.status(404).json({ success: false, error: 'invalid code' });
    const sticker = stickerResult.rows[0];
    if (sticker.event_status === 'stopped' || sticker.event_status === 'finished') return res.status(403).json({ success: false, error: 'event has ended' });
    if (new Date(sticker.ends_at) < new Date()) return res.status(403).json({ success: false, error: 'event has ended' });
    if (!sticker.paid) return res.status(403).json({ success: false, error: 'event not ready yet' });
    if (sticker.status === 'invalidated') return res.status(403).json({ success: false, error: 'sticker invalidated, please get a new one' });
    if (sticker.status === 'blocked') return res.status(403).json({ success: false, error: 'sticker blocked' });
    const existingSession = await pool.query('SELECT * FROM session WHERE sticker_id = $1 AND expires_at > NOW()', [sticker.id]);
    let token;
    if (existingSession.rows.length > 0) {
      token = existingSession.rows[0].token;
      await pool.query('UPDATE session SET last_seen_at = NOW() WHERE token = $1', [token]);
    } else {
      token = crypto.randomBytes(32).toString('hex');
      await pool.query(
        `INSERT INTO session (sticker_id, event_id, token, created_at, expires_at, last_seen_at, ip_address) VALUES ($1, $2, $3, NOW(), $4, NOW(), $5)`,
        [sticker.id, sticker.eid, token, sticker.ends_at, ip]
      );
      if (sticker.status === 'unused') {
        await pool.query("UPDATE sticker SET status = 'active', activated_at = NOW() WHERE id = $1", [sticker.id]);
        await pool.query('UPDATE event SET activated_count = activated_count + 1 WHERE id = $1', [sticker.eid]);
      }
    }
    if (sticker.event_status === 'pending') {
      await pool.query("UPDATE event SET status = 'active' WHERE id = $1", [sticker.eid]);
    }
    const profile = await pool.query('SELECT * FROM profile WHERE sticker_id = $1', [sticker.id]);
    res.json({
      success: true, token,
      participant: {
        nickname: sticker.nickname, sticker_id: sticker.id, event_id: sticker.eid,
        event_name: sticker.event_name, org_name: sticker.org_name, ends_at: sticker.ends_at,
        photo_url: profile.rows[0]?.photo_url || null, intro: profile.rows[0]?.intro || null,
      }
    });
  } catch (err) {
    console.error('Participant login error:', err);
    res.status(500).json({ success: false, error: 'server error' });
  }
});

app.get('/api/participant/me', requireParticipantSession, async (req, res) => {
  try {
    const profile = await pool.query('SELECT * FROM profile WHERE sticker_id = $1', [req.session.sticker_id]);
    res.json({
      success: true,
      participant: {
        nickname: req.session.nickname, sticker_id: req.session.sticker_id,
        event_id: req.session.event_id, event_name: req.session.event_name,
        org_name: req.session.org_name, start_at: req.session.start_at,
        ends_at: req.session.ends_at, timezone: req.session.timezone,
        photo_url: profile.rows[0]?.photo_url || null, intro: profile.rows[0]?.intro || null,
      }
    });
  } catch (err) {
    res.status(500).json({ success: false, error: 'server error' });
  }
});

app.put('/api/participant/profile', requireParticipantSession, async (req, res) => {
  const { photo_url, intro } = req.body;
  if (intro && intro.length > 100) return res.status(400).json({ success: false, error: 'intro max 100 chars' });
  try {
    const existing = await pool.query('SELECT id FROM profile WHERE sticker_id = $1', [req.session.sticker_id]);
    if (existing.rows.length > 0) {
      await pool.query(
        'UPDATE profile SET photo_url = COALESCE($1, photo_url), intro = COALESCE($2, intro), updated_at = NOW() WHERE sticker_id = $3',
        [photo_url || null, intro || null, req.session.sticker_id]
      );
    } else {
      await pool.query(
        'INSERT INTO profile (sticker_id, photo_url, intro, updated_at) VALUES ($1, $2, $3, NOW())',
        [req.session.sticker_id, photo_url || null, intro || null]
      );
    }
    res.json({ success: true });
  } catch (err) {
    res.status(500).json({ success: false, error: 'server error' });
  }
});

// ============================================================
// SEARCH
// ============================================================

app.get('/api/search', requireParticipantSession, async (req, res) => {
  const { q } = req.query;
  if (!q || q.length < 1) return res.json({ success: true, participants: [] });
  try {
    const result = await pool.query(
      `SELECT s.id as sticker_id, s.nickname, p.photo_url, p.intro
       FROM sticker s LEFT JOIN profile p ON p.sticker_id = s.id
       WHERE s.event_id = $1 AND s.status = 'active' AND s.id != $2 AND UPPER(s.nickname) LIKE UPPER($3)
       ORDER BY s.nickname ASC LIMIT 10`,
      [req.session.event_id, req.session.sticker_id, q + '%']
    );
    // Filter out participants with whom there is a block (NO response or blocked chat)
    const blockedIds = await pool.query(
      `SELECT target_id as id FROM request WHERE event_id = $1 AND seeker_id = $2 AND status = 'no'
       UNION
       SELECT seeker_id as id FROM request WHERE event_id = $1 AND target_id = $2 AND status = 'no'
       UNION
       SELECT CASE WHEN seeker_id = $2 THEN target_id ELSE seeker_id END as id FROM chat WHERE event_id = $1 AND (seeker_id = $2 OR target_id = $2) AND status = 'blocked'`,
      [req.session.event_id, req.session.sticker_id]
    );
    const blockedSet = new Set(blockedIds.rows.map(r => r.id));
    const filtered = result.rows.filter(p => !blockedSet.has(p.id));
    res.json({ success: true, participants: filtered });
  } catch (err) {
    res.status(500).json({ success: false, error: 'server error' });
  }
});

app.get('/api/participants/:nickname', requireParticipantSession, async (req, res) => {
  try {
    const result = await pool.query(
      `SELECT s.id as sticker_id, s.nickname, p.photo_url, p.intro
       FROM sticker s LEFT JOIN profile p ON p.sticker_id = s.id
       WHERE s.event_id = $1 AND UPPER(s.nickname) = UPPER($2) AND s.status = 'active' AND s.id != $3`,
      [req.session.event_id, req.params.nickname, req.session.sticker_id]
    );
    if (result.rows.length === 0) return res.status(404).json({ success: false, error: 'participant not found' });
    res.json({ success: true, participant: result.rows[0] });
  } catch (err) {
    res.status(500).json({ success: false, error: 'server error' });
  }
});

// ============================================================
// REQUESTS
// ============================================================

app.post('/api/requests', requireParticipantSession, async (req, res) => {
  const { target_nickname, message } = req.body;
  if (!target_nickname || !message) return res.status(400).json({ success: false, error: 'target_nickname and message required' });
  if (message.length < 2 || message.length > 200) return res.status(400).json({ success: false, error: 'message must be 2-200 chars' });
  try {
    const target = await pool.query("SELECT id FROM sticker WHERE UPPER(nickname) = UPPER($1) AND event_id = $2 AND status = 'active'", [target_nickname, req.session.event_id]);
    if (target.rows.length === 0) return res.status(404).json({ success: false, error: 'participant not found' });
    const targetId = target.rows[0].id;
    if (targetId === req.session.sticker_id) return res.status(400).json({ success: false, error: 'cannot send request to yourself' });
    const blockCheck = await pool.query(`SELECT id FROM request WHERE event_id = $1 AND ((seeker_id = $2 AND target_id = $3) OR (seeker_id = $3 AND target_id = $2)) AND status = 'no'`, [req.session.event_id, req.session.sticker_id, targetId]);
    if (blockCheck.rows.length > 0) return res.status(403).json({ success: false, error: 'blocked' });
    const chatBlockCheck = await pool.query(`SELECT id FROM chat WHERE event_id = $1 AND ((seeker_id = $2 AND target_id = $3) OR (seeker_id = $3 AND target_id = $2)) AND status = 'blocked'`, [req.session.event_id, req.session.sticker_id, targetId]);
    if (chatBlockCheck.rows.length > 0) return res.status(403).json({ success: false, error: 'blocked' });
    const existing = await pool.query("SELECT id FROM request WHERE seeker_id = $1 AND target_id = $2 AND event_id = $3 AND status = 'pending'", [req.session.sticker_id, targetId, req.session.event_id]);
    if (existing.rows.length > 0) return res.status(409).json({ success: false, error: 'request already pending' });
    const chatCheck = await pool.query(`SELECT id FROM chat WHERE event_id = $1 AND ((seeker_id = $2 AND target_id = $3) OR (seeker_id = $3 AND target_id = $2)) AND status = 'active'`, [req.session.event_id, req.session.sticker_id, targetId]);
    if (chatCheck.rows.length > 0) return res.status(409).json({ success: false, error: 'already in active chat' });
    const event = await pool.query('SELECT ends_at FROM event WHERE id = $1', [req.session.event_id]);
    const result = await pool.query(`INSERT INTO request (seeker_id, target_id, event_id, message, sent_at, expires_at, status) VALUES ($1, $2, $3, $4, NOW(), $5, 'pending') RETURNING *`, [req.session.sticker_id, targetId, req.session.event_id, message, event.rows[0].ends_at]);
    res.status(201).json({ success: true, request: result.rows[0] });
  } catch (err) {
    console.error('Request error:', err);
    res.status(500).json({ success: false, error: 'server error' });
  }
});

app.put('/api/requests/:id', requireParticipantSession, async (req, res) => {
  const { answer } = req.body;
  if (!['yes', 'no'].includes(answer)) return res.status(400).json({ success: false, error: 'answer must be yes or no' });
  try {
    const request = await pool.query("SELECT * FROM request WHERE id = $1 AND target_id = $2 AND status = 'pending'", [req.params.id, req.session.sticker_id]);
    if (request.rows.length === 0) return res.status(404).json({ success: false, error: 'not found' });
    const r = request.rows[0];
    await pool.query('UPDATE request SET status = $1, responded_at = NOW() WHERE id = $2', [answer, r.id]);
    if (answer === 'yes') {
      const event = await pool.query('SELECT ends_at FROM event WHERE id = $1', [r.event_id]);
      const chat = await pool.query(`INSERT INTO chat (request_id, event_id, seeker_id, target_id, started_at, ends_at, status) VALUES ($1, $2, $3, $4, NOW(), $5, 'active') RETURNING *`, [r.id, r.event_id, r.seeker_id, r.target_id, event.rows[0].ends_at]);
      await pool.query('UPDATE event SET connection_count = connection_count + 1 WHERE id = $1', [r.event_id]);
      await pool.query('INSERT INTO message (chat_id, sender_id, text, sent_at) VALUES ($1, $2, $3, NOW())', [chat.rows[0].id, r.seeker_id, r.message]);
      return res.json({ success: true, chat: chat.rows[0] });
    }
    res.json({ success: true });
  } catch (err) {
    console.error('Answer request error:', err);
    res.status(500).json({ success: false, error: 'server error' });
  }
});

app.get('/api/requests/incoming', requireParticipantSession, async (req, res) => {
  try {
    const result = await pool.query(
      `SELECT r.*, s.nickname as seeker_nickname, p.photo_url, p.intro FROM request r
       JOIN sticker s ON r.seeker_id = s.id LEFT JOIN profile p ON p.sticker_id = s.id
       WHERE r.target_id = $1 AND r.event_id = $2 AND r.status = 'pending' AND r.expires_at > NOW() ORDER BY r.sent_at DESC`,
      [req.session.sticker_id, req.session.event_id]
    );
    res.json({ success: true, requests: result.rows });
  } catch (err) {
    res.status(500).json({ success: false, error: 'server error' });
  }
});

app.get('/api/requests/outgoing', requireParticipantSession, async (req, res) => {
  try {
    const result = await pool.query(
      `SELECT r.*, s.nickname as target_nickname FROM request r JOIN sticker s ON r.target_id = s.id
       WHERE r.seeker_id = $1 AND r.event_id = $2 AND r.status = 'pending' ORDER BY r.sent_at DESC`,
      [req.session.sticker_id, req.session.event_id]
    );
    res.json({ success: true, requests: result.rows });
  } catch (err) {
    res.status(500).json({ success: false, error: 'server error' });
  }
});

app.get('/api/requests/history', requireParticipantSession, async (req, res) => {
  try {
    const result = await pool.query(
      `SELECT r.*, CASE WHEN r.seeker_id = $1 THEN s2.nickname ELSE s1.nickname END as other_nickname
       FROM request r JOIN sticker s1 ON r.seeker_id = s1.id JOIN sticker s2 ON r.target_id = s2.id
       WHERE (r.seeker_id = $1 OR r.target_id = $1) AND r.event_id = $2 AND r.status IN ('yes', 'no', 'expired')
       ORDER BY r.sent_at DESC`,
      [req.session.sticker_id, req.session.event_id]
    );
    res.json({ success: true, history: result.rows });
  } catch (err) {
    res.status(500).json({ success: false, error: 'server error' });
  }
});

// ============================================================
// CHATS + MESSAGES
// ============================================================

app.post('/api/chats/start', requireParticipantSession, async (req, res) => {
  const { target_nickname, message } = req.body;
  if (!target_nickname || !message) return res.status(400).json({ success: false, error: 'target_nickname and message required' });
  if (message.length < 2 || message.length > 500) return res.status(400).json({ success: false, error: 'message must be 2-500 chars' });
  try {
    const target = await pool.query("SELECT id FROM sticker WHERE UPPER(nickname) = UPPER($1) AND event_id = $2 AND status = 'active'", [target_nickname, req.session.event_id]);
    if (target.rows.length === 0) return res.status(404).json({ success: false, error: 'participant not found' });
    const targetId = target.rows[0].id;
    if (targetId === req.session.sticker_id) return res.status(400).json({ success: false, error: 'cannot chat with yourself' });
    const blockCheck = await pool.query(`SELECT id FROM chat WHERE event_id = $1 AND ((seeker_id = $2 AND target_id = $3) OR (seeker_id = $3 AND target_id = $2)) AND status = 'blocked'`, [req.session.event_id, req.session.sticker_id, targetId]);
    if (blockCheck.rows.length > 0) return res.status(403).json({ success: false, error: 'blocked' });
    const existing = await pool.query(`SELECT id FROM chat WHERE event_id = $1 AND ((seeker_id = $2 AND target_id = $3) OR (seeker_id = $3 AND target_id = $2)) AND status = 'active'`, [req.session.event_id, req.session.sticker_id, targetId]);
    if (existing.rows.length > 0) {
      await pool.query('INSERT INTO message (chat_id, sender_id, text, sent_at) VALUES ($1, $2, $3, NOW())', [existing.rows[0].id, req.session.sticker_id, message]);
      return res.json({ success: true, chat_id: existing.rows[0].id });
    }
    const event = await pool.query('SELECT ends_at FROM event WHERE id = $1', [req.session.event_id]);
    const chat = await pool.query(`INSERT INTO chat (event_id, seeker_id, target_id, started_at, ends_at, status) VALUES ($1, $2, $3, NOW(), $4, 'active') RETURNING *`, [req.session.event_id, req.session.sticker_id, targetId, event.rows[0].ends_at]);
    await pool.query('INSERT INTO message (chat_id, sender_id, text, sent_at) VALUES ($1, $2, $3, NOW())', [chat.rows[0].id, req.session.sticker_id, message]);
    await pool.query('UPDATE event SET connection_count = connection_count + 1 WHERE id = $1', [req.session.event_id]);
    res.status(201).json({ success: true, chat_id: chat.rows[0].id });
  } catch (err) {
    console.error('Start chat error:', err);
    res.status(500).json({ success: false, error: 'server error' });
  }
});

app.get('/api/chats', requireParticipantSession, async (req, res) => {
  try {
    const result = await pool.query(
      `SELECT c.*,
        CASE WHEN c.seeker_id = $1 THEN s2.nickname ELSE s1.nickname END as other_nickname,
        CASE WHEN c.seeker_id = $1 THEN p2.photo_url ELSE p1.photo_url END as other_photo,
        CASE WHEN c.seeker_id = $1 THEN p2.intro ELSE p1.intro END as other_intro,
        (SELECT m.sender_id FROM message m WHERE m.chat_id = c.id ORDER BY m.sent_at DESC LIMIT 1) as last_sender_id,
        (SELECT m.text FROM message m WHERE m.chat_id = c.id ORDER BY m.sent_at DESC LIMIT 1) as last_message
       FROM chat c JOIN sticker s1 ON c.seeker_id = s1.id JOIN sticker s2 ON c.target_id = s2.id
       LEFT JOIN profile p1 ON p1.sticker_id = s1.id LEFT JOIN profile p2 ON p2.sticker_id = s2.id
       WHERE (c.seeker_id = $1 OR c.target_id = $1) AND c.event_id = $2 AND c.status = 'active'
       ORDER BY c.started_at DESC`,
      [req.session.sticker_id, req.session.event_id]
    );
    res.json({ success: true, chats: result.rows });
  } catch (err) {
    res.status(500).json({ success: false, error: 'server error' });
  }
});

app.get('/api/chats/blocked', requireParticipantSession, async (req, res) => {
  try {
    const result = await pool.query(
      `SELECT c.*,
        CASE WHEN c.seeker_id = $1 THEN s2.nickname ELSE s1.nickname END as other_nickname,
        CASE
          WHEN c.blocked_by = $1 THEN 'blocked by you'
          WHEN c.blocked_by != $1 AND c.seeker_id = $1 THEN 'blocked by target'
          WHEN c.blocked_by != $1 AND c.target_id = $1 THEN 'blocked by seeker'
          ELSE 'blocked'
        END as blocked_label
       FROM chat c
       JOIN sticker s1 ON c.seeker_id = s1.id
       JOIN sticker s2 ON c.target_id = s2.id
       WHERE (c.seeker_id = $1 OR c.target_id = $1) AND c.event_id = $2 AND c.status = 'blocked'
       ORDER BY c.blocked_at DESC`,
      [req.session.sticker_id, req.session.event_id]
    );
    res.json({ success: true, chats: result.rows });
  } catch (err) {
    res.status(500).json({ success: false, error: 'server error' });
  }
});

app.get('/api/messages/:chatId', requireParticipantSession, async (req, res) => {
  try {
    const chat = await pool.query('SELECT * FROM chat WHERE id = $1 AND (seeker_id = $2 OR target_id = $2)', [req.params.chatId, req.session.sticker_id]);
    if (chat.rows.length === 0) return res.status(404).json({ success: false, error: 'not found' });
    const messages = await pool.query(`SELECT m.*, s.nickname as sender_nickname FROM message m JOIN sticker s ON m.sender_id = s.id WHERE m.chat_id = $1 ORDER BY m.sent_at ASC`, [req.params.chatId]);
    res.json({ success: true, messages: messages.rows });
  } catch (err) {
    res.status(500).json({ success: false, error: 'server error' });
  }
});

app.post('/api/messages', requireParticipantSession, async (req, res) => {
  const { chat_id, text } = req.body;
  if (!chat_id || !text) return res.status(400).json({ success: false, error: 'chat_id and text required' });
  if (text.length > 1000) return res.status(400).json({ success: false, error: 'message too long' });
  try {
    const chat = await pool.query("SELECT * FROM chat WHERE id = $1 AND (seeker_id = $2 OR target_id = $2) AND status = 'active'", [chat_id, req.session.sticker_id]);
    if (chat.rows.length === 0) return res.status(404).json({ success: false, error: 'chat not found or not active' });
    const result = await pool.query('INSERT INTO message (chat_id, sender_id, text, sent_at) VALUES ($1, $2, $3, NOW()) RETURNING *', [chat_id, req.session.sticker_id, text]);
    res.status(201).json({ success: true, message: result.rows[0] });
  } catch (err) {
    res.status(500).json({ success: false, error: 'server error' });
  }
});

app.put('/api/chats/:id/block', requireParticipantSession, async (req, res) => {
  try {
    const chat = await pool.query("SELECT * FROM chat WHERE id = $1 AND (seeker_id = $2 OR target_id = $2) AND status = 'active'", [req.params.id, req.session.sticker_id]);
    if (chat.rows.length === 0) return res.status(404).json({ success: false, error: 'not found' });
    await pool.query("UPDATE chat SET status = 'blocked', blocked_by = $1, blocked_at = NOW() WHERE id = $2", [req.session.sticker_id, req.params.id]);
    res.json({ success: true });
  } catch (err) {
    res.status(500).json({ success: false, error: 'server error' });
  }
});

// ============================================================
// NICKRADAR ADMIN
// ============================================================

app.get('/api/admin/event-admins', requireAdminKey, async (req, res) => {
  try {
    const result = await pool.query(
      `SELECT id, org_name, contact_name, business_type, country, street, street_number, postal_code, city, vat,
              email, status, email_verified, created_at, last_login_at
       FROM event_admin ORDER BY created_at DESC`
    );
    res.json({ success: true, admins: result.rows });
  } catch (err) {
    res.status(500).json({ success: false, error: 'server error' });
  }
});

app.put('/api/admin/event-admin/:id/profile', requireAdminKey, async (req, res) => {
  const { org_name, contact_name, business_type, country, street, street_number, postal_code, city, vat } = req.body;
  try {
    await pool.query(
      `UPDATE event_admin SET
        org_name = COALESCE($1, org_name), contact_name = COALESCE($2, contact_name),
        business_type = COALESCE($3, business_type), country = COALESCE($4, country),
        street = COALESCE($5, street), street_number = COALESCE($6, street_number),
        postal_code = COALESCE($7, postal_code), city = COALESCE($8, city),
        vat = COALESCE($9, vat)
       WHERE id = $10`,
      [org_name || null, contact_name || null, business_type || null, country || null,
       street || null, street_number || null, postal_code || null, city || null,
       vat || null,
       req.params.id]
    );
    res.json({ success: true });
  } catch (err) {
    console.error('Admin profile update error:', err);
    res.status(500).json({ success: false, error: 'server error' });
  }
});

app.post('/api/admin/event-admin/:id/block', requireAdminKey, async (req, res) => {
  try {
    await pool.query("UPDATE event_admin SET status = 'blocked' WHERE id = $1", [req.params.id]);
    res.json({ success: true });
  } catch (err) {
    res.status(500).json({ success: false, error: 'server error' });
  }
});

app.post('/api/admin/event-admin/:id/unblock', requireAdminKey, async (req, res) => {
  try {
    await pool.query("UPDATE event_admin SET status = 'active' WHERE id = $1", [req.params.id]);
    res.json({ success: true });
  } catch (err) {
    res.status(500).json({ success: false, error: 'server error' });
  }
});

app.post('/api/admin/event-admin/:id/set-password', requireAdminKey, async (req, res) => {
  const { password } = req.body;
  if (!password || password.length < 8) return res.status(400).json({ success: false, error: 'password min 8 chars' });
  try {
    const hash = await bcrypt.hash(password, 10);
    await pool.query('UPDATE event_admin SET password_hash = $1 WHERE id = $2', [hash, req.params.id]);
    const admin = await pool.query('SELECT email, org_name FROM event_admin WHERE id = $1', [req.params.id]);
    if (admin.rows.length > 0) {
      sendEmail(admin.rows[0].email, 'nickradar: Your password has been set', `Hello ${admin.rows[0].org_name},\n\nYour password has been set by the nickradar team.\n\nNew password: ${password}\n\nLogin at: https://events.nickradar.com\n\nPlease change your password after login.\n\nnickradar`);
    }
    res.json({ success: true });
  } catch (err) {
    res.status(500).json({ success: false, error: 'server error' });
  }
});



app.post('/api/admin/events/:id/confirm-payment', requireAdminKey, async (req, res) => {
  try {
    await pool.query('UPDATE event SET paid = TRUE WHERE id = $1', [req.params.id]);
    res.json({ success: true });
  } catch (err) {
    res.status(500).json({ success: false, error: 'server error' });
  }
});

app.get('/api/admin/events', requireAdminKey, async (req, res) => {
  try {
    const result = await pool.query(`SELECT e.*, ea.contact_name as admin_name, ea.org_name as admin_org, ea.email as admin_email FROM event e JOIN event_admin ea ON e.admin_id = ea.id ORDER BY e.created_at DESC`);
    res.json({ success: true, events: result.rows });
  } catch (err) {
    res.status(500).json({ success: false, error: 'server error' });
  }
});

app.get('/api/admin/events/:id', requireAdminKey, async (req, res) => {
  try {
    const event = await pool.query('SELECT * FROM event WHERE id = $1', [req.params.id]);
    if (event.rows.length === 0) return res.status(404).json({ success: false, error: 'not found' });
    const stickers = await pool.query('SELECT * FROM sticker WHERE event_id = $1 ORDER BY id ASC', [req.params.id]);
    const conns = await pool.query(
      `SELECT c.id, s1.id as seeker_id, s2.id as target_id, s1.nickname as seeker_nick, s2.nickname as target_nick
       FROM chat c JOIN sticker s1 ON c.seeker_id=s1.id JOIN sticker s2 ON c.target_id=s2.id
       WHERE c.event_id=$1 AND c.status='active'`, [req.params.id]
    );
    res.json({ success: true, event: event.rows[0], stickers: stickers.rows, connections: conns.rows });
  } catch (err) {
    res.status(500).json({ success: false, error: 'server error' });
  }
});

app.get('/api/admin/events/:id/stickers', requireAdminKey, async (req, res) => {
  try {
    const stickers = await pool.query('SELECT * FROM sticker WHERE event_id = $1 ORDER BY id ASC', [req.params.id]);
    res.json({ success: true, stickers: stickers.rows });
  } catch (err) {
    res.status(500).json({ success: false, error: 'server error' });
  }
});

app.post('/api/admin/events/:id/stop', requireAdminKey, async (req, res) => {
  try {
    await finishEvent(parseInt(req.params.id), 'nickradar_admin');
    res.json({ success: true });
  } catch (err) {
    res.status(500).json({ success: false, error: 'server error' });
  }
});

app.put('/api/admin/events/:id/effective-times', requireAdminKey, async (req, res) => {
  const { effective_start_at, effective_end_at } = req.body;
  if (!effective_start_at && !effective_end_at) {
    return res.status(400).json({ success: false, error: 'at least one field required' });
  }
  try {
    const fields = [];
    const vals = [];
    let idx = 1;
    if (effective_start_at) { fields.push(`effective_start_at = $${idx++}`); vals.push(new Date(effective_start_at)); }
    if (effective_end_at) { fields.push(`effective_end_at = $${idx++}`); vals.push(new Date(effective_end_at)); }
    vals.push(req.params.id);
    await pool.query(`UPDATE event SET ${fields.join(', ')} WHERE id = $${idx}`, vals);
    res.json({ success: true });
  } catch (err) {
    console.error('Effective times update error:', err);
    res.status(500).json({ success: false, error: 'server error' });
  }
});



app.get('/api/admin/invoices', requireAdminKey, async (req, res) => {
  try {
    const result = await pool.query(`SELECT i.*, ea.contact_name as admin_name, ea.org_name, e.event_name FROM invoice i JOIN event_admin ea ON i.admin_id = ea.id LEFT JOIN event e ON i.event_id = e.id ORDER BY i.created_at DESC`);
    res.json({ success: true, invoices: result.rows });
  } catch (err) {
    res.status(500).json({ success: false, error: 'server error' });
  }
});
app.get('/api/admin/events/:id/invoice', function(req,res,next){if(req.query.key&&req.query.key===ADMIN_KEY){return next();}requireAdminKey(req,res,next);},  async (req, res) => {
  try {
    const eventResult = await pool.query('SELECT * FROM event WHERE id = $1', [req.params.id]);
    if (eventResult.rows.length === 0) return res.status(404).json({ success: false, error: 'not found' });
    const e = eventResult.rows[0];
    const adminResult = await pool.query('SELECT * FROM event_admin WHERE id = $1', [e.admin_id]);
    if (adminResult.rows.length === 0) return res.status(404).json({ success: false, error: 'admin not found' });
    const a = adminResult.rows[0];
    const invoiceResult = await pool.query('SELECT * FROM invoice WHERE event_id = $1 ORDER BY created_at ASC', [req.params.id]);
    if (invoiceResult.rows.length === 0) return res.status(404).json({ success: false, error: 'no invoice found' });
    const inv = invoiceResult.rows[0];
    const packagesResult = await pool.query('SELECT * FROM sticker_package WHERE event_id = $1 ORDER BY created_at ASC', [req.params.id]);
    const packages = packagesResult.rows;
    const tz = e.timezone || 'Europe/Vienna';
    const tzLabel = tzAbbr(tz);
    const effStart = e.effective_start_at || e.start_at;
    const effEnd = e.effective_end_at || e.ends_at;
    const startDateStr = new Date(effStart).toLocaleDateString('de-AT', { day: '2-digit', month: '2-digit', year: 'numeric', timeZone: tz });
    const startTime = new Date(effStart).toLocaleTimeString('de-AT', { hour: '2-digit', minute: '2-digit', timeZone: tz });
    const endDateStr = new Date(effEnd).toLocaleDateString('de-AT', { day: '2-digit', month: '2-digit', year: 'numeric', timeZone: tz });
    const endTime = new Date(effEnd).toLocaleTimeString('de-AT', { hour: '2-digit', minute: '2-digit', timeZone: tz });
    const invoiceDate = new Date(inv.created_at).toLocaleDateString('de-AT', { day: '2-digit', month: '2-digit', year: 'numeric' });
    const durationMs = new Date(effEnd) - new Date(effStart);
    const durationH = Math.floor(durationMs / 3600000);
    const durationM = Math.floor((durationMs % 3600000) / 60000);
    const durationS = Math.floor((durationMs % 60000) / 1000);
    const durationStr = String(durationH).padStart(2, '0') + ':' + String(durationM).padStart(2, '0') + ':' + String(durationS).padStart(2, '0');
    const stoppedByMap = { time_expired: 'Time expired', event_admin: 'Event Admin', nickradar_admin: 'nickradar Admin' };
    const stoppedAtStr = '';
    const stoppedByStr = stoppedByMap[e.stopped_by] || '—';
    const paymentStatus = inv.paid_at ? `<span style="color:green;font-weight:bold;">✓ Paid &nbsp;·&nbsp; ${inv.payment_provider || '—'}${inv.payment_id ? ' ···· ' + inv.payment_id.slice(-4) : ''} &nbsp;·&nbsp; ${new Date(inv.paid_at).toLocaleDateString('de-AT')}</span>` : `<span style="color:#cc6600;font-weight:bold;">⏳ Pending</span>`;
    let grandTotal = 0;
    let posRows = '';
    packages.forEach(function(p, i) {
      const qty = p.quantity;
      const lineTotal = calcPrice(qty);
      const up = lineTotal / qty;
      grandTotal += lineTotal;
      const pkgDate = new Date(p.created_at).toLocaleDateString('de-AT', { day: '2-digit', month: '2-digit', year: 'numeric', timeZone: tz });
      const pkgTime = new Date(p.created_at).toLocaleTimeString('de-AT', { hour: '2-digit', minute: '2-digit', timeZone: tz });
      const desc = i === 0 ? 'Nickname Sticker Package &nbsp;·&nbsp; Initial Order' : 'Nickname Sticker Package &nbsp;·&nbsp; Additional Order';
      posRows += `<tr><td>${i + 1}</td><td>${desc}<br><small style="color:#999;">${e.event_name} &nbsp;·&nbsp; ${pkgDate} ${pkgTime}</small></td><td style="text-align:right;">${qty}</td><td style="text-align:right;">€${up.toFixed(2)}</td><td style="text-align:right;font-weight:bold;">€${lineTotal.toFixed(2)}</td></tr>`;
    });
    const html = `<!DOCTYPE html><html lang="de"><head><meta charset="UTF-8"><title>Invoice ${inv.invoice_number}</title><link href="https://fonts.googleapis.com/css2?family=Share+Tech+Mono&display=swap" rel="stylesheet"><style>*{margin:0;padding:0;box-sizing:border-box;}body{font-family:'Share Tech Mono','Courier New',monospace;font-size:12px;color:#000;background:#fff;padding:20mm;max-width:210mm;margin:0 auto;}.header{display:flex;justify-content:space-between;align-items:flex-start;margin-bottom:12mm;}.logo-wrap{display:flex;align-items:center;gap:10px;}.logo-img{height:38px;width:auto;}.logo-text{font-size:22px;font-weight:bold;letter-spacing:4px;}.sender-info{font-size:10px;color:#999;margin-top:8px;line-height:1.8;}.invoice-meta{text-align:right;font-size:11px;line-height:1.8;}.inv-title{font-size:18px;font-weight:bold;letter-spacing:3px;margin-bottom:2px;}.inv-sub{font-size:10px;color:#999;letter-spacing:2px;margin-bottom:8px;}.addresses{margin-bottom:10mm;}.address-block{font-size:11px;line-height:1.8;}.label{font-size:9px;letter-spacing:2px;color:#999;text-transform:uppercase;margin-bottom:4px;}.event-info{background:#f5f5f5;padding:8px 12px;margin-bottom:8mm;font-size:11px;line-height:1.8;border-left:3px solid #000;}table{width:100%;border-collapse:collapse;margin-bottom:8mm;}thead tr{background:#000;color:#fff;}th{padding:7px 10px;text-align:left;font-size:10px;letter-spacing:1px;text-transform:uppercase;}th:nth-child(3),th:nth-child(4),th:nth-child(5){text-align:right;}td{padding:8px 10px;border-bottom:1px solid #eee;vertical-align:top;font-size:11px;}td small{font-size:10px;}.total-box{display:flex;justify-content:flex-end;margin-bottom:8mm;}.total-table{width:220px;}.total-table td{padding:4px 10px;border:none;font-size:11px;}.total-table .grand{font-weight:bold;font-size:14px;border-top:2px solid #000;padding-top:8px;}.payment-box{border:1px solid #eee;padding:10px 14px;margin-bottom:8mm;font-size:11px;line-height:1.8;}.footer{border-top:1px solid #eee;padding-top:6mm;font-size:10px;color:#999;line-height:1.7;}.print-btn{position:fixed;top:16px;right:16px;background:#000;color:#fff;border:none;padding:8px 20px;font-family:inherit;font-size:11px;cursor:pointer;letter-spacing:2px;}@media print{.print-btn{display:none;}body{padding:15mm;}}</style></head><body><button class="print-btn" onclick="window.print()">Print</button><div class="header"><div><div class="logo-wrap"><img class="logo-img" src="https://app.nickradar.com/nr_logo.png" alt="nickradar" /><span class="logo-text">nickradar</span></div><div class="sender-info">Badhausstrasse 3<br>6080 Innsbruck-Igls&#8239;·&#8239;Austria<br>info@nickradar.com&#8239;·&#8239;nickradar.com</div></div><div class="invoice-meta"><div class="inv-title">RECHNUNG</div><div class="inv-sub">INVOICE</div><div style="font-weight:bold;letter-spacing:2px;">${inv.invoice_number}</div><div style="margin-top:6px;color:#999;">Date: ${invoiceDate}</div><div style="margin-top:4px;color:#999;">Customer ID: ${formatCustomerId(a.id)}</div></div></div><div class="addresses"><div class="address-block"><div class="label">Rechnungsempfänger / Bill To</div><strong>${a.org_name || ''}</strong><br>${a.street ? a.street + (a.street_number ? ' ' + a.street_number : '') + '<br>' : ''}${a.postal_code || a.city ? (a.postal_code || '') + ' ' + (a.city || '') + '<br>' : ''}${a.country ? a.country + '<br>' : ''}${a.vat ? 'UID / VAT: ' + a.vat : ''}</div></div><div class="event-info"><div style="margin-bottom:6px;"><span style="color:#999;">Event ID:</span> ${formatEventId(e.id)} &nbsp;·&nbsp; <span style="color:#999;">Event Name:</span> ${e.event_name}</div><table style="width:100%;border:none;margin:0 0 6px;font-size:11px;"><tr><td style="border:none;padding:1px 0;color:#999;white-space:nowrap;">Ordered Event Times:</td><td style="border:none;padding:1px 0 1px 12px;"><strong>${new Date(e.start_at).toLocaleDateString('de-AT',{day:'2-digit',month:'2-digit',year:'numeric',timeZone:tz})} ${new Date(e.start_at).toLocaleTimeString('de-AT',{hour:'2-digit',minute:'2-digit',timeZone:tz})} &ndash; ${new Date(e.ends_at).toLocaleDateString('de-AT',{day:'2-digit',month:'2-digit',year:'numeric',timeZone:tz})} ${new Date(e.ends_at).toLocaleTimeString('de-AT',{hour:'2-digit',minute:'2-digit',timeZone:tz})}</strong></td></tr><tr><td style="border:none;padding:1px 0;color:#999;white-space:nowrap;">Effective Event Times:</td><td style="border:none;padding:1px 0 1px 12px;"><strong>${startDateStr} ${startTime} &ndash; ${endDateStr} ${endTime}</strong></td></tr><tr><td style="border:none;padding:1px 0;color:#999;white-space:nowrap;">Effective Duration:</td><td style="border:none;padding:1px 0 1px 12px;"><strong>${durationStr}</strong> &nbsp;&nbsp; <span style="color:#999;">Timezone:</span> ${tzLabel} &nbsp;&nbsp; <span style="color:#999;">Ended by:</span> ${stoppedByMap[e.stopped_by]||'—'}</td></tr></table></div><table><thead><tr><th style="width:30px;">Pos.</th><th>Beschreibung / Description</th><th style="width:60px;">Menge / Qty</th><th style="width:90px;">Preis/Stk / Unit</th><th style="width:90px;">Gesamt / Total</th></tr></thead><tbody>${posRows}</tbody></table><div class="total-box"><table class="total-table"><tr><td>Zwischensumme / Subtotal</td><td style="text-align:right;">€${grandTotal.toFixed(2)}</td></tr><tr><td style="font-size:10px;color:#999;">MwSt. / VAT (0%)*</td><td style="text-align:right;font-size:10px;color:#999;">€0.00</td></tr><tr class="grand"><td>Gesamtbetrag / Total</td><td style="text-align:right;">€${grandTotal.toFixed(2)}</td></tr></table></div><div class="payment-box"><div class="label">Zahlungsinformation / Payment Info</div>${paymentStatus}</div><div class="footer">* Gemäß §6 Abs. 1 Z 27 UStG wird keine Umsatzsteuer berechnet (Kleinunternehmerregelung).<br>&nbsp;&nbsp;In accordance with §6 para. 1 no. 27 Austrian VAT Act, no VAT is charged (small business regulation.).</div></body></html>`;
    res.setHeader('Content-Type', 'text/html');
    res.send(html);
  } catch (err) {
    console.error('Admin invoice error:', err);
    res.status(500).json({ success: false, error: 'server error' });
  }
});


app.get('/api/admin/events/:id/chat-export', requireAdminKey, async (req, res) => {
  const reason = (req.query.reason || '').trim();
  const reasonCategory = (req.query.reason_category || '').trim();
  const referenceId = (req.query.reference_id || '').trim();
  if (!reason) return res.status(400).json({ success: false, error: 'reason required' });
  if (!reasonCategory) return res.status(400).json({ success: false, error: 'reason_category required' });
  const ip = getClientIP(req);
  const crypto = require('crypto');
  const keyHash = crypto.createHash('sha256').update(req.headers['x-admin-key'] || '').digest('hex').slice(0, 16);
  try {
    const event = await pool.query('SELECT * FROM event WHERE id = $1', [req.params.id]);
    if (event.rows.length === 0) return res.status(404).json({ success: false, error: 'not found' });
    if (event.rows[0].status !== 'active') return res.status(403).json({ success: false, error: 'only available for active events' });
    const messages = await pool.query(
      `SELECT s1.nickname as sender_nickname, s2.nickname as receiver_nickname, m.text as message, m.sent_at as timestamp
       FROM message m
       JOIN chat c ON m.chat_id = c.id
       JOIN sticker s1 ON m.sender_id = s1.id
       JOIN sticker s2 ON (CASE WHEN c.seeker_id = m.sender_id THEN c.target_id ELSE c.seeker_id END) = s2.id
       WHERE c.event_id = $1
       ORDER BY m.sent_at ASC`,
      [req.params.id]
    );
    const header = 'sender_nickname,receiver_nickname,message,timestamp\n';
    const csvRows = messages.rows.map(r => {
      const msg = r.message.replace(/"/g, '""');
      return `"${r.sender_nickname}","${r.receiver_nickname}","${msg}","${new Date(r.timestamp).toISOString()}"`;
    }).join('\n');
    const csv = header + csvRows;
    const csvHash = crypto.createHash('sha256').update(csv).digest('hex');
    const auditTimestamp = new Date().toISOString();
    const exportId = 'EX-' + auditTimestamp.slice(0,10).replace(/-/g,'') + '-' + auditTimestamp.slice(11,19).replace(/:/g,'') + '-' + crypto.randomBytes(2).toString('hex').toUpperCase();
    const filename = `nickradar_chat_export_EV-${String(req.params.id).padStart(8,'0')}_${exportId}.csv`;
    await pool.query(
      `INSERT INTO admin_access_log (event_id, action, reason_category, reason, reference_id, ip_address, admin_key_hash, message_count, export_id, csv_hash, created_at)
       VALUES ($1, 'chat_export', $2, $3, $4, $5, $6, $7, $8, $9, NOW())`,
      [req.params.id, reasonCategory, reason, referenceId || null, ip, keyHash, messages.rows.length, exportId, csvHash]
    );
    console.log(`[ADMIN ACCESS] chat_export | export_id=${exportId} | event=${req.params.id} | messages=${messages.rows.length} | category=${reasonCategory} | reason="${reason}" | ref="${referenceId}" | ip=${ip} | key=${keyHash} | csv_hash=${csvHash} | ${auditTimestamp}`);
    if (process.env.AUDIT_EMAIL) {
      const auditSubject = `[nickradar AUDIT] Chat Export | Event:${req.params.id} | ExportID:${exportId} | Category:${reasonCategory} | Msgs:${messages.rows.length} | UTC:${auditTimestamp}`;
      const auditBody = [
        'NICKRADAR AUDIT LOG -- CHAT EXPORT',
        '',
        `Timestamp (UTC): ${auditTimestamp}`,
        `Export ID: ${exportId}`,
        '',
        `Event ID: EV-${String(req.params.id).padStart(8,'0')}`,
        `Event Name: ${event.rows[0].event_name}`,
        '',
        `Reason Category: ${reasonCategory}`,
        `Reason Details: ${reason}`,
        `Reference ID: ${referenceId || '—'}`,
        '',
        `Messages Exported: ${messages.rows.length}`,
        `CSV File Name: ${filename}`,
        `CSV SHA-256: ${csvHash}`,
        '',
        `IP Address: ${ip}`,
        `Admin Key Hash: ${keyHash}`,
        `Access Actor: PRIMARY_OPERATOR`,
        '',
        'This email was generated automatically by nickradar at the time of export.',
        'It serves as an external timestamped audit notification and supplementary evidence of the export event.'
      ].join('\n');
      sendEmail(process.env.AUDIT_EMAIL, auditSubject, auditBody);
    }
    res.setHeader('Content-Type', 'text/csv; charset=utf-8');
    res.setHeader('Content-Disposition', `attachment; filename="${filename}"`);
    res.send(csv);
  } catch (err) {
    console.error('Chat export error:', err);
    res.status(500).json({ success: false, error: 'server error' });
  }
});


app.get('/api/admin/access-log', requireAdminKey, async (req, res) => {
  try {
    const result = await pool.query(
      `SELECT al.*, e.event_name FROM admin_access_log al
       LEFT JOIN event e ON al.event_id = e.id
       ORDER BY al.created_at DESC LIMIT 500`
    );
    res.json({ success: true, logs: result.rows });
  } catch (err) {
    res.status(500).json({ success: false, error: 'server error' });
  }
});

// ============================================================
// HEALTH
// ============================================================

app.get('/', (req, res) => {
  res.json({ message: 'nickradar API v8.0.0', status: 'running' });
});

// ============================================================
// FINISH EVENT
// ============================================================

async function finishEvent(eid, stoppedBy) {
  await pool.query("UPDATE event SET status = 'finished', stopped_at = NOW(), stopped_by = $1, effective_start_at = COALESCE(effective_start_at, start_at), effective_end_at = COALESCE(effective_end_at, NOW()) WHERE id = $2", [stoppedBy, eid]);
  await pool.query("DELETE FROM message WHERE chat_id IN (SELECT id FROM chat WHERE event_id = $1)", [eid]);
  await pool.query("DELETE FROM chat WHERE event_id = $1", [eid]);
  await pool.query("DELETE FROM profile WHERE sticker_id IN (SELECT id FROM sticker WHERE event_id = $1)", [eid]);
  await pool.query("DELETE FROM session WHERE event_id = $1", [eid]);
  await pool.query("UPDATE sticker SET code = NULL WHERE event_id = $1", [eid]);
  await pool.query("DELETE FROM report WHERE event_id = $1", [eid]);
  try {
    const eventResult = await pool.query('SELECT * FROM event WHERE id = $1', [eid]);
    if (eventResult.rows.length === 0) return;
    const e = eventResult.rows[0];
    const packages = await pool.query('SELECT * FROM sticker_package WHERE event_id = $1 ORDER BY created_at ASC', [eid]);
    if (packages.rows.length === 0) return;
    let grandTotal = 0;
    let grandQty = 0;
    packages.rows.forEach(function(p) { const lineTotal = calcPrice(p.quantity); grandTotal += lineTotal; grandQty += p.quantity; });
    const invoiceNumber = await getNextInvoiceNumber();
    const invoiceResult = await pool.query(`INSERT INTO invoice (invoice_number, admin_id, event_id, quantity, unit_price, total, currency, payment_provider, created_at) VALUES ($1, $2, $3, $4, $5, $6, 'EUR', 'stripe', NOW()) RETURNING *`, [invoiceNumber, e.admin_id, eid, grandQty, (grandTotal / grandQty).toFixed(4), grandTotal.toFixed(2)]);
    await pool.query('UPDATE sticker_package SET invoice_id = $1 WHERE event_id = $2', [invoiceResult.rows[0].id, eid]);
  } catch (err) {
    console.error('[finishEvent] Invoice creation error:', err.message);
  }
}

// ============================================================
// CRON
// ============================================================

cron.schedule('* * * * *', async () => {
  try {
    await pool.query(`UPDATE event SET status = 'active', effective_start_at = NOW() WHERE status = 'pending' AND start_at <= NOW() AND paid = TRUE`);
    const expired = await pool.query(`SELECT id FROM event WHERE status = 'active' AND COALESCE(effective_end_at, ends_at) < NOW()`);
    for (const row of expired.rows) {
      await finishEvent(row.id, 'time_expired');
      console.log(`[CRON] Event ${row.id} finished by time_expired`);
    }
  } catch (err) {
    console.error('[CRON] Error:', err.message);
  }
});

// ============================================================
// SERVER START + DB INIT
// ============================================================

app.listen(PORT, '0.0.0.0', async () => {
  console.log(`nickradar API v8.0.0 running on port ${PORT}`);
  try {
    await pool.query(`
      CREATE TABLE IF NOT EXISTS event_admin (
        id SERIAL PRIMARY KEY,
        org_name VARCHAR(100) NOT NULL,
        contact_name VARCHAR(100),
        business_type VARCHAR(50),
        country VARCHAR(100),
        street VARCHAR(150),
        street_number VARCHAR(20),
        postal_code VARCHAR(20),
        city VARCHAR(100),
        vat VARCHAR(50),
        phone VARCHAR(50),
        email VARCHAR(255) UNIQUE NOT NULL,
        password_hash VARCHAR(255) NOT NULL,
        status VARCHAR(20) DEFAULT 'pending',
        email_verified BOOLEAN DEFAULT FALSE,
        verification_token VARCHAR(64),
        verification_token_expires_at TIMESTAMP,
        created_at TIMESTAMP DEFAULT NOW(),
        last_login_at TIMESTAMP
      )
    `);
    await pool.query(`ALTER TABLE event_admin ADD COLUMN IF NOT EXISTS business_type VARCHAR(50)`);
    await pool.query(`ALTER TABLE event_admin ADD COLUMN IF NOT EXISTS email_verified BOOLEAN DEFAULT FALSE`);
    await pool.query(`ALTER TABLE event_admin ADD COLUMN IF NOT EXISTS verification_token VARCHAR(64)`);
    await pool.query(`ALTER TABLE event_admin ADD COLUMN IF NOT EXISTS verification_token_expires_at TIMESTAMP`);
    await pool.query(`ALTER TABLE event_admin ADD COLUMN IF NOT EXISTS street_number VARCHAR(20)`);
    await pool.query(`ALTER TABLE event_admin ADD COLUMN IF NOT EXISTS postal_code VARCHAR(20)`);
    await pool.query(`ALTER TABLE event_admin ADD COLUMN IF NOT EXISTS city VARCHAR(100)`);
    await pool.query(`
      DO $$
      BEGIN
        IF EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name='event_admin' AND column_name='plz_city') THEN
          UPDATE event_admin SET postal_code = SPLIT_PART(plz_city, ' ', 1), city = TRIM(SUBSTRING(plz_city FROM POSITION(' ' IN plz_city))) WHERE plz_city IS NOT NULL AND postal_code IS NULL;
        END IF;
      END $$;
    `);

    await pool.query(`
      CREATE TABLE IF NOT EXISTS event (
        id SERIAL PRIMARY KEY,
        admin_id INTEGER REFERENCES event_admin(id),
        org_name VARCHAR(100),
        event_name VARCHAR(100) NOT NULL,
        start_at TIMESTAMP NOT NULL,
        ends_at TIMESTAMP NOT NULL,
        timezone VARCHAR(50) DEFAULT 'Europe/Vienna',
        status VARCHAR(20) DEFAULT 'pending',
        stopped_at TIMESTAMP,
        stopped_by VARCHAR(20),
        paid BOOLEAN DEFAULT FALSE,
        sticker_count INTEGER DEFAULT 0,
        activated_count INTEGER DEFAULT 0,
        connection_count INTEGER DEFAULT 0,
        created_at TIMESTAMP DEFAULT NOW()
      )
    `);
    await pool.query(`
      DO $$
      BEGIN
                IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name='event' AND column_name='reports_contact_name') THEN
        END IF;
        IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name='event' AND column_name='reports_contact_phone') THEN
        END IF;
        IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name='event' AND column_name='reports_contact_confirmed') THEN
        END IF;
      END $$;
    `);

    await pool.query(`CREATE TABLE IF NOT EXISTS sticker (id SERIAL PRIMARY KEY, event_id INTEGER REFERENCES event(id), nickname VARCHAR(50) NOT NULL, code VARCHAR(10) NOT NULL, status VARCHAR(20) DEFAULT 'unused', activated_at TIMESTAMP, invalidated_at TIMESTAMP, invalidated_by VARCHAR(50), created_at TIMESTAMP DEFAULT NOW(), UNIQUE(event_id, code))`);
    await pool.query(`CREATE TABLE IF NOT EXISTS session (id SERIAL PRIMARY KEY, sticker_id INTEGER REFERENCES sticker(id), event_id INTEGER REFERENCES event(id), token VARCHAR(64) UNIQUE NOT NULL, created_at TIMESTAMP DEFAULT NOW(), expires_at TIMESTAMP NOT NULL, last_seen_at TIMESTAMP, ip_address VARCHAR(45))`);
    await pool.query(`CREATE TABLE IF NOT EXISTS profile (id SERIAL PRIMARY KEY, sticker_id INTEGER REFERENCES sticker(id) UNIQUE, photo_url TEXT, intro VARCHAR(30), updated_at TIMESTAMP DEFAULT NOW())`);
    await pool.query(`CREATE TABLE IF NOT EXISTS request (id SERIAL PRIMARY KEY, seeker_id INTEGER REFERENCES sticker(id), target_id INTEGER REFERENCES sticker(id), event_id INTEGER REFERENCES event(id), message VARCHAR(200) NOT NULL, sent_at TIMESTAMP DEFAULT NOW(), expires_at TIMESTAMP, status VARCHAR(20) DEFAULT 'pending', responded_at TIMESTAMP)`);
    await pool.query(`CREATE TABLE IF NOT EXISTS chat (id SERIAL PRIMARY KEY, request_id INTEGER REFERENCES request(id), event_id INTEGER REFERENCES event(id), seeker_id INTEGER REFERENCES sticker(id), target_id INTEGER REFERENCES sticker(id), started_at TIMESTAMP DEFAULT NOW(), ends_at TIMESTAMP, status VARCHAR(20) DEFAULT 'active', blocked_by INTEGER REFERENCES sticker(id), blocked_at TIMESTAMP)`);
    await pool.query(`CREATE TABLE IF NOT EXISTS message (id SERIAL PRIMARY KEY, chat_id INTEGER REFERENCES chat(id), sender_id INTEGER REFERENCES sticker(id), text TEXT NOT NULL, sent_at TIMESTAMP DEFAULT NOW())`);
    await pool.query(`CREATE TABLE IF NOT EXISTS report (id SERIAL PRIMARY KEY, reporter_id INTEGER REFERENCES sticker(id), reported_id INTEGER REFERENCES sticker(id), event_id INTEGER REFERENCES event(id), reason VARCHAR(100) NOT NULL, details TEXT, created_at TIMESTAMP DEFAULT NOW(), handled_by_admin BOOLEAN DEFAULT FALSE)`);
    await pool.query(`CREATE TABLE IF NOT EXISTS invoice (id SERIAL PRIMARY KEY, invoice_number VARCHAR(20) UNIQUE, admin_id INTEGER REFERENCES event_admin(id), event_id INTEGER REFERENCES event(id), quantity INTEGER NOT NULL, unit_price NUMERIC(10,4), total NUMERIC(10,2), currency VARCHAR(3) DEFAULT 'EUR', payment_provider VARCHAR(50), payment_id VARCHAR(255), paid_at TIMESTAMP, created_at TIMESTAMP DEFAULT NOW())`);
    await pool.query(`CREATE TABLE IF NOT EXISTS sticker_package (id SERIAL PRIMARY KEY, invoice_id INTEGER REFERENCES invoice(id), event_id INTEGER REFERENCES event(id), quantity INTEGER NOT NULL, unit_price NUMERIC(10,4), created_at TIMESTAMP DEFAULT NOW())`);

    await pool.query(`ALTER TABLE report ADD COLUMN IF NOT EXISTS resolved BOOLEAN DEFAULT FALSE`);
    await pool.query(`ALTER TABLE report ADD COLUMN IF NOT EXISTS resolved_at TIMESTAMP`);
    await pool.query(`ALTER TABLE report ADD COLUMN IF NOT EXISTS resolved_by VARCHAR(100)`);
    await pool.query(`ALTER TABLE report ADD COLUMN IF NOT EXISTS resolved_by_ip VARCHAR(45)`);
    await pool.query(`ALTER TABLE event ADD COLUMN IF NOT EXISTS effective_start_at TIMESTAMP`);
    await pool.query(`ALTER TABLE event ADD COLUMN IF NOT EXISTS effective_end_at TIMESTAMP`);
    await pool.query(`ALTER TABLE event ADD COLUMN IF NOT EXISTS terms_accepted_at TIMESTAMP`);
    await pool.query(`ALTER TABLE event ADD COLUMN IF NOT EXISTS terms_accepted_ip VARCHAR(45)`);
    await pool.query(`ALTER TABLE event ADD COLUMN IF NOT EXISTS terms_version VARCHAR(20)`);
    await pool.query(`UPDATE invoice SET invoice_number = 'EAR-' || SUBSTRING(invoice_number FROM 4) WHERE invoice_number LIKE 'EA-%' AND invoice_number NOT LIKE 'EAR-%'`).catch(()=>{});
    await pool.query(`CREATE TABLE IF NOT EXISTS admin_access_log (
      id SERIAL PRIMARY KEY,
      event_id INTEGER REFERENCES event(id),
      action VARCHAR(50) NOT NULL,
      reason_category VARCHAR(50),
      reason TEXT,
      reference_id TEXT,
      ip_address VARCHAR(45),
      admin_key_hash VARCHAR(16),
      message_count INTEGER DEFAULT 0,
      export_id VARCHAR(40),
      csv_hash VARCHAR(64),
      created_at TIMESTAMP DEFAULT NOW()
    )`);
    await pool.query(`ALTER TABLE admin_access_log ADD COLUMN IF NOT EXISTS reason_category VARCHAR(50)`);
    await pool.query(`ALTER TABLE admin_access_log ADD COLUMN IF NOT EXISTS export_id VARCHAR(40)`);
    await pool.query(`ALTER TABLE admin_access_log ADD COLUMN IF NOT EXISTS csv_hash VARCHAR(64)`);
    await pool.query(`ALTER TABLE admin_access_log ADD COLUMN IF NOT EXISTS reference_id TEXT`);
    await pool.query(`ALTER TABLE profile RENAME COLUMN intro TO intro`)
      .catch(() => {}); 
    console.log('DB schema v8.0.0 ready');
  } catch (err) {
    console.error('DB init error:', err.message);
  }
});
