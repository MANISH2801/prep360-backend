// middleware/deviceLock.js
//
// Enforces (or just records) single‑device usage.
//
// ▸ Reads deviceId primarily from JWT payload (req.user.deviceId)  
//   …falls back to x‑device‑id header if needed.
// ▸ Checks / sets the stored device_id column in the users table.
// ▸ Enforcement is toggled with ENFORCE_DEVICE_LOCK=true
// --------------------------------------------------------------

const pool = require('../db');

const {
  ENFORCE_DEVICE_LOCK = 'false', // 'true' ➜ actively block 2nd device
} = process.env;

async function deviceLock(req, res, next) {
  try {
    /* ─────────── 0 ▸ Skip fast when enforcement off ─────────── */
    const shouldBlock = ENFORCE_DEVICE_LOCK === 'true';
    if (!shouldBlock) return next();   // staging: permit any device

    /* ─────────── 1 ▸ Get device ID ──────────────────────────── */
    // Preferred: the JWT payload (set in auth middleware)
    let deviceId = req.user?.deviceId;

    // Fallback to header if token somehow missing it
    if (!deviceId) deviceId = req.headers['x-device-id'];

    if (!deviceId) {
      return res.status(400).json({ error: 'Missing device identifier' });
    }

    /* ─────────── 2 ▸ Read current device_id from DB ─────────── */
    const { rows } = await pool.query(
      'SELECT device_id FROM users WHERE id = $1',
      [req.user.id]
    );

    if (!rows.length) return res.status(401).json({ error: 'User not found' });

    const current = rows[0].device_id;

    /* ─────────── 3 ▸ Enforce / record ───────────────────────── */
    if (current && current !== deviceId) {
      // Someone’s already logged in elsewhere
      return res.status(403).json({ error: 'Account already active on another device' });
    }

    // First‑time login on this account ➜ store the device fingerprint
    if (!current) {
      await pool.query(
        'UPDATE users SET device_id = $1 WHERE id = $2',
        [deviceId, req.user.id]
      );
    }

    return next();
  } catch (err) {
    console.error('[deviceLock]', err);
    return res.status(500).json({ error: 'Device lock failed' });
  }
}

module.exports = deviceLock;
