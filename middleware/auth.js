// middleware/auth.js
//
// ▸ Verifies JWT
// ▸ Adds req.user = { id, role, deviceId }
// ▸ (Optional) blocks if the incoming token’s deviceId ≠ one saved in DB
// ---------------------------------------------------------------------

const jwt = require('jsonwebtoken');
const { User } = require('../models');   // ⚠️ adjust the path if your model folder is elsewhere

const {
  JWT_SECRET,
  ENFORCE_DEVICE_LOCK = 'false', // 'true' ➜ actively block 2nd device
} = process.env;

module.exports = async function auth(req, res, next) {
  try {
    /* ─────────── 1 ▸ Extract token ─────────── */
    const hdr   = req.headers.authorization || '';
    const token = hdr.replace(/^Bearer\s+/i, '');

    if (!token) {
      return res.status(401).json({ error: 'No token provided' });
    }

    /* ─────────── 2 ▸ Verify token ─────────── */
    const payload = jwt.verify(token, JWT_SECRET);
    // payload now contains: { id, role, deviceId, iat, exp }

    /* ─────────── 3 ▸ Attach user context ─────────── */
    req.user = {
      id:        payload.id,
      role:      payload.role,
      deviceId:  payload.deviceId,   // <-- used for device lock
    };

    /* ─────────── 4 ▸ (Optional) single‑device lock ─────────── */
    if (ENFORCE_DEVICE_LOCK === 'true') {
      // Fetch the trusted device_id once and compare
      const user = await User.findByPk(payload.id, { attributes: ['device_id'] });

      if (user && user.device_id && user.device_id !== payload.deviceId) {
        return res
          .status(403)
          .json({ error: 'Account already active on another device' });
      }
    }

    /* ─────────── 5 ▸ Done ─────────── */
    return next();
  } catch (err) {
    console.error('[auth]', err);
    return res.status(401).json({ error: 'Invalid / expired token' });
  }
};
