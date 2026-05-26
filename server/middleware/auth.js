const jwt = require('jsonwebtoken');
const config = require('../config');

/**
 * Express middleware to extract user data from JWT
 * Attaches user object to request: req.user = { id, email, role, is_admin }
 */
module.exports = (req, res, next) => {
  const authHeader = req.headers.authorization;
  if (!authHeader) {
    req.user = null;
    return next();
  }

  const parts = authHeader.split(' ');
  if (parts.length !== 2 || parts[0].toLowerCase() !== 'bearer') {
    req.user = null;
    return next();
  }

  const token = parts[1];
  const securityMode = config.getSecurityMode();

  if (securityMode === 'VULNERABLE') {
    try {
      // 1. Check for "alg: none" vulnerability
      // Decode JWT headers first
      const decodedParts = token.split('.');
      if (decodedParts.length >= 2) {
        try {
          const headerJson = Buffer.from(decodedParts[0], 'base64').toString('utf8');
          const header = JSON.parse(headerJson);
          
          if (header && header.alg && header.alg.toLowerCase() === 'none') {
            // Vulnerable mode: accept "alg: none" and decode without verifying signature
            const payloadJson = Buffer.from(decodedParts[1], 'base64').toString('utf8');
            const payload = JSON.parse(payloadJson);
            req.user = payload;
            console.log('[AUTH] Vulnerable login accepted via JWT "alg: none":', payload.email);
            return next();
          }
        } catch (e) {
          // Ignore parse errors and fall through
        }
      }

      // 2. Weak JWT Validation: verify using weak secret
      // In vulnerable mode, we also log if the signature is invalid but allow continuing (simulate poor fallback logic or signature bypass)
      const decoded = jwt.verify(token, config.getJwtSecret(), { algorithms: ['HS256', 'none'] });
      req.user = decoded;
    } catch (err) {
      console.warn('[AUTH] JWT verification failed in VULNERABLE mode:', err.message);
      
      // Insecure trust assumption: let's try decoding it anyway to see if the developer used decode() instead of verify()
      try {
        const decoded = jwt.decode(token);
        if (decoded) {
          console.warn('[AUTH] Vulnerability Active: Falling back to decoded token claims without signature verification!');
          req.user = decoded;
        } else {
          req.user = null;
        }
      } catch (decErr) {
        req.user = null;
      }
    }
  } else {
    // MITIGATED (Secure Mode)
    try {
      // Strictly enforce HS256, verify signature with strong secret checking
      const decoded = jwt.verify(token, config.getJwtSecret(), { algorithms: ['HS256'] });
      
      // Additional safety checks
      if (!decoded.id || !decoded.email || !decoded.role) {
        req.user = null;
      } else {
        req.user = decoded;
      }
    } catch (err) {
      console.warn('[AUTH] JWT verification failed in SECURE mode:', err.message);
      req.user = null;
    }
  }

  next();
};
