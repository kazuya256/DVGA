const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const db = require('../database/db');
const config = require('../config');
const { runCommand } = require('../modules/cmd');
const { fetchUrlMetadata } = require('../modules/ssrf');
const { processBase64Upload } = require('../modules/upload');

// Helper to escape HTML to prevent XSS
function escapeHTML(str) {
  if (!str) return '';
  return str
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#x27;');
}

const resolvers = {
  Query: {
    // -------------------------------------------------------------------------
    // BOLA & IDOR: Profile Resolver
    // -------------------------------------------------------------------------
    profile: async (_, { id }, context) => {
      // Require authentication for all users (including vulnerable mode)
      if (!context.user) {
        throw new Error('Authentication required.');
      }

      const mode = config.getSecurityMode();
      
      if (mode === 'VULNERABLE') {
        // INSECURE: Blindly runs unsafe query without validating user ownership
        // and uses string interpolation (SQL Injection vulnerable as well!)
        console.log(`[RESOLVER] Insecure Profile Fetch for ID: ${id}`);
        const queryStr = `SELECT * FROM profiles WHERE id = ${id}`;
        const res = await db.unsafeQuery(queryStr);
        return res.rows[0] || null;
      } else {
        // SECURE: Enforces authentication, parameterizes queries, and checks ownership
        console.log(`[RESOLVER] Secure Profile Fetch for ID: ${id}`);
        
        // Parameterized query to prevent SQLi
        const res = await db.query('SELECT * FROM profiles WHERE id = $1', [id]);
        const profile = res.rows[0];
        
        if (!profile) return null;
        
        // BOLA Mitigation: Check if profile belongs to logged-in user or user is admin
        if (profile.user_id !== context.user.id && context.user.role !== 'admin') {
          throw new Error('Access Denied: You do not have permission to view this profile.');
        }
        
        return profile;
      }
    },

    // -------------------------------------------------------------------------
    // BOLA: Orders Resolver
    // -------------------------------------------------------------------------
    orders: async (_, { userId }, context) => {
      // Require authentication for all users (including vulnerable mode)
      if (!context.user) {
        throw new Error('Authentication required.');
      }

      const mode = config.getSecurityMode();

      if (mode === 'VULNERABLE') {
        // INSECURE: No validation on requested userId. Alice can fetch Bob's orders.
        console.log(`[RESOLVER] Insecure Orders Fetch for User ID: ${userId}`);
        const res = await db.query('SELECT * FROM orders WHERE user_id = $1', [userId]);
        return res.rows;
      } else {
        // SECURE: Enforces that requested orders belong to current logged-in user
        console.log(`[RESOLVER] Secure Orders Fetch for User ID: ${userId}`);

        // BOLA validation: owner check
        if (parseInt(userId, 10) !== context.user.id && context.user.role !== 'admin') {
          throw new Error('Access Denied: You are not authorized to view orders of another user.');
        }

        const res = await db.query('SELECT * FROM orders WHERE user_id = $1', [userId]);
        return res.rows;
      }
    },

    // -------------------------------------------------------------------------
    // IDOR: Single Order Resolver
    // -------------------------------------------------------------------------
    order: async (_, { id }, context) => {
      // Require authentication for all users (including vulnerable mode)
      if (!context.user) {
        throw new Error('Authentication required.');
      }

      const mode = config.getSecurityMode();

      if (mode === 'VULNERABLE') {
        // INSECURE: Blindly returns order by ID. Allows order ID enumeration.
        console.log(`[RESOLVER] Insecure Order ID Fetch: ${id}`);
        const res = await db.query('SELECT * FROM orders WHERE id = $1', [id]);
        return res.rows[0] || null;
      } else {
        // SECURE: Verifies ownership of the requested order
        console.log(`[RESOLVER] Secure Order ID Fetch: ${id}`);

        const res = await db.query('SELECT * FROM orders WHERE id = $1', [id]);
        const order = res.rows[0];
        
        if (!order) return null;

        // IDOR Mitigation: verify ownership
        if (order.user_id !== context.user.id && context.user.role !== 'admin') {
          throw new Error('Access Denied: You are not authorized to view this order.');
        }

        return order;
      }
    },

    // -------------------------------------------------------------------------
    // SQL INJECTION: Products Search
    // -------------------------------------------------------------------------
    productsSearch: async (_, { query }) => {
      const mode = config.getSecurityMode();

      if (mode === 'VULNERABLE') {
        // INSECURE: Direct string concatenation. Allows UNION based injection to leak credentials.
        console.log(`[RESOLVER] Insecure SQL Search query: "${query}"`);
        const queryStr = `SELECT * FROM products WHERE name LIKE '%${query}%' OR description LIKE '%${query}%'`;
        const res = await db.unsafeQuery(queryStr);
        return res.rows;
      } else {
        // SECURE: Uses parameterized variables to neutralize input
        console.log(`[RESOLVER] Secure SQL Search query: "${query}"`);
        const pattern = `%${query}%`;
        const res = await db.query(
          'SELECT * FROM products WHERE name ILIKE $1 OR description ILIKE $1',
          [pattern]
        );
        return res.rows;
      }
    },

    // -------------------------------------------------------------------------
    // STORED XSS: Comments List
    // -------------------------------------------------------------------------
    comments: async () => {
      // Insecure comments returns raw text. Secure returns HTML-escaped text.
      const mode = config.getSecurityMode();
      console.log(`[RESOLVER] Comments Fetch (${mode} mode)`);
      const res = await db.query('SELECT * FROM comments ORDER BY created_at DESC');
      
      if (mode === 'VULNERABLE') {
        return res.rows;
      } else {
        // Escape content to mitigate stored XSS
        return res.rows.map(row => ({
          ...row,
          comment_text: escapeHTML(row.comment_text)
        }));
      }
    },

    // -------------------------------------------------------------------------
    // SSRF: Metadata Fetcher
    // -------------------------------------------------------------------------
    fetchMetadata: async (_, { url }) => {
      const mode = config.getSecurityMode();
      console.log(`[RESOLVER] SSRF Fetch Request for: "${url}" (${mode} mode)`);
      // Calls our metadata module which contains checks
      return await fetchUrlMetadata(url, mode);
    },

    // -------------------------------------------------------------------------
    // COMMAND EXECUTION: Diagnostic logs runner
    // -------------------------------------------------------------------------
    runDiagnostics: async (_, { cmd }, context) => {
      const mode = config.getSecurityMode();
      console.log(`[RESOLVER] Diagnostics execution requested: "${cmd}" (${mode} mode)`);

      if (mode === 'VULNERABLE') {
        // INSECURE: Executes whatever commands are received.
        return new Promise((resolve) => {
          runCommand(cmd, (error, output) => {
            resolve({
              command: cmd,
              output: output || (error ? error.message : 'No output'),
              status: error ? 'ERROR' : 'SUCCESS'
            });
          });
        });
      } else {
        // SECURE: Command execution strictly disabled or whitelisted to non-vulnerable parameters
        if (!context.user || context.user.role !== 'admin') {
          throw new Error('Access Denied: Only system administrators can run server diagnostics.');
        }

        // Whitelist arguments to prevent injection
        const cleanCmd = cmd.trim();
        const allowed = ['ping 127.0.0.1', 'whoami', 'id'];
        if (!allowed.includes(cleanCmd)) {
          throw new Error('Access Denied: Executable command parameters are restricted.');
        }

        return new Promise((resolve) => {
          runCommand(cleanCmd, (error, output) => {
            resolve({
              command: cleanCmd,
              output: output || 'No output',
              status: error ? 'ERROR' : 'SUCCESS'
            });
          });
        });
      }
    },

    // -------------------------------------------------------------------------
    // EXCESSIVE DATA EXPOSURE: Return Users
    // -------------------------------------------------------------------------
    users: async (_, __, context) => {
      const mode = config.getSecurityMode();
      console.log(`[RESOLVER] Users list request (${mode} mode)`);

      if (mode === 'VULNERABLE') {
        // INSECURE: Returns all database columns including password hash and internal fields
        const res = await db.query('SELECT * FROM users');
        return res.rows;
      } else {
        // SECURE: Enforces admin role for user catalog and strips hashes
        if (!context.user || context.user.role !== 'admin') {
          throw new Error('Access Denied: Only administrators can view the user list.');
        }
        const res = await db.query('SELECT id, email, role, is_admin FROM users');
        return res.rows;
      }
    },

    user: async (_, { id }, context) => {
      const mode = config.getSecurityMode();
      console.log(`[RESOLVER] User detail fetch for ID: ${id}`);
      
      const res = await db.query('SELECT * FROM users WHERE id = $1', [id]);
      const user = res.rows[0];
      if (!user) return null;

      if (mode === 'VULNERABLE') {
        return user;
      } else {
        if (!context.user) throw new Error('Authentication required.');
        // Secure mode: Only let user see their own record or be admin, strip password_hash
        if (context.user.id !== user.id && context.user.role !== 'admin') {
          throw new Error('Access Denied.');
        }
        delete user.password_hash;
        return user;
      }
    },

    introspectionStatus: () => {
      return `Introspection is active. Current Security Mode: ${config.getSecurityMode()}`;
    },

    // -------------------------------------------------------------------------
    // API5: BROKEN FUNCTION LEVEL AUTHORIZATION - Transactions Query
    // -------------------------------------------------------------------------
    transactions: async (_, __, context) => {
      const mode = config.getSecurityMode();
      console.log(`[RESOLVER] Transactions list request (${mode} mode)`);

      if (mode === 'VULNERABLE') {
        // INSECURE: Any authenticated user can view ALL transactions including
        // admin salary payments, internal transfers, and financial records.
        // No role check whatsoever - a regular user sees everything.
        if (!context.user) throw new Error('Authentication required.');
        const res = await db.query('SELECT * FROM transactions ORDER BY created_at DESC');
        return res.rows;
      } else {
        // SECURE: Only admin users can access the transactions ledger
        if (!context.user || context.user.role !== 'admin') {
          throw new Error('Access Denied: Only administrators can view financial transactions.');
        }
        const res = await db.query('SELECT * FROM transactions ORDER BY created_at DESC');
        return res.rows;
      }
    },

    // -------------------------------------------------------------------------
    // API6: UNRESTRICTED ACCESS TO SENSITIVE BUSINESS FLOWS - Coupons Query
    // -------------------------------------------------------------------------
    coupons: async (_, __, context) => {
      const mode = config.getSecurityMode();
      console.log(`[RESOLVER] Coupons list request (${mode} mode)`);

      if (mode === 'VULNERABLE') {
        // INSECURE: Returns all coupons including codes, discount values,
        // and usage counts. No authentication required. Attackers can
        // enumerate all coupon codes and abuse high-value ones.
        const res = await db.query('SELECT * FROM coupons');
        return res.rows;
      } else {
        // SECURE: Only admin can list all coupons
        if (!context.user || context.user.role !== 'admin') {
          throw new Error('Access Denied: Only administrators can view the coupon registry.');
        }
        const res = await db.query('SELECT * FROM coupons');
        return res.rows;
      }
    },

    securityMode: () => config.getSecurityMode(),
    learningMode: () => config.getLearningMode()
  },

  Mutation: {
    // -------------------------------------------------------------------------
    // LOGIN & BRUTE FORCE: Handle Authentications
    // -------------------------------------------------------------------------
    login: async (_, { email, password }) => {
      const mode = config.getSecurityMode();
      console.log(`[RESOLVER] Login request for: "${email}" (${mode} mode)`);

      if (mode === 'VULNERABLE') {
        // 1. INSECURE SQL query construction: vulnerable to Login Bypass
        // If SQLi injection succeeds, we fetch user records without verifying hashes!
        const queryStr = `SELECT * FROM users WHERE email = '${email}'`;
        
        try {
          const res = await db.unsafeQuery(queryStr);
          const user = res.rows[0];

          if (!user) {
            throw new Error('Invalid email or password');
          }

          // If standard login, check bcrypt hash. If SQLi login bypass, we skip check!
          // This simulates code that trusts rows returned when querying input directly.
          const isSqliBypass = email.includes("'") || password.includes("'");
          
          if (!isSqliBypass) {
            const valid = await bcrypt.compare(password, user.password_hash);
            if (!valid) {
              throw new Error('Invalid email or password');
            }
          } else {
            console.log('[AUTH] SQL Injection bypass active. Authentication accepted without bcrypt check!');
          }

          // Issue token with weak configuration
          const token = jwt.sign(
            { id: user.id, email: user.email, role: user.role, is_admin: user.is_admin },
            config.getJwtSecret()
          );

          return { token, user };
        } catch (err) {
          // SQL Error leakage: throw the direct system database error
          throw new Error(`Database Query Execution Error: ${err.message}`);
        }
      } else {
        // SECURE: Enforces parameterized queries and bcrypt checks
        // Introduce small login delays to mitigate brute force
        await new Promise((resolve) => setTimeout(resolve, 800));

        const res = await db.query('SELECT * FROM users WHERE email = $1', [email]);
        const user = res.rows[0];

        if (!user) {
          throw new Error('Invalid credentials.');
        }

        const valid = await bcrypt.compare(password, user.password_hash);
        if (!valid) {
          throw new Error('Invalid credentials.');
        }

        // Standard token with explicit algorithm
        const token = jwt.sign(
          { id: user.id, email: user.email, role: user.role },
          config.getJwtSecret(),
          { algorithm: 'HS256', expiresIn: '2h' }
        );

        return { token, user };
      }
    },

    // -------------------------------------------------------------------------
    // STORED XSS / SQLi: Update Bio Mutation
    // -------------------------------------------------------------------------
    updateBio: async (_, { bio }, context) => {
      // Require authentication for all users (including vulnerable mode)
      if (!context.user) {
        throw new Error('Authentication required.');
      }

      const mode = config.getSecurityMode();
      
      if (mode === 'VULNERABLE') {
        // INSECURE: SQL injection vulnerable, saves arbitrary tags (Stored XSS). Allows guests.
        console.log(`[RESOLVER] Insecure Update Bio: "${bio}"`);
        // Escape single quotes for SQL string literal to avoid syntax errors
        const escapedBio = bio.replace(/'/g, "''");
        const queryStr = `UPDATE profiles SET bio = '${escapedBio}' WHERE user_id = ${context.user.id} RETURNING *`;
        const res = await db.unsafeQuery(queryStr);
        return res.rows[0];
      } else {
        // SECURE: Parameterized query, HTML sanitized bio input, strictly requires login
        console.log(`[RESOLVER] Secure Update Bio: "${bio}"`);
        const sanitizedBio = escapeHTML(bio);
        const res = await db.query(
          'UPDATE profiles SET bio = $1 WHERE user_id = $2 RETURNING *',
          [sanitizedBio, context.user.id]
        );
        return res.rows[0];
      }
    },

    // -------------------------------------------------------------------------
    // IDOR / ACCESS CONTROL: Update Profile Address
    // -------------------------------------------------------------------------
    updateProfileAddress: async (_, { profileId, address }, context) => {
      // Require authentication for all users (including vulnerable mode)
      if (!context.user) {
        throw new Error('Authentication required.');
      }

      const mode = config.getSecurityMode();

      if (mode === 'VULNERABLE') {
        // INSECURE: Blindly updates address of ANY profileId without checking authorization!
        console.log(`[RESOLVER] Insecure Update Profile Address for ID: ${profileId}`);
        const queryStr = `UPDATE profiles SET address = '${address}' WHERE id = ${profileId} RETURNING *`;
        const res = await db.unsafeQuery(queryStr);
        return res.rows[0];
      } else {
        // SECURE: Validates that current logged-in user owns the profile they are modifying
        console.log(`[RESOLVER] Secure Update Profile Address for ID: ${profileId}`);

        // Fetch profile first to verify owner
        const checkRes = await db.query('SELECT * FROM profiles WHERE id = $1', [profileId]);
        const profile = checkRes.rows[0];

        if (!profile) {
          throw new Error('Profile not found.');
        }

        // Validate Ownership (IDOR mitigation)
        if (profile.user_id !== context.user.id && context.user.role !== 'admin') {
          throw new Error('Access Denied: You cannot modify address details of another user.');
        }

        const res = await db.query(
          'UPDATE profiles SET address = $1 WHERE id = $2 RETURNING *',
          [address, profileId]
        );
        return res.rows[0];
      }
    },

    // -------------------------------------------------------------------------
    // INSECURE FILE UPLOAD: Mutation Upload
    // -------------------------------------------------------------------------
    uploadFile: async (_, { filename, base64Content }, context) => {
      const mode = config.getSecurityMode();
      console.log(`[RESOLVER] GraphQL File Upload: "${filename}" (${mode} mode)`);

      let uploaderId = null;
      if (context.user) {
        uploaderId = context.user.id;
      }

      // Calls file upload module
      const fileData = await processBase64Upload(filename, base64Content, mode);

      // Save database file record
      const res = await db.query(
        'INSERT INTO files (filename, file_path, uploaded_by) VALUES ($1, $2, $3) RETURNING *',
        [fileData.filename, fileData.filePath, uploaderId]
      );
      
      const row = res.rows[0];
      return {
        id: row.id,
        filename: row.filename,
        filePath: row.file_path,
        size: fileData.size
      };
    },

    // -------------------------------------------------------------------------
    // CREATE FEEDBACK
    // -------------------------------------------------------------------------
    createFeedback: async (_, { email, message }) => {
      const mode = config.getSecurityMode();
      
      if (mode === 'VULNERABLE') {
        const res = await db.query(
          'INSERT INTO feedback (email, message) VALUES ($1, $2) RETURNING *',
          [email, message]
        );
        return res.rows[0];
      } else {
        const cleanEmail = escapeHTML(email);
        const cleanMessage = escapeHTML(message);
        const res = await db.query(
          'INSERT INTO feedback (email, message) VALUES ($1, $2) RETURNING *',
          [cleanEmail, cleanMessage]
        );
        return res.rows[0];
      }
    },

    // -------------------------------------------------------------------------
    // API2: BROKEN AUTHENTICATION - Login with Session Token
    // -------------------------------------------------------------------------
    loginWithToken: async (_, { email, sessionToken }) => {
      const mode = config.getSecurityMode();
      console.log(`[RESOLVER] Token-based login for: "${email}" (${mode} mode)`);

      if (mode === 'VULNERABLE') {
        // INSECURE: Accepts ANY session token value without verification.
        // The server trusts the client-provided token and never validates it
        // against a stored session or checks token integrity.
        // An attacker can provide any string as sessionToken to bypass auth.
        const res = await db.query('SELECT * FROM users WHERE email = $1', [email]);
        const user = res.rows[0];

        if (!user) {
          throw new Error('User not found.');
        }

        // VULNERABILITY: Token is never validated! Any non-empty string works.
        if (!sessionToken || sessionToken.length === 0) {
          throw new Error('Session token is required.');
        }

        console.log(`[AUTH] VULNERABLE: Token-based login accepted without verification for ${email}`);

        const token = jwt.sign(
          { id: user.id, email: user.email, role: user.role, is_admin: user.is_admin },
          config.getJwtSecret()
        );
        return { token, user };
      } else {
        // SECURE: Token-based login is disabled entirely.
        // Proper implementations would validate against a server-side session store.
        throw new Error('Token-based authentication is disabled. Use password-based login.');
      }
    },

    // -------------------------------------------------------------------------
    // API3: BROKEN OBJECT PROPERTY LEVEL AUTHORIZATION - Mass Assignment
    // -------------------------------------------------------------------------
    updateUserProfile: async (_, { userId, email, role, is_admin }, context) => {
      const mode = config.getSecurityMode();
      console.log(`[RESOLVER] Update user profile for ID: ${userId} (${mode} mode)`);

      if (!context.user) {
        throw new Error('Authentication required.');
      }

      if (mode === 'VULNERABLE') {
        // INSECURE: Mass assignment vulnerability!
        // The resolver blindly applies ALL provided fields including
        // role and is_admin, which are privileged properties.
        // A regular user can escalate their own privileges by setting
        // role='admin' and is_admin=true on their own user record.
        const updates = [];
        const values = [];
        let paramIndex = 1;

        if (email !== undefined) {
          updates.push(`email = $${paramIndex++}`);
          values.push(email);
        }
        if (role !== undefined) {
          updates.push(`role = $${paramIndex++}`);
          values.push(role);
        }
        if (is_admin !== undefined) {
          updates.push(`is_admin = $${paramIndex++}`);
          values.push(is_admin);
        }

        if (updates.length === 0) {
          throw new Error('No fields provided to update.');
        }

        values.push(userId);
        const queryStr = `UPDATE users SET ${updates.join(', ')} WHERE id = $${paramIndex} RETURNING *`;
        console.log(`[AUTH] VULNERABLE: Mass assignment update applied: ${queryStr}`);
        const res = await db.query(queryStr, values);
        const user = res.rows[0];
        if (!user) throw new Error('User not found.');
        return { ...user, message: 'Profile updated successfully.' };
      } else {
        // SECURE: Only allow non-privileged field updates (email).
        // role and is_admin changes require admin privileges.
        if (parseInt(userId, 10) !== context.user.id && context.user.role !== 'admin') {
          throw new Error('Access Denied: You can only update your own profile.');
        }

        // Regular users can only update email
        if ((role !== undefined || is_admin !== undefined) && context.user.role !== 'admin') {
          throw new Error('Access Denied: Only administrators can modify role or admin status.');
        }

        const updates = [];
        const values = [];
        let paramIndex = 1;

        if (email !== undefined) {
          updates.push(`email = $${paramIndex++}`);
          values.push(email);
        }
        // Only admin can set these
        if (role !== undefined && context.user.role === 'admin') {
          updates.push(`role = $${paramIndex++}`);
          values.push(role);
        }
        if (is_admin !== undefined && context.user.role === 'admin') {
          updates.push(`is_admin = $${paramIndex++}`);
          values.push(is_admin);
        }

        if (updates.length === 0) {
          throw new Error('No valid fields provided to update.');
        }

        values.push(userId);
        const res = await db.query(
          `UPDATE users SET ${updates.join(', ')} WHERE id = $${paramIndex} RETURNING *`,
          values
        );
        const user = res.rows[0];
        if (!user) throw new Error('User not found.');
        return { ...user, message: 'Profile updated successfully (secure).' };
      }
    },

    // -------------------------------------------------------------------------
    // API5: BROKEN FUNCTION LEVEL AUTHORIZATION - Fund Transfer
    // -------------------------------------------------------------------------
    transferFunds: async (_, { fromUserId, toUserId, amount, description }, context) => {
      const mode = config.getSecurityMode();
      console.log(`[RESOLVER] Fund transfer request: $${amount} from user ${fromUserId} to ${toUserId} (${mode} mode)`);

      if (!context.user) {
        throw new Error('Authentication required.');
      }

      if (mode === 'VULNERABLE') {
        // INSECURE: Any authenticated user can initiate fund transfers
        // between ANY users. No admin role check. No ownership validation.
        // A regular user (Alice) can transfer funds from Admin's account
        // to their own account or to anyone else.
        if (amount <= 0) throw new Error('Amount must be positive.');

        const res = await db.query(
          'INSERT INTO transactions (from_user_id, to_user_id, amount, description) VALUES ($1, $2, $3, $4) RETURNING *',
          [fromUserId, toUserId, amount, description || 'Fund transfer']
        );
        console.log(`[AUTH] VULNERABLE: Unrestricted fund transfer executed by user ${context.user.id}`);
        return res.rows[0];
      } else {
        // SECURE: Only admin can initiate fund transfers
        if (context.user.role !== 'admin') {
          throw new Error('Access Denied: Only administrators can perform fund transfers.');
        }
        if (amount <= 0) throw new Error('Amount must be positive.');

        const res = await db.query(
          'INSERT INTO transactions (from_user_id, to_user_id, amount, description) VALUES ($1, $2, $3, $4) RETURNING *',
          [fromUserId, toUserId, amount, description || 'Fund transfer']
        );
        return res.rows[0];
      }
    },

    // -------------------------------------------------------------------------
    // API5: BROKEN FUNCTION LEVEL AUTHORIZATION - Delete User
    // -------------------------------------------------------------------------
    deleteUser: async (_, { userId }, context) => {
      const mode = config.getSecurityMode();
      console.log(`[RESOLVER] Delete user request for ID: ${userId} (${mode} mode)`);

      if (!context.user) {
        throw new Error('Authentication required.');
      }

      if (mode === 'VULNERABLE') {
        // INSECURE: Any authenticated user can delete ANY user account
        // including admin accounts. No role verification at all.
        const res = await db.query('DELETE FROM users WHERE id = $1 RETURNING id', [userId]);
        if (res.rowCount === 0) throw new Error('User not found.');
        console.log(`[AUTH] VULNERABLE: User ${userId} deleted by non-admin user ${context.user.id}`);
        return true;
      } else {
        // SECURE: Only admin can delete users, and cannot delete self
        if (context.user.role !== 'admin') {
          throw new Error('Access Denied: Only administrators can delete user accounts.');
        }
        if (parseInt(userId, 10) === context.user.id) {
          throw new Error('Cannot delete your own admin account.');
        }
        const res = await db.query('DELETE FROM users WHERE id = $1 RETURNING id', [userId]);
        if (res.rowCount === 0) throw new Error('User not found.');
        return true;
      }
    },

    // -------------------------------------------------------------------------
    // API6: UNRESTRICTED ACCESS TO SENSITIVE BUSINESS FLOWS - Coupon Abuse
    // -------------------------------------------------------------------------
    applyCoupon: async (_, { code }, context) => {
      const mode = config.getSecurityMode();
      console.log(`[RESOLVER] Coupon application request: "${code}" (${mode} mode)`);

      if (mode === 'VULNERABLE') {
        // INSECURE: No authentication required. No rate limiting.
        // No enforcement of max_uses. Attackers can:
        // 1. Apply coupons without logging in
        // 2. Apply the same coupon unlimited times (ignoring max_uses)
        // 3. Apply high-value coupons (VIP50, STAFF75) meant for internal use
        const res = await db.query('SELECT * FROM coupons WHERE code = $1', [code]);
        const coupon = res.rows[0];

        if (!coupon) throw new Error('Invalid coupon code.');
        if (!coupon.is_active) throw new Error('Coupon is no longer active.');

        // VULNERABILITY: max_uses is checked but current_uses is incremented
        // without any concurrency controls, and the check itself is bypassable
        // because we don't actually enforce it in vulnerable mode
        await db.query(
          'UPDATE coupons SET current_uses = current_uses + 1 WHERE id = $1',
          [coupon.id]
        );

        console.log(`[BUSINESS] VULNERABLE: Coupon ${code} applied (uses: ${coupon.current_uses + 1}, max: ${coupon.max_uses})`);

        // Return updated coupon
        const updated = await db.query('SELECT * FROM coupons WHERE id = $1', [coupon.id]);
        return updated.rows[0];
      } else {
        // SECURE: Requires authentication, enforces max_uses, rate limits
        if (!context.user) {
          throw new Error('Authentication required to apply coupons.');
        }

        const res = await db.query('SELECT * FROM coupons WHERE code = $1', [code]);
        const coupon = res.rows[0];

        if (!coupon) throw new Error('Invalid coupon code.');
        if (!coupon.is_active) throw new Error('Coupon is no longer active.');

        // Enforce max usage limit
        if (coupon.current_uses >= coupon.max_uses) {
          throw new Error('Coupon has reached its maximum number of uses.');
        }

        // Check if internal-only coupon (STAFF coupons require admin)
        if (coupon.code.startsWith('STAFF') && context.user.role !== 'admin') {
          throw new Error('Access Denied: This coupon is restricted to staff members.');
        }

        await db.query(
          'UPDATE coupons SET current_uses = current_uses + 1 WHERE id = $1',
          [coupon.id]
        );

        const updated = await db.query('SELECT * FROM coupons WHERE id = $1', [coupon.id]);
        return updated.rows[0];
      }
    },

    // -------------------------------------------------------------------------
    // SYSTEM CONTROLS
    // -------------------------------------------------------------------------
    setSecurityMode: (_, { mode }) => {
      return config.setSecurityMode(mode);
    },

    setLearningMode: (_, { mode }) => {
      return config.setLearningMode(mode);
    }
  },

  User: {
    profile: async (parent) => {
      const res = await db.query('SELECT * FROM profiles WHERE user_id = $1', [parent.id]);
      return res.rows[0] || null;
    }
  },

  Order: {
    product: async (parent) => {
      const res = await db.query('SELECT * FROM products WHERE id = $1', [parent.product_id]);
      return res.rows[0] || null;
    },
    user: async (parent, __, context) => {
      const mode = config.getSecurityMode();
      const res = await db.query('SELECT * FROM users WHERE id = $1', [parent.user_id]);
      const user = res.rows[0];
      
      if (!user) return null;
      
      // Excessive data exposure & Field level authorization failure
      if (mode === 'VULNERABLE') {
        return user;
      } else {
        if (!context.user) return null;
        if (context.user.id !== user.id && context.user.role !== 'admin') {
          // Hide fields
          return null;
        }
        delete user.password_hash;
        return user;
      }
    }
  },

  Comment: {
    user: async (parent) => {
      const res = await db.query('SELECT id, email, role FROM users WHERE id = $1', [parent.user_id]);
      return res.rows[0] || null;
    }
  }
};

module.exports = resolvers;
