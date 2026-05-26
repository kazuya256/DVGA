// =========================================================================
// DVGA-Node SPA Frontend Engine
// =========================================================================

// Global State
let activeView = 'dashboard';
let currentModuleId = null;
let securityMode = 'VULNERABLE';
let learningMode = 'BEGINNER';
let jwtToken = localStorage.getItem('dvga_token') || '';

// Reference documentation articles database
const referenceArticles = {
  'resolver-security': {
    title: 'Secure Resolver Coding Best Practices',
    content: `
      <h3>Introduction to Resolver Security</h3>
      <p>GraphQL shifts execution logic from predefined endpoints to granular resolvers. Each field has its own resolver, which means standard authorization filters applied at the routing layer (e.g. Express middleware) are often bypassed or insufficient.</p>
      <h3>The Golden Rules of Resolver Coding:</h3>
      <ul>
        <li><strong>Enforce Authentication:</strong> Explicitly verify the <code>context.user</code> object before returning data or processing state changes.</li>
        <li><strong>Verify Authorization (Ownership):</strong> Do not assume a user requesting an object has permission to read it. Verify that the owner matches <code>context.user.id</code>.</li>
        <li><strong>Use Parameterized Databases:</strong> Never concatenate user input inside queries. Utilize query parameters (e.g. <code>$1</code>) provided by pg.</li>
        <li><strong>Sanitize Input:</strong> Strip HTML and scripts from inputs before they are saved to mitigate Stored Cross-Site Scripting (XSS).</li>
      </ul>
    `
  },
  'authorization-patterns': {
    title: 'Authorization Patterns in GraphQL APIs',
    content: `
      <h3>GraphQL Authorization Strategy</h3>
      <p>Unlike REST where access is validated at the endpoint route level, GraphQL requires object-level and field-level permissions. Authorization can be implemented in three ways:</p>
      <ul>
        <li><strong>Resolver-Level:</strong> Validating permissions inside the individual field resolver function.</li>
        <li><strong>Directive-Level:</strong> Applying schema directives (e.g. <code>@auth(requires: ADMIN)</code>) to filter access.</li>
        <li><strong>Data-Layer:</strong> Encapsulating security checks in the business logic layer or model classes (such as GraphQL DataLoaders) before database access.</li>
      </ul>
    `
  },
  'jwt-security': {
    title: 'JWT (JSON Web Token) Security Guidelines',
    content: `
      <h3>Securing JWT Signatures</h3>
      <p>JWT tokens are client-side credentials. Since they are readable, their security depends entirely on the integrity of the cryptographic signature. Common failures include:</p>
      <ul>
        <li><strong>Accepting None Algorithm:</strong> If the <code>alg</code> field in the token header is set to <code>none</code>, some parsers skip signature validation. Secure servers must strictly enforce signature algorithms (e.g., HS256, RS256).</li>
        <li><strong>Weak Secrets:</strong> Secrets must be cryptographically strong, random keys. Weak secrets are vulnerable to offline brute force cracking.</li>
        <li><strong>Claims Trust Assumption:</strong> Never trust administrative flags (like <code>role: admin</code>) present in the JWT blindly without verifying authorization state.</li>
      </ul>
    `
  },
  'object-authorization': {
    title: 'Mitigating BOLA & IDOR in GraphQL Resolvers',
    content: `
      <h3>Object-Level Access Controls</h3>
      <p>Broken Object Level Authorization (BOLA) occurs when a resolver returns an object based on user-supplied IDs without checking ownership boundaries.</p>
      <p><strong>Example Mitigation:</strong></p>
      <pre style="background: #111b27; padding: 12px; border-radius: 4px; color: #10b981; font-family: monospace;">
async function orderResolver(parent, { id }, context) {
  const order = await db.getOrder(id);
  if (order.userId !== context.user.id && context.user.role !== 'admin') {
    throw new Error("Access Denied");
  }
  return order;
}
      </pre>
    `
  },
  'introspection-risks': {
    title: 'GraphQL Schema Introspection Risks',
    content: `
      <h3>Introspection Exposure</h3>
      <p>GraphQL supports Introspection queries, which allow clients to download the entire API schema definition (types, queries, mutations, parameters). In production, this can leak internal administration endpoints or draft mutations.</p>
      <p><strong>Remediation:</strong> Disable introspection in production. For Apollo Server, set <code>introspection: false</code> and disable the landing page plugins.</p>
    `
  },
  'secure-resolver-design': {
    title: 'Secure Resolver Design Patterns',
    content: `
      <h3>Architecting Defensible Resolvers</h3>
      <p>Decouple authorization checks from database queries by creating validation utilities. Implement a shared wrapper pattern or authorization middleware hooks to protect resolver functions uniformly.</p>
    `
  },
  'field-level-auth': {
    title: 'Field-Level Access Control Strategies',
    content: `
      <h3>Restricting Specific Fields</h3>
      <p>Sometimes the parent object is public, but specific child fields (e.g. <code>password_hash</code>, <code>social_security_number</code>) must be hidden. Apply field-level checks on the types resolvers directly rather than the query route.</p>
    `
  }
};

// Vulnerability challenges database
const vulnerabilityModules = [
  {
    id: 'bola',
    title: 'Broken Object Level Authorization (BOLA)',
    severity: 'critical',
    difficulty: 'easy',
    category: 'Authorization',
    status: 'Pending',
    description: 'Broken Object Level Authorization (BOLA) occurs when an API exposes an endpoint that handles object identifiers but does not validate user privileges regarding the requested object.',
    objective: 'Log in as Alice (user_a@lab.local), copy the JWT token, and execute a query to fetch the profile of Bob (User ID 3) or view Bob\'s order lists.',
    hints: `
      <p><strong>Exploitation Steps:</strong></p>
      <ol>
        <li>Select <strong>Alice</strong> from the Session dropdown in the header. Notice the Authorization token is automatically filled.</li>
        <li>Go to the GraphQL Playground tab.</li>
        <li>Execute the profile query for profile ID 3 (which belongs to Bob):</li>
      </ol>
      <pre style="background:#111b27; color:#38bdf8; padding:8px; border-radius:4px; margin: 8px 0; font-family: monospace;">
query {
  profile(id: "3") {
    id
    fullName
    phone
    address
  }
}
      </pre>
      <p>Observe that in <strong>Vulnerable</strong> mode, you can see Bob\'s physical address. Toggle the mode to <strong>Mitigated</strong> and run it again to see the authorization error.</p>
    `,
    sampleQuery: `query {\n  profile(id: "3") {\n    id\n    fullName\n    phone\n    address\n  }\n}`,
    vulnerableCode: `profile: async (_, { id }) => {\n  // INSECURE: No user check or ownership checks. Directly interpolates input string.\n  const queryStr = \`SELECT * FROM profiles WHERE id = \${id}\`;\n  const res = await db.unsafeQuery(queryStr);\n  return res.rows[0];\n}`,
    secureCode: `profile: async (_, { id }, context) => {\n  // SECURE: Checks authentication, parameterized queries, and ownership validation\n  if (!context.user) {\n    throw new Error('Authentication required.');\n  }\n  const res = await db.query('SELECT * FROM profiles WHERE id = $1', [id]);\n  const profile = res.rows[0];\n  if (!profile) return null;\n\n  // Check if profile owner matches logged-in user\n  if (profile.user_id !== context.user.id && context.user.role !== 'admin') {\n    throw new Error('Access Denied: You do not own this profile.');\n  }\n  return profile;\n}`,
    mitigation: 'Implement strict checks inside the resolver comparing the object\'s owner user ID (<code>profile.user_id</code>) against the authenticated context user ID (<code>context.user.id</code>). Use database parameterized inputs.',
    learning: 'Object-level access validation must reside within the application resolver layer because general routing-based authorization cannot inspect the data records being retrieved.'
  },
  {
    id: 'idor',
    title: 'Insecure Direct Object Reference (IDOR)',
    severity: 'high',
    difficulty: 'easy',
    category: 'Authorization',
    status: 'Pending',
    description: 'IDOR occurs when an application exposes reference to database records (IDs) and allows attackers to modify or access data without permission by changing input values.',
    objective: 'Change the physical address of another user\'s profile using their profile ID.',
    hints: `
      <p><strong>Exploitation Steps:</strong></p>
      <ol>
        <li>Set Session to <strong>Alice</strong> (User A, Profile ID 2).</li>
        <li>Execute the <code>updateProfileAddress</code> mutation targeting profile ID 3 (Bob\'s profile):</li>
      </ol>
      <pre style="background:#111b27; color:#38bdf8; padding:8px; border-radius:4px; margin:8px 0; font-family:monospace;">
mutation {
  updateProfileAddress(profileId: "3", address: "HACKED ADDRESS") {
    id
    address
  }
}
      </pre>
      <p>Under <strong>Vulnerable</strong> mode, the mutation succeeds. In <strong>Mitigated</strong> mode, it rejects the operation due to ownership mismatch.</p>
    `,
    sampleQuery: `mutation {\n  updateProfileAddress(profileId: "3", address: "1337 Cyber Lane, Hackerspace") {\n    id\n    address\n  }\n}`,
    vulnerableCode: `updateProfileAddress: async (_, { profileId, address }) => {\n  // INSECURE: Blind write, no ownership verification\n  const queryStr = \`UPDATE profiles SET address = '\${address}' WHERE id = \${profileId} RETURNING *\`;\n  const res = await db.unsafeQuery(queryStr);\n  return res.rows[0];\n}`,
    secureCode: `updateProfileAddress: async (_, { profileId, address }, context) => {\n  // SECURE: Fetches record first, validates ownership, updates via parameterized query\n  if (!context.user) throw new Error('Authentication required.');\n  const checkRes = await db.query('SELECT * FROM profiles WHERE id = $1', [profileId]);\n  const profile = checkRes.rows[0];\n  if (!profile) throw new Error('Profile not found.');\n\n  if (profile.user_id !== context.user.id && context.user.role !== 'admin') {\n    throw new Error('Access Denied: You cannot modify this profile.');\n  }\n\n  const res = await db.query(\n    'UPDATE profiles SET address = $1 WHERE id = $2 RETURNING *',\n    [address, profileId]\n  );\n  return res.rows[0];\n}`,
    mitigation: 'Before applying mutations or SQL updates, execute a preliminary read query to confirm the user ID on the record matches the user ID in the session context.',
    learning: 'Always treat write actions (mutations) with extra validation steps. Prevent users from performing state changes on resources they do not own.'
  },
  {
    id: 'jwt',
    title: 'Weak JWT Validation',
    severity: 'critical',
    difficulty: 'medium',
    category: 'Authentication',
    status: 'Pending',
    description: 'If the token signature checking is flawed or utilizes weak secrets, attackers can forge admin-level JWT tokens, enabling full system access.',
    objective: 'Forge a JWT token with "alg: none" or crack the weak secret to gain access to admin query parameters.',
    hints: `
      <p><strong>Exploitation Steps:</strong></p>
      <ol>
        <li>Craft a JWT payload with <code>"role": "admin"</code>.</li>
        <li>Format the token header with <code>"alg": "none"</code>. Encode the header and payload in base64, concatenate them with dots, and append an empty signature: <code>eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJpZCI6Miwicm9sZSI6ImFkbWluIiwiZW1haWwiOiJ1c2VyX2FAbGFiLmxvY2FsIn0.</code></li>
        <li>Paste this forged token into the <strong>Authorization JWT Token Header</strong> box in the playground and query <code>users { id email role }</code>.</li>
      </ol>
    `,
    sampleQuery: `query {\n  users {\n    id\n    email\n    role\n  }\n}`,
    vulnerableCode: `// INSECURE: Accepts "alg: none" by parsing the base64 parts directly without verification\nif (header && header.alg.toLowerCase() === 'none') {\n  req.user = JSON.parse(payload);\n  return next();\n}`,
    secureCode: `// SECURE: Enforces signature verification and restricts algorithms strictly\ntry {\n  const decoded = jwt.verify(token, config.getJwtSecret(), { algorithms: ['HS256'] });\n  req.user = decoded;\n} catch (err) {\n  req.user = null;\n}`,
    mitigation: 'Configure the JWT validation library to strictly specify supported signature algorithms (e.g. <code>algorithms: ["HS256"]</code>) and reject unsigned header settings.',
    learning: 'A JWT is only as secure as its signature check. Never fallback to signature-less decoding schemes in server environments.'
  },
  {
    id: 'bac',
    title: 'Broken Access Control',
    severity: 'high',
    difficulty: 'easy',
    category: 'Authorization',
    status: 'Pending',
    description: 'Broken Access Control happens when privilege restrictions are missing, allowing regular users to execute admin mutations or retrieve private datasets.',
    objective: 'Retrieve the system\'s full user directory listing while logged in as a normal user (Alice or Bob).',
    hints: `
      <p><strong>Exploitation Steps:</strong></p>
      <ol>
        <li>Log in as Alice.</li>
        <li>Run the <code>users</code> query:</li>
      </ol>
      <pre style="background:#111b27; color:#38bdf8; padding:8px; border-radius:4px; margin:8px 0; font-family:monospace;">
query {
  users {
    id
    email
    role
  }
}
      </pre>
      <p>In <strong>Vulnerable</strong> mode, the server happily lists the database tables. In <strong>Mitigated</strong> mode, the query returns an error: "Access Denied: Only administrators can view the user list."</p>
    `,
    sampleQuery: `query {\n  users {\n    id\n    email\n    role\n  }\n}`,
    vulnerableCode: `users: async (_, __, context) => {\n  // INSECURE: Blindly queries all users without validating user's administrative level\n  const res = await db.query('SELECT * FROM users');\n  return res.rows;\n}`,
    secureCode: `users: async (_, __, context) => {\n  // SECURE: Enforces that user is authenticated AND holds admin role\n  if (!context.user || context.user.role !== 'admin') {\n    throw new Error('Access Denied: Only administrators can view the user list.');\n  }\n  const res = await db.query('SELECT id, email, role, is_admin FROM users');\n  return res.rows;\n}`,
    mitigation: 'Implement role-based or attribute-based authorization checks in the resolver before extracting records.',
    learning: 'Always apply authorization barriers globally or inside individual sensitive resolvers.'
  },
  {
    id: 'sqli',
    title: 'SQL Injection (SQLi)',
    severity: 'critical',
    difficulty: 'medium',
    category: 'Injection',
    status: 'Pending',
    description: 'SQL Injection occurs when user input is concatenated directly into SQL queries, giving attackers the ability to run raw database operations.',
    objective: 'Bypass search limits or perform a UNION attack to leak credentials from the users table.',
    hints: `
      <p><strong>Exploitation Steps:</strong></p>
      <ol>
        <li>In the playground, run a query searching products.</li>
        <li>Inject a UNION SELECT payload into the query argument:</li>
      </ol>
      <pre style="background:#111b27; color:#38bdf8; padding:8px; border-radius:4px; margin:8px 0; font-family:monospace;">
query {
  productsSearch(query: "Audit%' UNION SELECT id, email, password_hash, role, '1' FROM users --") {
    id
    name
    price
    description
  }
}
      </pre>
      <p>Observe that in <strong>Vulnerable</strong> mode, the products search yields the user database table credentials (hashed passwords) reflected in the fields!</p>
    `,
    sampleQuery: `query {\n  productsSearch(query: "Audit%' UNION SELECT id, email, 0, concat(password_hash,'|',role) FROM users --") {\n    id\n    name\n    price\n    description\n  }\n}`,
      
    vulnerableCode: `productsSearch: async (_, { query }) => {\n  // INSECURE: Concatenating input strings directly into dynamic SQL queries\n  const queryStr = \`SELECT * FROM products WHERE name LIKE '%\${query}%' OR description LIKE '%\${query}%'\`;\n  const res = await db.unsafeQuery(queryStr);\n  return res.rows;\n}`,
    secureCode: `productsSearch: async (_, { query }) => {\n  // SECURE: Neutralize inputs using parameterized arrays\n  const pattern = \`%\${query}%\`;\n  const res = await db.query(\n    'SELECT * FROM products WHERE name ILIKE $1 OR description ILIKE $1',\n    [pattern]\n  );\n  return res.rows;\n}`,
    mitigation: 'Ensure that you NEVER construct SQL queries dynamically using string concatenation or template strings. Always utilize parameterized query arrays.',
    learning: 'Direct SQL execution wrappers like pg require parameterized placeholders ($1, $2) to treat inputs as strings rather than executable SQL statements.'
  },
  {
    id: 'storedxss',
    title: 'XSS (Stored)',
    severity: 'high',
    difficulty: 'easy',
    category: 'Cross-Site Scripting',
    status: 'Pending',
    description: 'Stored Cross-Site Scripting occurs when an input containing malicious scripting tags is stored in the database and loaded without sanitization in the client UI.',
    objective: 'Inject a comment or profile bio containing HTML scripts that execute when comments are loaded.',
    hints: `
      <p><strong>Exploitation Steps:</strong></p>
      <ol>
        <li>Execute a mutation to update your bio or post a comment with script payloads:</li>
      </ol>
      <pre style="background:#111b27; color:#38bdf8; padding:8px; border-radius:4px; margin:8px 0; font-family:monospace;">
mutation {
  updateBio(bio: "&lt;img src=x onerror=alert('StoredXSS')&gt;") {
    bio
  }
}
      </pre>
      <p>When the client application reads and displays bios/comments, the script runs directly.</p>
    `,
    sampleQuery: `mutation {\n  updateBio(bio: "<img src=x onerror=alert('Stored-XSS')>") {\n    id\n    bio\n  }\n}`,
    vulnerableCode: `updateBio: async (_, { bio }, context) => {\n  // INSECURE: Directly saves the input tags to database\n  const queryStr = \`UPDATE profiles SET bio = '\${bio}' WHERE user_id = \${context.user.id} RETURNING *\`;\n  const res = await db.unsafeQuery(queryStr);\n  return res.rows[0];\n}`,
    secureCode: `updateBio: async (_, { bio }, context) => {\n  // SECURE: Escapes user inputs before database storage or on retrieval\n  const sanitizedBio = escapeHTML(bio);\n  const res = await db.query(\n    'UPDATE profiles SET bio = $1 WHERE user_id = $2 RETURNING *',\n    [sanitizedBio, context.user.id]\n  );\n  return res.rows[0];\n}`,
    mitigation: 'Implement input validation or HTML entity-encoding on user-supplied strings before rendering them or saving them to databases.',
    learning: 'Escape dynamic content using HTML character entity references to neutralize code interpretation by web browsers.'
  },
  {
    id: 'ssrf',
    title: 'Server-Side Request Forgery (SSRF)',
    severity: 'high',
    difficulty: 'medium',
    category: 'SSRF',
    status: 'Pending',
    description: 'SSRF allows an attacker to force the server into hosting requests targeting local servers, loopback addresses, or protected internal metadata endpoints.',
    objective: 'Query loopback addresses (like localhost or 127.0.0.1) or internal server indicators.',
    hints: `
      <p><strong>Exploitation Steps:</strong></p>
      <ol>
        <li>Trigger the metadata query using localhost address port 5013 (the app port itself) or loopbacks:</li>
      </ol>
      <pre style="background:#111b27; color:#38bdf8; padding:8px; border-radius:4px; margin:8px 0; font-family:monospace;">
query {
  fetchMetadata(url: "http://localhost:5013/healthz")
}
      </pre>
      <p>In <strong>Vulnerable</strong> mode, the server retrieves internal diagnostic information. In <strong>Mitigated</strong> mode, the query yields an error: "Access denied: Requesting local resources is prohibited."</p>
    `,
    sampleQuery: `query {\n  fetchMetadata(url: "http://localhost:5013/healthz")\n}`,
    vulnerableCode: `// INSECURE: Blindly fetches target URLs\nconst response = await axios.get(targetUrl);\nreturn response.data;`,
    secureCode: `// SECURE: Validates protocols and checks host against private IP ranges (RFC 1918)\nconst parsed = new URL(targetUrl);\nif (isPrivateAddress(parsed.hostname)) {\n  throw new Error("Access Denied: Private IP space requested.");\n}\nconst response = await axios.get(targetUrl);`,
    mitigation: 'Parse URL inputs and block DNS resolution targeting private CIDR blocks (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, 127.0.0.0/8, 169.254.169.254).',
    learning: 'Always enforce domain Whitelists for server-initiated fetches or restrict external requests to isolated outbound network proxy setups.'
  },
  {
    id: 'bruteforce',
    title: 'Brute Force Throttling Failure',
    severity: 'medium',
    difficulty: 'easy',
    category: 'Authentication',
    status: 'Pending',
    description: 'Failure to implement rate limiting on authentication mutations allows attackers to guess user credentials via dictionary attacks.',
    objective: 'Submit multiple rapid login requests without being blocked by throttling layers.',
    hints: `
      <p><strong>Exploitation Steps:</strong></p>
      <ol>
        <li>Switch security levels to observe differences.</li>
        <li>In <strong>Vulnerable</strong> mode, execution completes instantly, allowing automated password spray scripts.</li>
        <li>In <strong>Mitigated</strong> mode, resolvers introduce artificial delays on processing authentication requests.</li>
      </ol>
    `,
    sampleQuery: `mutation {\n  login(email: "admin@lab.local", password: "WrongPassword") {\n    token\n  }\n}`,
    vulnerableCode: `login: async (_, { email, password }) => {\n  // INSECURE: Completes instantly on failure. No rate limiting or delay logic.\n  const res = await db.query('SELECT * FROM users WHERE email = $1', [email]);\n  ...\n}`,
    secureCode: `login: async (_, { email, password }) => {\n  // SECURE: Introduces database sleep delay on credentials check to throttle dictionary attacks\n  await new Promise((resolve) => setTimeout(resolve, 800));\n  const res = await db.query('SELECT * FROM users WHERE email = $1', [email]);\n  ...\n}`,
    mitigation: 'Implement IP-based or account-based lockouts using tools like <code>express-rate-limit</code> or Redis rate-limiters. Introduce computational delays for incorrect requests.',
    learning: 'Slowing down credentials validation minimizes the speed and effectiveness of brute-forcing programs.'
  },
  {
    id: 'cmdexec',
    title: 'Command Execution Risks',
    severity: 'critical',
    difficulty: 'hard',
    category: 'Injection',
    status: 'Pending',
    description: 'Spawning shell processes using unvalidated inputs allows command injection, letting attackers execute arbitrary OS commands.',
    objective: 'Inject malicious command separators (like semicolon or pipeline) to read simulated files like /etc/passwd.',
    hints: `
      <p><strong>Exploitation Steps:</strong></p>
      <ol>
        <li>Execute diagnostics command query.</li>
        <li>Append command injection separators to leak credentials:</li>
      </ol>
      <pre style="background:#111b27; color:#38bdf8; padding:8px; border-radius:4px; margin:8px 0; font-family:monospace;">
query {
  runDiagnostics(cmd: "ping 127.0.0.1;") {
    output
    status
  }
}
      </pre>
    `,
    sampleQuery: `query {\n  runDiagnostics(cmd: "ping 127.0.0.1") {\n    command\n    output\n    status\n  }\n}`,
    vulnerableCode: `runDiagnostics: async (_, { cmd }) => {\n  // INSECURE: Executes command string directly inside the system shell context\n  return new Promise((resolve) => {\n    runCommand(cmd, (error, output) => {\n      resolve({ output, status: error ? 'ERROR' : 'SUCCESS' });\n    });\n  });\n}`,
    secureCode: `runDiagnostics: async (_, { cmd }, context) => {\n  // SECURE: Enforce admin role authentication, check whitelist parameters\n  if (!context.user || context.user.role !== 'admin') throw new Error('Unauthorized');\n\n  const allowed = ['ping 127.0.0.1', 'whoami', 'id'];\n  if (!allowed.includes(cmd.trim())) {\n    throw new Error('Command execution parameter restricted.');\n  }\n  // Execute only safe whitelisted command string\n}`,
    mitigation: 'Avoid executing shell commands dynamically. If required, restrict execution parameter inputs using static whitelists or parameterized argument APIs (e.g. <code>execFile</code>).',
    learning: 'Direct shell execution (<code>child_process.exec</code>) spawns command interpreters which evaluate metacharacters. Parameterized executors prevent this evaluation.'
  },
  {
    id: 'introspection',
    title: 'Introspection Schema Exposure',
    severity: 'low',
    difficulty: 'easy',
    category: 'Information Disclosure',
    status: 'Pending',
    description: 'Enabling Introspection in production environments exposes the full API structure, exposing draft endpoints and sensitive database mappings.',
    objective: 'Inspect the GraphQL system schema using tools or the default introspect helper query.',
    hints: `
      <p><strong>Exploitation Steps:</strong></p>
      <ol>
        <li>Submit query parameters testing default system meta-fields:</li>
      </ol>
      <pre style="background:#111b27; color:#38bdf8; padding:8px; border-radius:4px; margin:8px 0; font-family:monospace;">
query {
  __schema {
    types {
      name
      fields {
        name
      }
    }
  }
}
      </pre>
    `,
    sampleQuery: `query {\n  __schema {\n    types {\n      name\n      fields {\n        name\n      }\n    }\n  }\n}`,
    vulnerableCode: `// INSECURE: Introspection is active globally, exposing all internal query schemes\nconst server = new ApolloServer({\n  typeDefs,\n  resolvers,\n  introspection: true\n});`,
    secureCode: `// SECURE: Disable introspection for production-facing applications\nconst server = new ApolloServer({\n  typeDefs,\n  resolvers,\n  introspection: process.env.NODE_ENV !== 'production' // or false\n});`,
    mitigation: 'Configure Apollo Server or GraphQL Yoga with <code>introspection: false</code> in production environments.',
    learning: 'Disabling schema introspection forces attackers to guess queries, restricting simple black-box scanning capabilities.'
  },
  {
    id: 'excessive',
    title: 'Excessive Data Exposure',
    severity: 'medium',
    difficulty: 'easy',
    category: 'Information Disclosure',
    status: 'Pending',
    description: 'Excessive Data Exposure occurs when resolvers retrieve and serialize entire database rows, leaking internal fields (like password hashes) that the frontend does not display but are visible in the API payload response.',
    objective: 'Fetch all users in the system and verify if password hashes are exposed in the JSON response.',
    hints: `
      <p><strong>Exploitation Steps:</strong></p>
      <ol>
        <li>Run the <code>users</code> query including the <code>password_hash</code> field:</li>
      </ol>
      <pre style="background:#111b27; color:#38bdf8; padding:8px; border-radius:4px; margin:8px 0; font-family:monospace;">
query {
  users {
    id
    email
    role
    password_hash
  }
}
      </pre>
      <p>In <strong>Vulnerable</strong> mode, the hashes are returned. In <strong>Mitigated</strong> mode, the schema returns validation errors or null fields.</p>
    `,
    sampleQuery: `query {\n  users {\n    id\n    email\n    role\n    password_hash\n  }\n}`,
    vulnerableCode: `// INSECURE: GraphQL User type exposes password_hash. Resolver query return all db columns.\ntype User {\n  id: ID!\n  email: String!\n  password_hash: String\n}\n\nusers: async () => {\n  return await db.query('SELECT * FROM users'); // Returns password_hash too!\n}`,
    secureCode: `// SECURE: Strip password_hash from the schema definition and explicitly select required fields in SQL\ntype User {\n  id: ID!\n  email: String!\n  role: String!\n}\n\nusers: async () => {\n  return await db.query('SELECT id, email, role FROM users'); // Do not select password_hash\n}`,
    mitigation: 'Remove sensitive fields (like password hashes, token secrets, SSN) from the GraphQL schema types. Ensure SQL queries select only needed columns.',
    learning: 'Do not rely on the client frontend to hide sensitive fields. Validate security models at the API schema tier.'
  },
  {
    id: 'fieldauth',
    title: 'Field-Level Authorization Failure',
    severity: 'medium',
    difficulty: 'easy',
    category: 'Authorization',
    status: 'Pending',
    description: 'Field-Level Authorization failure happens when a field containing sensitive details is exposed publicly inside a parent type, instead of restricting it to authorized roles.',
    objective: 'Fetch parent records (like Order list) and extract details of other user accounts (like email addresses or role parameters) using nested relations.',
    hints: `
      <p><strong>Exploitation Steps:</strong></p>
      <ol>
        <li>Query orders list (using IDOR order lookup).</li>
        <li>Query nested user information block:</li>
      </ol>
      <pre style="background:#111b27; color:#38bdf8; padding:8px; border-radius:4px; margin:8px 0; font-family:monospace;">
query {
  order(id: "2") {
    id
    quantity
    user {
      email
      role
      is_admin
    }
  }
}
      </pre>
      <p>Under <strong>Vulnerable</strong> mode, details are exposed. In <strong>Mitigated</strong> mode, nested queries on unauthorized accounts return null or error messages.</p>
    `,
    sampleQuery: `query {\n  order(id: "2") {\n    id\n    quantity\n    user {\n      email\n      role\n      is_admin\n    }\n  }\n}`,
    vulnerableCode: `Order: {\n  user: async (parent) => {\n    // INSECURE: No authorization checks when returning related User object\n    const res = await db.query('SELECT * FROM users WHERE id = $1', [parent.user_id]);\n    return res.rows[0];\n  }\n}`,
    secureCode: `Order: {\n  user: async (parent, __, context) => {\n    // SECURE: Enforce that requester is the owner of the order OR an admin\n    if (!context.user) return null;\n    if (context.user.id !== parent.user_id && context.user.role !== 'admin') {\n      return null; // Silent block or throw Authorization Error\n    }\n    const res = await db.query('SELECT id, email, role FROM users WHERE id = $1', [parent.user_id]);\n    return res.rows[0];\n  }\n}`,
    mitigation: 'Implement explicit authorization validations inside nested/relational fields resolver functions.',
    learning: 'GraphQL is a graph. Access to nodes can be reached via many edge relations. Securing parent queries is not enough; secure child resolvers.'
  },
  {
    id: 'errorleak',
    title: 'Sensitive Error Leakage',
    severity: 'low',
    difficulty: 'easy',
    category: 'Information Disclosure',
    status: 'Pending',
    description: 'Exposing detailed SQL syntax errors, application stacks, or library debug traces helps attackers construct functional exploit payloads.',
    objective: 'Generate a database syntax error (e.g. by sending malformed queries to SQLi target) and inspect the returned error message extensions.',
    hints: `
      <p><strong>Exploitation Steps:</strong></p>
      <ol>
        <li>Submit search parameters containing single quote malformed expressions.</li>
        <li>Inspect the response errors block.</li>
        <li>Observe raw system error parameters containing SQL files info and query snippets.</li>
      </ol>
    `,
    sampleQuery: `query {\n  productsSearch(query: "'") {\n    id\n  }\n}`,
    vulnerableCode: `// INSECURE: Returns raw stack trace and database original error parameters\nformatError: (formattedError, error) => {\n  return {\n    message: error.message,\n    extensions: { stacktrace: error.stack, originalError: error.originalError }\n  };\n}`,
    secureCode: `// SECURE: Intercept database errors, mask with generic messages, hide system stack details\nformatError: (formattedError, error) => {\n  let message = formattedError.message;\n  if (message.includes('syntax error') || message.includes('relation')) {\n    message = 'Internal server error occurred.';\n  }\n  return { message, code: 'INTERNAL_SERVER_ERROR' };\n}`,
    mitigation: 'Utilize customized Apollo Server error formatters (<code>formatError</code>) to sanitize error message extensions in production settings.',
    learning: 'Database traces tell hackers what table name schemas and query models exist. Keep error messages user-friendly and generic.'
  },
  {
    id: 'fileupload',
    title: 'Insecure File Upload Validation',
    severity: 'high',
    difficulty: 'medium',
    category: 'File Upload',
    status: 'Pending',
    description: 'Failing to check file extensions or MIME headers allows uploading arbitrary files (e.g. PHP shell or HTML with XSS) directly to public folders.',
    objective: 'Upload a file containing an insecure file extension (e.g. filename ending with .html containing scripts or .php).',
    hints: `
      <p><strong>Exploitation Steps:</strong></p>
      <ol>
        <li>Go to the Playground. Notice the custom form helper field is visible because this module is active.</li>
        <li>Provide filename <code>exploit.html</code>.</li>
        <li>Paste HTML/JS contents: <code>&lt;script&gt;alert('File Upload XSS')&lt;/script&gt;</code>.</li>
        <li>Execute mutation. Click the link returned in the response object. Observe that the script runs directly on the local web port.</li>
      </ol>
    `,
    sampleQuery: `mutation {\n  uploadFile(filename: "exploit.html", base64Content: "PHNjcmlwdD5hbGVydCgnRmlsZSBVcGxvYWQgWFNTJyk8L3NjcmlwdD4=") {\n    id\n    filename\n    filePath\n  }\n}`,
    vulnerableCode: `// INSECURE: Saves files directly to directories without validation checks\nconst destPath = path.join(uploadDir, filename);\nfs.writeFileSync(destPath, buffer);`,
    secureCode: `// SECURE: Enforces strict whitelist of extensions and checks signature headers\nconst ext = path.extname(filename).toLowerCase();\nconst allowed = ['.jpg', '.jpeg', '.png', '.pdf', '.txt'];\nif (!allowed.includes(ext)) {\n  throw new Error("Invalid file extension!");\n}`,
    mitigation: 'Implement files whitelist (MIME type and file extensions) checks. Save uploaded files in remote storage (S3) rather than locally, or disable execution rights on server folders.',
    learning: 'Insecure file handling allows path traversal attempts (../) and execution of active web server shells.'
  },
  {
    id: 'weakpass',
    title: 'Weak Password Policy',
    severity: 'medium',
    difficulty: 'easy',
    category: 'Authentication',
    status: 'Pending',
    description: 'Allowing weak or predictable passwords exposes training environments to simple dictionary scans.',
    objective: 'Attempt authentication requests using standard administrative credentials.',
    hints: `
      <p><strong>Exploitation Steps:</strong></p>
      <ol>
        <li>Try authenticating admin accounts with weak passwords: <code>admin@lab.local</code> / <code>Admin123!</code>.</li>
        <li>Observe that simple credentials succeed.</li>
      </ol>
    `,
    sampleQuery: `mutation {\n  login(email: "admin@lab.local", password: "Admin123!") {\n    token\n    user {\n      id\n      email\n      role\n    }\n  }\n}`,
    vulnerableCode: `// INSECURE: Accept weak passwords and keep standard training parameters open\n// admin@lab.local / Admin123!`,
    secureCode: `// SECURE: Enforce password complexity check (minimum 12 chars, upper/lower case, special character)\nif (password.length < 12) {\n  throw new Error("Password must be at least 12 characters.");\n}`,
    mitigation: 'Enforce strict passwords checks during registration. Integrate standard password validator libraries.',
    learning: 'Training accounts are simple entries for scanners. Secure standard defaults.'
  }
];

// Document Event Listeners
document.addEventListener('DOMContentLoaded', () => {
  initUI();
});

// Initialize UI
function initUI() {
  renderVulnerabilityCards();
  renderSidebarList();
  
  // Navigation elements
  document.getElementById('go-home').addEventListener('click', showDashboard);
  document.getElementById('back-to-dashboard').addEventListener('click', showDashboard);
  document.getElementById('ref-back-to-dashboard').addEventListener('click', showDashboard);
  document.getElementById('nav-docs-link').addEventListener('click', (e) => {
    e.preventDefault();
    loadReferenceArticle('resolver-security');
  });

  // Mode Dropdowns change
  document.getElementById('security-mode').addEventListener('change', async (e) => {
    const val = e.target.value;
    try {
      const mode = await executeGraphQLMutation(`
        mutation {
          setSecurityMode(mode: "${val}")
        }
      `);
      securityMode = mode.setSecurityMode;
      document.getElementById('security-mode').value = securityMode;
      // Style toggle dropdown
      document.getElementById('security-mode').setAttribute('value', securityMode);
      console.log('Server security mode changed to:', securityMode);
    } catch (err) {
      console.error('Error toggling server security:', err);
    }
  });

  document.getElementById('learning-mode').addEventListener('change', (e) => {
    learningMode = e.target.value;
    updateLearningModeUI();
  });

  document.getElementById('session-select').addEventListener('change', async (e) => {
    const val = e.target.value;
    await switchSession(val);
  });

  // Tab buttons click
  const tabButtons = document.querySelectorAll('.tab-btn');
  tabButtons.forEach(btn => {
    btn.addEventListener('click', (e) => {
      const tabId = e.target.getAttribute('data-tab');
      switchTab(tabId);
    });
  });

  // Playground actions
  document.getElementById('btn-run-query').addEventListener('click', runPlaygroundQuery);
  document.getElementById('btn-prefill-query').addEventListener('click', () => {
    const currentModule = vulnerabilityModules.find(m => m.id === currentModuleId);
    if (currentModule) {
      document.getElementById('graphql-query-input').value = currentModule.sampleQuery;
    }
  });

  // Reference sidebar click
  const refLinks = document.querySelectorAll('#reference-list li');
  refLinks.forEach(link => {
    link.addEventListener('click', (e) => {
      const refKey = e.target.getAttribute('data-ref');
      loadReferenceArticle(refKey);
    });
  });

  // File upload injector
  document.getElementById('btn-inject-upload').addEventListener('click', () => {
    const fn = document.getElementById('upload-filename').value || 'exploit.html';
    const content = document.getElementById('upload-content').value || "test";
    const base64 = btoa(content);
    
    const query = `mutation {\n  uploadFile(filename: "${fn}", base64Content: "${base64}") {\n    id\n    filename\n    filePath\n  }\n}`;
    document.getElementById('graphql-query-input').value = query;
  });

  // Sync state with server configuration on startup
  syncServerState();
}

// Render Vulnerability Cards Grid
function renderVulnerabilityCards() {
  const container = document.getElementById('vulnerability-cards-container');
  container.innerHTML = '';
  
  vulnerabilityModules.forEach(mod => {
    const card = document.createElement('div');
    card.className = `vuln-card`;
    card.innerHTML = `
      <div class="vuln-card-header">
        <h4>${mod.title}</h4>
        <span class="badge ${mod.severity}">${mod.severity}</span>
      </div>
      <p>${mod.description.substring(0, 100)}...</p>
      <div class="vuln-card-footer">
        <span>Diff: <span class="badge ${mod.difficulty === 'medium' ? 'medium-diff' : mod.difficulty}">${mod.difficulty}</span></span>
        <span>Cat: ${mod.category}</span>
      </div>
    `;
    card.addEventListener('click', () => selectModule(mod.id));
    container.appendChild(card);
  });
}

// Render Sidebar List
function renderSidebarList() {
  const container = document.getElementById('vulnerabilities-list');
  container.innerHTML = '';
  
  vulnerabilityModules.forEach(mod => {
    const li = document.createElement('li');
    li.textContent = mod.title;
    li.setAttribute('data-id', mod.id);
    li.addEventListener('click', () => selectModule(mod.id));
    container.appendChild(li);
  });
}

// Show Dashboard View
function showDashboard() {
  activeView = 'dashboard';
  currentModuleId = null;
  document.querySelectorAll('.content-view').forEach(v => v.classList.remove('active'));
  document.getElementById('dashboard-view').classList.add('active');
  
  // Clear sidebar active highlights
  document.querySelectorAll('.sidebar-nav li').forEach(li => li.classList.remove('active'));
}

// Select Vulnerability Module
function selectModule(modId) {
  currentModuleId = modId;
  const mod = vulnerabilityModules.find(m => m.id === modId);
  if (!mod) return;
  
  activeView = 'module';
  document.querySelectorAll('.content-view').forEach(v => v.classList.remove('active'));
  document.getElementById('module-view').classList.add('active');
  
  // Highlight sidebar
  document.querySelectorAll('.sidebar-nav li').forEach(li => li.classList.remove('active'));
  const activeLi = document.querySelector(`#vulnerabilities-list li[data-id="${modId}"]`);
  if (activeLi) activeLi.classList.add('active');
  
  // Fill module data
  document.getElementById('module-title').textContent = mod.title;
  
  const sev = document.getElementById('module-severity');
  sev.textContent = mod.severity;
  sev.className = `badge ${mod.severity}`;
  
  const diff = document.getElementById('module-difficulty');
  diff.textContent = mod.difficulty;
  diff.className = `badge ${mod.difficulty === 'medium' ? 'medium-diff' : mod.difficulty}`;

  const cat = document.getElementById('module-category');
  cat.textContent = mod.category;
  
  document.getElementById('module-description').textContent = mod.description;
  document.getElementById('module-objective').textContent = mod.objective;
  document.getElementById('module-hints').innerHTML = mod.hints;
  
  // Prefill editor
  document.getElementById('graphql-query-input').value = mod.sampleQuery;
  
  // Code comparison panels
  document.getElementById('code-vulnerable').textContent = mod.vulnerableCode;
  document.getElementById('code-secure').textContent = mod.secureCode;
  
  // Mitigation panel
  document.getElementById('module-mitigation').innerHTML = mod.mitigation;
  document.getElementById('module-learning').innerHTML = mod.learning;

  // Show/Hide custom upload form helper inside playground if module is fileupload
  const uploadHelper = document.getElementById('playground-upload-helper');
  if (modId === 'fileupload') {
    uploadHelper.classList.remove('hidden');
  } else {
    uploadHelper.classList.add('hidden');
  }

  // Set default active tab to Overview
  switchTab('tab-overview');
  updateLearningModeUI();
}

// Switch Tabs inside Module View
function switchTab(tabId) {
  // Toggle buttons active state
  document.querySelectorAll('.tab-btn').forEach(btn => {
    if (btn.getAttribute('data-tab') === tabId) {
      btn.classList.add('active');
    } else {
      btn.classList.remove('active');
    }
  });

  // Toggle panels visibility
  document.querySelectorAll('.tab-panel').forEach(panel => {
    if (panel.id === tabId) {
      panel.classList.add('active');
    } else {
      panel.classList.remove('active');
    }
  });
}

// Load Reference Article
function loadReferenceArticle(key) {
  const art = referenceArticles[key];
  if (!art) return;

  activeView = 'reference';
  document.querySelectorAll('.content-view').forEach(v => v.classList.remove('active'));
  document.getElementById('reference-view').classList.add('active');

  // Highlight reference link in sidebar
  document.querySelectorAll('.sidebar-nav li').forEach(li => li.classList.remove('active'));
  const activeLi = document.querySelector(`#reference-list li[data-ref="${key}"]`);
  if (activeLi) activeLi.classList.add('active');

  // Fill content
  document.getElementById('ref-title').textContent = art.title;
  document.getElementById('ref-content').innerHTML = art.content;
}

// Update UI elements based on Learning Mode (Beginner vs Expert)
function updateLearningModeUI() {
  const hints = document.getElementById('module-hints-container');
  const codeTab = document.getElementById('tab-code-btn');
  
  if (learningMode === 'BEGINNER') {
    if (hints) hints.classList.remove('hidden');
    if (codeTab) codeTab.classList.remove('hidden');
  } else {
    // Expert Mode: Hide hints and source code comparisons
    if (hints) hints.classList.add('hidden');
    if (codeTab) codeTab.classList.add('hidden');
    // If code comparison tab is currently open, switch back to overview
    const activeTab = document.querySelector('.tab-btn.active');
    if (activeTab && activeTab.getAttribute('data-tab') === 'tab-code') {
      switchTab('tab-overview');
    }
  }
}

// Session Credentials Switcher helper
async function switchSession(userKey) {
  if (userKey === 'guest') {
    jwtToken = '';
    localStorage.removeItem('dvga_token');
    document.getElementById('jwt-token').value = '';
    console.log('[SESSION] Switched to Guest.');
    return;
  }

  // Pre-configured training user parameters
  let email = '';
  let password = 'User123!';
  if (userKey === 'user_a') email = 'user_a@lab.local';
  if (userKey === 'user_b') email = 'user_b@lab.local';
  if (userKey === 'admin') {
    email = 'admin@lab.local';
    password = 'Admin123!';
  }

  // Authenticate by executing the login mutation directly against the running server
  try {
    const res = await executeGraphQLMutation(`
      mutation {
        login(email: "${email}", password: "${password}") {
          token
        }
      }
    `);

    if (res && res.login && res.login.token) {
      jwtToken = res.login.token;
      localStorage.setItem('dvga_token', jwtToken);
      document.getElementById('jwt-token').value = jwtToken;
      console.log(`[SESSION] Successfully authenticated as ${email}. Token stored.`);
    }
  } catch (err) {
    console.error('[SESSION] Authentication switcher failed. Server down or SQLi triggered?', err);
    alert('Authentication mutation execution failed. Make sure Server is running and database initialized.');
  }
}

// Execute Playground Query
async function runPlaygroundQuery() {
  const query = document.getElementById('graphql-query-input').value;
  const token = document.getElementById('jwt-token').value;
  const outputElem = document.getElementById('graphql-response-output');
  const statusElem = document.getElementById('response-status');

  statusElem.textContent = 'Executing...';
  statusElem.className = 'response-badge';
  outputElem.textContent = 'Loading response...';

  try {
    const headers = {
      'Content-Type': 'application/json'
    };
    if (token) {
      headers['Authorization'] = `Bearer ${token.trim()}`;
    }

    const response = await fetch('/graphql', {
      method: 'POST',
      headers,
      body: JSON.stringify({ query })
    });

    const result = await response.json();
    
    // Formatting JSON response
    outputElem.textContent = JSON.stringify(result, null, 2);
    
    // Render XSS payloads if present
    const xssDiv = document.getElementById('xss-output');
    if (result.data && result.data.updateBio && result.data.updateBio.bio) {
      xssDiv.innerHTML = result.data.updateBio.bio;
    } else {
      xssDiv.innerHTML = '';
    }
    // Execute any <script> tags inserted via innerHTML (needed for XSS demonstration)
    xssDiv.querySelectorAll('script').forEach(oldScript => {
      const newScript = document.createElement('script');
      newScript.text = oldScript.textContent;
      document.body.appendChild(newScript);
      document.body.removeChild(newScript);
    });

    if (result.errors) {
      statusElem.textContent = 'Error';
      statusElem.classList.add('badge', 'high');
    } else {
      statusElem.textContent = 'Success';
      statusElem.classList.add('badge', 'low');
    }
  } catch (err) {
    outputElem.textContent = `GraphQL Execution Error: ${err.message}`;
    statusElem.textContent = 'Failed';
    statusElem.classList.add('badge', 'high');
  }
}

// Fetch helper executing mutations
async function executeGraphQLMutation(mutationString) {
  const response = await fetch('/graphql', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ query: mutationString })
  });
  const body = await response.json();
  if (body.errors) {
    throw new Error(body.errors[0].message);
  }
  return body.data;
}

// Sync local configuration state with server config values on page boot
async function syncServerState() {
  try {
    const response = await fetch('/graphql', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        query: `
          query {
            securityMode
            learningMode
          }
        `
      })
    });
    const result = await response.json();
    if (result.data) {
      securityMode = result.data.securityMode;
      learningMode = result.data.learningMode;

      // Update UI dropdown select elements
      document.getElementById('security-mode').value = securityMode;
      document.getElementById('security-mode').setAttribute('value', securityMode);
      document.getElementById('learning-mode').value = learningMode;
      
      updateLearningModeUI();
    }
  } catch (err) {
    console.warn('[BOOT] Server state sync failed. Server down?', err.message);
  }
}
