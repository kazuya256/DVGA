const express = require('express');
const http = require('http');
const path = require('path');
const cors = require('cors');
const { ApolloServer } = require('@apollo/server');
const { expressMiddleware } = require('@apollo/server/express4');
const { ApolloServerPluginDrainHttpServer } = require('@apollo/server/plugin/drainHttpServer');
const bodyParser = require('body-parser');
require('dotenv').config();

const config = require('./config');
const authMiddleware = require('./middleware/auth');
const initDatabase = require('./database/init');
const typeDefs = require('./graphql/typeDefs');
const resolvers = require('./graphql/resolvers');

const PORT = process.env.PORT || 5013;

async function startServer() {
  const app = express();
  const httpServer = http.createServer(app);

  // Set up Apollo Server
  const server = new ApolloServer({
    typeDefs,
    resolvers,
    plugins: [ApolloServerPluginDrainHttpServer({ httpServer })],
    // Support GraphQL Introspection Exposure challenge:
    // In secure mode, we would normally disable introspection if requested.
    // However, to keep it simple, we check securityMode. In MITIGATED mode, we disable introspection.
    introspection: true, // We will simulate introspection toggling inside the resolvers or schema metadata directly for educational clarity.
    formatError: (formattedError, error) => {
      const securityMode = config.getSecurityMode();
      if (securityMode === 'VULNERABLE') {
        // Leak stack traces, SQL syntax errors, and debug info
        return {
          message: error.message,
          locations: formattedError.locations,
          path: formattedError.path,
          extensions: {
            code: formattedError.extensions?.code,
            stacktrace: error.stack ? error.stack.split('\n') : null,
            originalError: error.originalError ? {
              message: error.originalError.message,
              detail: error.originalError.detail,
              hint: error.originalError.hint,
              query: error.originalError.query
            } : null
          }
        };
      } else {
        // Mitigated Mode: Sanitize errors
        let message = formattedError.message;
        const lowerMsg = message.toLowerCase();
        
        // Hide raw database details
        if (
          lowerMsg.includes('select') || 
          lowerMsg.includes('syntax error') || 
          lowerMsg.includes('relation') ||
          lowerMsg.includes('column') ||
          lowerMsg.includes('table')
        ) {
          message = 'Database operation failed. Please contact your administrator.';
        }
        
        return {
          message,
          extensions: {
            code: formattedError.extensions?.code || 'INTERNAL_SERVER_ERROR'
          }
        };
      }
    }
  });

  // Start Apollo Server
  await server.start();

  // Basic Middlewares
  app.use(cors());
  app.use(bodyParser.json({ limit: '10mb' }));
  app.use(authMiddleware);

  // Clean URL routes for structured views
  app.get('/playground', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'playground.html'));
  });

  app.get('/docs', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'docs.html'));
  });

  // Serve static UI assets
  app.use(express.static(path.join(__dirname, 'public')));

  // GraphQL endpoint integration
  app.use(
    '/graphql',
    expressMiddleware(server, {
      context: async ({ req }) => {
        // Return context for resolvers
        return {
          user: req.user,
          headers: req.headers
        };
      },
    })
  );

  // Healthcheck and diagnostics check
  app.get('/healthz', (req, res) => {
    res.json({
      status: 'healthy',
      securityMode: config.getSecurityMode(),
      learningMode: config.getLearningMode()
    });
  });

  // REST Upload helper for insecure upload showcase
  const multer = require('multer');
  const storage = multer.diskStorage({
    destination: (req, file, cb) => {
      cb(null, path.join(__dirname, 'public', 'uploads'));
    },
    filename: (req, file, cb) => {
      cb(null, Date.now() + '-' + file.originalname);
    }
  });
  const upload = multer({ storage });

  // Create uploads directory if it doesn't exist
  const fs = require('fs');
  const uploadDir = path.join(__dirname, 'public', 'uploads');
  if (!fs.existsSync(uploadDir)) {
    fs.mkdirSync(uploadDir, { recursive: true });
  }

  // REST File Upload Endpoint (Dual vulnerability coverage)
  app.post('/api/upload', upload.single('file'), (req, res) => {
    if (!req.file) {
      return res.status(400).json({ error: 'No file uploaded' });
    }

    const securityMode = config.getSecurityMode();
    const ext = path.extname(req.file.originalname).toLowerCase();

    if (securityMode === 'MITIGATED') {
      // In mitigated mode, strictly validate extension and MIME type
      const allowedExtensions = ['.jpg', '.jpeg', '.png', '.gif'];
      const allowedMimes = ['image/jpeg', 'image/png', 'image/gif'];
      
      if (!allowedExtensions.includes(ext) || !allowedMimes.includes(req.file.mimetype)) {
        // Delete uploaded file immediately
        fs.unlinkSync(req.file.path);
        return res.status(400).json({ error: 'Security Violation: Only image uploads are allowed!' });
      }
    }

    // Return response
    res.json({
      message: 'File uploaded successfully',
      filename: req.file.filename,
      filePath: `/uploads/${req.file.filename}`,
      size: req.file.size
    });
  });

  // Start HTTP Server
  httpServer.listen(PORT, async () => {
    console.log('\n=========================================================================');
    console.log(' DELIBERATELY VULNERABLE GRAPHQL APPLICATION - NODE EDITION');
    console.log('  WARNING: FOR EDUCATIONAL PURPOSES ONLY. DO NOT DEPLOY PUBLICLY.');
    console.log('=========================================================================');
    console.log(`Server listening on port ${PORT}`);
    console.log(`GraphQL endpoint available at http://localhost:${PORT}/graphql`);
    console.log(`Web UI panel available at http://localhost:${PORT}/`);
    console.log('=========================================================================\n');

    // Attempt automatic DB initialization
    try {
      await initDatabase();
    } catch (err) {
      console.warn('[DB] Automatic migration check failed. Ensure PostgreSQL server is running.', err.message);
    }
  });
}

startServer();
