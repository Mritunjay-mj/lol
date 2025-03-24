const express = require('express');
const mysql = require('mysql2');
const mongoose = require('mongoose');
const bcrypt = require('bcrypt');
const fs = require('fs');
const path = require('path');
const https = require('https');
const helmet = require('helmet');
// Extra security and validation modules added (as in app_clause_3.js)
const xssClean = require('xss-clean');
const rateLimit = require('express-rate-limit');
const { body, validationResult } = require('express-validator');

require('dotenv').config();
const logger = require('./utils/logger');  // Import the logger

// Express App
const app = express();
const port = 3000;

// Load SSL certificates for MySQL and HTTPS server
const caCertPath = '/etc/mysql/newcerts/ca-cert.pem';
const clientCertPath = '/etc/mysql/newcerts/client-cert.pem';
const clientKeyPath = '/etc/mysql/newcerts/client-key.pem';
const serverCertPath = 'cert.pem';
const serverKeyPath = 'private-key.pem';

// Function to read certificates (unchanged)
function readCertFile(filePath) {
  try {
    return fs.readFileSync(filePath);
  } catch (error) {
    logger.error(`Error reading certificate: ${filePath}`);
    process.exit(1);
  }
}

// Load SSL certificates
const caCert = readCertFile(caCertPath);
const clientCert = readCertFile(clientCertPath);
const clientKey = readCertFile(clientKeyPath);
const serverCert = readCertFile(serverCertPath);
const serverKey = readCertFile(serverKeyPath);

// MySQL Connection (unchanged)
const mysqlConnection = mysql.createConnection({
  host: process.env.DB_HOST,
  user: process.env.DB_USER,
  password: process.env.DB_PASSWORD,
  database: process.env.DB_NAME,
  port: process.env.DB_PORT,
  ssl: { ca: caCert, cert: clientCert, key: clientKey }
});

mysqlConnection.connect((err) => {
  if (err) {
    logger.error('MySQL Connection Failed:', err.stack);
    process.exit(1);
  }
  logger.info('Connected to MySQL with SSL.');
});

// MongoDB Connection (unchanged)
mongoose.connect(process.env.MONGO_URI, { useNewUrlParser: true, useUnifiedTopology: true })
  .then(() => logger.info("MongoDB Connected"))
  .catch(err => {
    logger.error("MongoDB Connection Error:", err);
    process.exit(1);
  });

// MongoDB User Schema (unchanged)
const User = mongoose.model("User", new mongoose.Schema({
  username: { type: String, required: true, unique: true },
  password: { type: String, required: true }
}));

// Middleware: Parsing and serving static files (unchanged)
app.use(express.urlencoded({ extended: true }));
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

// Use Helmet to set secure HTTP headers (unchanged)
app.use(helmet.hsts({ maxAge: 31536000, includeSubDomains: true, preload: true }));

// ▶️ Added Features from app_clause_3.js:

// 1. XSS Protection Middleware
app.use(xssClean());

// 2. Rate Limiting Middleware to prevent brute-force/DoS attacks
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100, // Limit each IP to 100 requests per window
  message: "Too many requests from this IP, please try again later."
});
app.use(limiter);

// 3. Enhanced Logging Middleware that captures response status codes
app.use((req, res, next) => {
  const ip = req.ip || req.connection.remoteAddress;
  const originalEnd = res.end;
  res.end = function (...args) {
    logger.info(`HTTP Request: ${req.method} ${req.originalUrl} from ${ip} | Status: ${res.statusCode}`);
    originalEnd.apply(this, args);
  };
  next();
});

// Redirect root to /login (unchanged)
app.get('/', (req, res) => res.redirect('/login'));

// Serve login and signup pages (unchanged)
app.get('/login', (req, res) => res.sendFile(path.join(__dirname, 'views', 'login.html')));
app.get('/signup', (req, res) => res.sendFile(path.join(__dirname, 'views', 'signup.html')));

// 4. Input Validation Middleware for Signup & Login using express-validator
const validateUserInput = [
  body('username')
    .trim().escape().isLength({ min: 3 }).withMessage('Username must be at least 3 characters.')
    .matches(/^[a-zA-Z0-9_]+$/).withMessage('Username can only contain letters, numbers, and underscores.'),
  body('password')
    .trim().isLength({ min: 8 }).withMessage('Password must be at least 8 characters.')
    .matches(/[A-Z]/).withMessage('Password must contain at least one uppercase letter.')
    .matches(/[a-z]/).withMessage('Password must contain at least one lowercase letter.')
    .matches(/\d/).withMessage('Password must contain at least one number.')
    .matches(/[@#]/).withMessage('Password must contain at least one special character (@ or #).')
];

// (Optional) Preserve the original custom password validation function
function isValidPassword(password) {
  return /(?=.*[A-Z].*[A-Z])(?=.*[a-z].*[a-z].*[a-z].*[a-z].*[a-z])(?=.*\d.*\d.*\d)(?=.*[@#])/.test(password);
}

// Handle signup with input validation and logging (modified to include extra features)
app.post('/signup', validateUserInput, async (req, res) => {
  // Check for validation errors from express-validator
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    logger.warn(`Signup validation failed: ${JSON.stringify(errors.array())}`);
    return res.status(400).json({ errors: errors.array() });
  }

  const { username, password } = req.body;

  // Optionally retain original password check if desired
  if (!isValidPassword(password)) {
    return res.status(400).send('Password requirements not met.');
  }

  try {
    const hashedPassword = await bcrypt.hash(password, 10);

    // Insert into MySQL
    mysqlConnection.query('INSERT INTO users (username, password_hash) VALUES (?, ?)', [username, hashedPassword], async (err) => {
      if (err) {
        return res.status(500).send('Error creating user in MySQL.');
      }
      // Insert into MongoDB
      const newUser = new User({ username, password: hashedPassword });
      await newUser.save();

      logger.info(`User signed up: ${username}`);
      res.send('Signup successful!');
    });
  } catch (error) {
    logger.error("Signup Error:", error);
    res.status(500).send('Internal server error.');
  }
});

// Handle login with input validation and enhanced logging
app.post('/login', validateUserInput, async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({ errors: errors.array() });
  }

  const { username, password } = req.body;
  const ip = req.ip || req.connection.remoteAddress;

  try {
    mysqlConnection.query('SELECT * FROM users WHERE username = ?', [username], async (err, results) => {
      if (err || results.length === 0) {
        logger.warn(`Failed login attempt: ${username} from ${ip}`);
        return res.status(401).json({ message: "Invalid username or password." });
      }

      const user = results[0];
      const isPasswordValid = await bcrypt.compare(password, user.password_hash);

      if (!isPasswordValid) {
        logger.warn(`Failed login attempt: ${username} from ${ip}`);
        return res.status(401).json({ message: "Invalid username or password." });
      }

      logger.info(`Successful login: ${username} from ${ip}`);
      res.json({ message: "Login successful!", username });
    });
  } catch (error) {
    logger.error("Login Error:", error);
    res.status(500).send("Internal server error.");
  }
});

// Start HTTPS Server (unchanged)
https.createServer({ key: serverKey, cert: serverCert }, app).listen(port, '0.0.0.0', () => {
  logger.info(`Server running at https://10.118.5.145:${port}`);
});
