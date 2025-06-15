/**
 * Sample Express.js application to test vulnerability scanning
 */

const express = require('express');
const bodyParser = require('body-parser');
const cookieParser = require('cookie-parser');
const session = require('express-session');
const path = require('path');
const fs = require('fs');
const helmet = require('helmet');

// This version is vulnerable to multiple CVEs
const EXPRESS_VERSION = '4.16.1';

// Create Express application
const app = express();
const port = process.env.PORT || 3000;

// Middleware
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));
app.use(cookieParser());
app.use(express.static('public'));

// Session configuration (potentially insecure)
app.use(session({
  secret: 'my-secret-key',
  resave: false,
  saveUninitialized: true,
  cookie: { secure: false } // Missing security options
}));

// Routes with potential security vulnerabilities
app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// API endpoint with potential SQL injection
app.get('/api/users', (req, res) => {
  const userId = req.query.id;
  // Vulnerable to SQL injection
  const query = `SELECT * FROM users WHERE id = ${userId}`;
  
  // Mock database response
  const users = [
    { id: 1, username: 'admin', email: 'admin@example.com' },
    { id: 2, username: 'user', email: 'user@example.com' }
  ];
  
  res.json(users.filter(user => user.id === parseInt(userId)));
});

// API endpoint with potential XSS vulnerability
app.post('/api/messages', (req, res) => {
  const { message } = req.body;
  
  // Store message without sanitization
  const messages = [];
  messages.push(message);
  
  // Return success response
  res.json({ success: true, message: 'Message saved successfully' });
});

// API endpoint with potential command injection
app.get('/api/files', (req, res) => {
  const directory = req.query.dir || '.';
  
  // Vulnerable to command injection
  const command = `ls -la ${directory}`;
  
  // Using exec without proper sanitization
  require('child_process').exec(command, (error, stdout, stderr) => {
    if (error) {
      return res.status(500).json({ error: stderr });
    }
    res.json({ files: stdout });
  });
});

// API endpoint with potential path traversal
app.get('/api/file', (req, res) => {
  const filename = req.query.name;
  
  // Vulnerable to path traversal
  const filePath = path.join(__dirname, 'files', filename);
  
  fs.readFile(filePath, 'utf8', (err, data) => {
    if (err) {
      return res.status(404).json({ error: 'File not found' });
    }
    res.send(data);
  });
});

// User authentication with weak password policies
app.post('/api/login', (req, res) => {
  const { username, password } = req.body;
  
  // Mock user authentication
  if (username === 'admin' && password === 'password') {
    req.session.user = { username, role: 'admin' };
    return res.json({ success: true, message: 'Login successful' });
  }
  
  res.status(401).json({ success: false, message: 'Invalid credentials' });
});

// Missing CSRF protection
app.post('/api/update-profile', (req, res) => {
  // No CSRF token validation
  const { name, email } = req.body;
  
  // Update user profile
  res.json({ success: true, message: 'Profile updated successfully' });
});

// Missing rate limiting
app.post('/api/reset-password', (req, res) => {
  const { email } = req.body;
  
  // Send password reset email
  res.json({ success: true, message: 'Password reset email sent' });
});

// Start server
app.listen(port, () => {
  console.log(`Express server running on port ${port}`);
});

// Export app for testing
module.exports = app; 