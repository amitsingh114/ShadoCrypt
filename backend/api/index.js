const express = require('express');
const app = express();

// Middleware
app.use(express.json());

// Routes
app.get('/', (req, res) => {
  res.send('ShadoCrypt Backend is live!');
});

// Export the app (DO NOT use app.listen)
module.exports = app;
