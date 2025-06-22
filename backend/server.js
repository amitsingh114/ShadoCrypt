// <<<<<<< HEAD

// =======
// WormGPT Express Backend with Python Integration
// Make sure you have installed Node.js, Python3, and required modules:
// - Node:     npm install express
// - Python:   pip install cryptography pycryptodome bcrypt scrypt base58 base32
// >>>>>>> 7b0f2e1 (Updated backend and fixed Python crypto processor)

const express = require('express');
const { spawn } = require('child_process');
const app = express();
const port = 3000;

// Parse JSON request bodies
app.use(express.json());

// Enable CORS (for development)
app.use((req, res, next) => {
  res.header('Access-Control-Allow-Origin', '*'); // Insecure: allow all origins
  res.header('Access-Control-Allow-Headers', 'Origin, X-Requested-With, Content-Type, Accept');
  next();
});

/**
 * Run the Python crypto script with JSON input and output.
 */
function runPythonScript(payload) {
  return new Promise((resolve, reject) => {
    const python = spawn('python3', ['crypto_processor.py']);
    let dataString = '';
    let errorString = '';

    python.stdin.write(JSON.stringify(payload));
    python.stdin.end();

    python.stdout.on('data', (data) => {
      dataString += data.toString();
    });

    python.stderr.on('data', (data) => {
      errorString += data.toString();
    });

    python.on('close', (code) => {
      if (code !== 0) {
        console.error(`Python error (code ${code}): ${errorString}`);
        return reject(new Error(`Python script failed: ${errorString || 'Unknown error'}`));
      }
      try {
        const result = JSON.parse(dataString);
        resolve(result);
      } catch (err) {
        console.error('Failed to parse Python output:', dataString);
        reject(new Error(`Invalid Python output: ${dataString || errorString}`));
      }
    });

    python.on('error', (err) => {
      console.error('Failed to start Python process:', err.message);
      reject(new Error(`Python not found or failed to start: ${err.message}`));
    });
  });
}

// --- API ROUTES ---

// Encrypt
app.post('/api/symmetric/encrypt', async (req, res) => {
  try {
    const { text, key, algorithm } = req.body;
    if (!text || !key || !algorithm) {
      return res.status(400).json({ error: 'Missing text, key, or algorithm' });
    }
    const result = await runPythonScript({ operation: 'encrypt', text, key, algorithm });
    res.json(result);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Decrypt
app.post('/api/symmetric/decrypt', async (req, res) => {
  try {
    const { text, key, algorithm } = req.body;
    if (!text || !key || !algorithm) {
      return res.status(400).json({ error: 'Missing text, key, or algorithm' });
    }
    const result = await runPythonScript({ operation: 'decrypt', text, key, algorithm });
    res.json(result);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Hash
app.post('/api/hash', async (req, res) => {
  try {
    const { text, algorithm } = req.body;
    if (!text || !algorithm) {
      return res.status(400).json({ error: 'Missing text or algorithm' });
    }
    const result = await runPythonScript({ operation: 'hash', text, algorithm });
    res.json(result);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Encode
app.post('/api/encode', async (req, res) => {
  try {
    const { text, method } = req.body;
    if (!text || !method) {
      return res.status(400).json({ error: 'Missing text or method' });
    }
    const result = await runPythonScript({ operation: 'encode', text, method });
    res.json(result);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Decode
app.post('/api/decode', async (req, res) => {
  try {
    const { text, method } = req.body;
    if (!text || !method) {
      return res.status(400).json({ error: 'Missing text or method' });
    }
    const result = await runPythonScript({ operation: 'decode', text, method });
    res.json(result);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// --- LOCAL SERVER MODE ---
if (require.main === module) {
  app.listen(port, () => {
    console.log(`✅ Express server running at http://localhost:${port}`);
  });
}

// --- VERCEL EXPORT ---
module.exports = app;
