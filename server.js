const express = require('express');
const fs = require('fs');
const path = require('path');
const cors = require('cors');
const app = express();
const PORT = process.env.PORT || 4000;
const BASE_PATH = '/mock';

app.use(cors());
app.use(express.json());

const configPath = path.join(__dirname, 'IHFA_Mock_API_Secure.json');
const { endpoints } = JSON.parse(fs.readFileSync(configPath, 'utf-8'));

app.use((req, res, next) => {
  const delay = parseInt(process.env.MOCK_DELAY_MS || '0', 10);
  if (delay > 0) setTimeout(next, delay); else next();
});

function buildHandler(def) {
  return (req, res) => {
    if (def.headers && def.headers.Authorization) {
      const auth = req.headers['authorization'];
      if (!auth || !auth.startsWith('Bearer ')) {
        return res.status(401).json({ status: 'error', message: 'Missing or invalid Authorization header' });
      }
    }
    if (def.response) return res.json(def.response);
    return res.json({ status: 'success', message: 'Mock endpoint reached', echo: { method: req.method, path: req.path, body: req.body, query: req.query } });
  };
}

Object.entries(endpoints).forEach(([route, def]) => {
  const method = (def.method || 'GET').toLowerCase();
  const fullPath = `${BASE_PATH}${route}`;
  if (['get','post','put','patch','delete'].includes(method)) {
    app[method](fullPath, buildHandler(def));
    console.log(`Registered ${method.toUpperCase()} ${fullPath}`);
  } else {
    console.warn(`Unsupported method for ${route}: ${def.method}`);
  }
});

app.get('/', (req, res) => {
  res.json({ message: 'IHFA Mock API Server', baseUrl: `http://localhost:${PORT}${BASE_PATH}` });
});

app.listen(PORT, () => console.log(`Mock server running on http://localhost:${PORT}${BASE_PATH}`));
