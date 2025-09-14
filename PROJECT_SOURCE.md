# Store Rating Application - Complete Source Code

## Project Structure
```
store-rating-app/
├── backend/
│   ├── src/
│   │   ├── config/
│   │   │   ├── db.js
│   │   │   ├── schema.sql
│   │   ├── controllers/
│   │   │   ├── auth.js
│   │   │   ├── rating.js
│   │   │   ├── store.js
│   │   │   ├── user.js
│   │   ├── middleware/
│   │   │   ├── auth.js
│   │   ├── models/
│   │   │   ├── rating.js
│   │   │   ├── store.js
│   │   │   ├── user.js
│   │   ├── routes/
│   │   │   ├── auth.js
│   │   │   ├── rating.js
│   │   │   ├── store.js
│   │   │   ├── user.js
│   │   └── index.js
│   ├── .env
│   └── package.json
└── frontend/
    ├── src/
    │   ├── components/
    │   │   ├── Layout.jsx
    │   │   └── PrivateRoute.jsx
    │   ├── context/
    │   │   └── AuthContext.jsx
    │   ├── hooks/
    │   │   └── useAuth.js
    │   ├── pages/
    │   │   ├── Dashboard.jsx
    │   │   ├── Home.jsx
    │   │   ├── Login.jsx
    │   │   └── Register.jsx
    │   ├── services/
    │   │   └── api.js
    │   ├── App.jsx
    │   ├── index.css
    │   └── main.jsx
    ├── index.html
    └── package.json
```

## Backend Source Files

### 1. src/config/db.js
```javascript
const { Pool } = require('pg');
require('dotenv').config();

const pool = new Pool({
  host: process.env.DB_HOST,
  user: process.env.DB_USER,
  password: process.env.DB_PASSWORD,
  database: process.env.DB_NAME,
  port: 5432,
});

module.exports = pool;
```

### 2. src/config/schema.sql
```sql
-- Create database if it doesn't exist
CREATE DATABASE store_rating_db;

-- Connect to the database
\c store_rating_db;

-- Create enum type for user roles
CREATE TYPE user_role AS ENUM ('system_admin', 'normal_user', 'store_owner');

-- Create users table
CREATE TABLE users (
    id SERIAL PRIMARY KEY,
    name VARCHAR(60) NOT NULL CHECK (LENGTH(name) >= 20),
    email VARCHAR(255) UNIQUE NOT NULL,
    password VARCHAR(255) NOT NULL,
    address VARCHAR(400) NOT NULL,
    role user_role NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Create stores table
CREATE TABLE stores (
    id SERIAL PRIMARY KEY,
    name VARCHAR(255) NOT NULL,
    email VARCHAR(255) UNIQUE NOT NULL,
    address VARCHAR(400) NOT NULL,
    owner_id INTEGER REFERENCES users(id),
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Create ratings table
CREATE TABLE ratings (
    id SERIAL PRIMARY KEY,
    user_id INTEGER REFERENCES users(id),
    store_id INTEGER REFERENCES stores(id),
    rating INTEGER CHECK (rating >= 1 AND rating <= 5),
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(user_id, store_id)
);

-- Create function to update timestamp
CREATE OR REPLACE FUNCTION update_updated_at_column()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = CURRENT_TIMESTAMP;
    RETURN NEW;
END;
$$ language 'plpgsql';

-- Create triggers for updating timestamps
CREATE TRIGGER update_users_updated_at
    BEFORE UPDATE ON users
    FOR EACH ROW
    EXECUTE FUNCTION update_updated_at_column();

CREATE TRIGGER update_stores_updated_at
    BEFORE UPDATE ON stores
    FOR EACH ROW
    EXECUTE FUNCTION update_updated_at_column();

CREATE TRIGGER update_ratings_updated_at
    BEFORE UPDATE ON ratings
    FOR EACH ROW
    EXECUTE FUNCTION update_updated_at_column();

-- Create view for store ratings
CREATE OR REPLACE VIEW store_ratings AS
SELECT 
    s.id as store_id,
    s.name as store_name,
    s.address,
    ROUND(AVG(r.rating)::numeric, 2) as average_rating,
    COUNT(r.id) as total_ratings
FROM stores s
LEFT JOIN ratings r ON s.id = r.store_id
GROUP BY s.id, s.name, s.address;
```

### 3. src/middleware/auth.js
```javascript
const jwt = require('jsonwebtoken');

const authenticateToken = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];

  if (!token) {
    return res.status(401).json({ message: 'Access denied. No token provided.' });
  }

  try {
    const verified = jwt.verify(token, process.env.JWT_SECRET);
    req.user = verified;
    next();
  } catch (error) {
    res.status(400).json({ message: 'Invalid token.' });
  }
};

const authorizeRole = (roles) => {
  return (req, res, next) => {
    if (!roles.includes(req.user.role)) {
      return res.status(403).json({ message: 'Access denied. Insufficient privileges.' });
    }
    next();
  };
};

module.exports = {
  authenticateToken,
  authorizeRole
};
```

### 4. src/models/user.js
```javascript
const pool = require('../config/db');
const bcrypt = require('bcrypt');

class User {
  static async create({ name, email, password, address, role }) {
    const hashedPassword = await bcrypt.hash(password, 10);
    const query = `
      INSERT INTO users (name, email, password, address, role)
      VALUES ($1, $2, $3, $4, $5)
      RETURNING id, name, email, address, role
    `;
    const values = [name, email, hashedPassword, address, role];
    const { rows } = await pool.query(query, values);
    return rows[0];
  }

  static async findByEmail(email) {
    const query = 'SELECT * FROM users WHERE email = $1';
    const { rows } = await pool.query(query, [email]);
    return rows[0];
  }

  static async findById(id) {
    const query = 'SELECT id, name, email, address, role FROM users WHERE id = $1';
    const { rows } = await pool.query(query, [id]);
    return rows[0];
  }

  static async updatePassword(id, newPassword) {
    const hashedPassword = await bcrypt.hash(newPassword, 10);
    const query = 'UPDATE users SET password = $1 WHERE id = $2 RETURNING id';
    const { rows } = await pool.query(query, [hashedPassword, id]);
    return rows[0];
  }

  static async getAll(filters = {}) {
    let query = 'SELECT id, name, email, address, role FROM users';
    const values = [];
    const conditions = [];

    if (filters.name) {
      values.push(`%${filters.name}%`);
      conditions.push(`name ILIKE $${values.length}`);
    }
    if (filters.email) {
      values.push(`%${filters.email}%`);
      conditions.push(`email ILIKE $${values.length}`);
    }
    if (filters.role) {
      values.push(filters.role);
      conditions.push(`role = $${values.length}`);
    }

    if (conditions.length > 0) {
      query += ' WHERE ' + conditions.join(' AND ');
    }

    const { rows } = await pool.query(query, values);
    return rows;
  }
}

module.exports = User;
```

### 5. src/models/store.js
```javascript
const pool = require('../config/db');

class Store {
  static async create({ name, email, address, ownerId }) {
    const query = `
      INSERT INTO stores (name, email, address, owner_id)
      VALUES ($1, $2, $3, $4)
      RETURNING *
    `;
    const values = [name, email, address, ownerId];
    const { rows } = await pool.query(query, values);
    return rows[0];
  }

  static async findById(id) {
    const query = `
      SELECT s.*, 
             ROUND(AVG(r.rating)::numeric, 2) as average_rating,
             COUNT(r.id) as total_ratings
      FROM stores s
      LEFT JOIN ratings r ON s.id = r.store_id
      WHERE s.id = $1
      GROUP BY s.id
    `;
    const { rows } = await pool.query(query, [id]);
    return rows[0];
  }

  static async getAll(filters = {}) {
    let query = `
      SELECT s.*, 
             ROUND(AVG(r.rating)::numeric, 2) as average_rating,
             COUNT(r.id) as total_ratings
      FROM stores s
      LEFT JOIN ratings r ON s.id = r.store_id
    `;
    const values = [];
    const conditions = [];

    if (filters.name) {
      values.push(`%${filters.name}%`);
      conditions.push(`s.name ILIKE $${values.length}`);
    }
    if (filters.address) {
      values.push(`%${filters.address}%`);
      conditions.push(`s.address ILIKE $${values.length}`);
    }

    if (conditions.length > 0) {
      query += ' WHERE ' + conditions.join(' AND ');
    }

    query += ' GROUP BY s.id';

    if (filters.sortBy) {
      const sortDirection = filters.sortDesc ? 'DESC' : 'ASC';
      query += ` ORDER BY ${filters.sortBy} ${sortDirection}`;
    }

    const { rows } = await pool.query(query, values);
    return rows;
  }

  static async getByOwnerId(ownerId) {
    const query = `
      SELECT s.*, 
             ROUND(AVG(r.rating)::numeric, 2) as average_rating,
             COUNT(r.id) as total_ratings
      FROM stores s
      LEFT JOIN ratings r ON s.id = r.store_id
      WHERE s.owner_id = $1
      GROUP BY s.id
    `;
    const { rows } = await pool.query(query, [ownerId]);
    return rows;
  }
}

module.exports = Store;
```

### 6. src/models/rating.js
```javascript
const pool = require('../config/db');

class Rating {
  static async create({ userId, storeId, rating }) {
    const query = `
      INSERT INTO ratings (user_id, store_id, rating)
      VALUES ($1, $2, $3)
      RETURNING *
    `;
    const values = [userId, storeId, rating];
    const { rows } = await pool.query(query, values);
    return rows[0];
  }

  static async update({ userId, storeId, rating }) {
    const query = `
      UPDATE ratings
      SET rating = $3
      WHERE user_id = $1 AND store_id = $2
      RETURNING *
    `;
    const values = [userId, storeId, rating];
    const { rows } = await pool.query(query, values);
    return rows[0];
  }

  static async getUserRating(userId, storeId) {
    const query = 'SELECT * FROM ratings WHERE user_id = $1 AND store_id = $2';
    const { rows } = await pool.query(query, [userId, storeId]);
    return rows[0];
  }

  static async getStoreRatings(storeId) {
    const query = `
      SELECT r.*, u.name as user_name
      FROM ratings r
      JOIN users u ON r.user_id = u.id
      WHERE r.store_id = $1
    `;
    const { rows } = await pool.query(query, [storeId]);
    return rows;
  }

  static async getAverageRating(storeId) {
    const query = `
      SELECT 
        ROUND(AVG(rating)::numeric, 2) as average_rating,
        COUNT(*) as total_ratings
      FROM ratings
      WHERE store_id = $1
    `;
    const { rows } = await pool.query(query, [storeId]);
    return rows[0];
  }
}

module.exports = Rating;
```

### 7. src/routes/auth.js
```javascript
const express = require('express');
const AuthController = require('../controllers/auth');
const { authenticateToken } = require('../middleware/auth');

const router = express.Router();

// Public routes
router.post('/register', AuthController.register);
router.post('/login', AuthController.login);

// Protected routes
router.put('/password', authenticateToken, AuthController.updatePassword);

module.exports = router;
```

### 8. src/routes/user.js
```javascript
const express = require('express');
const UserController = require('../controllers/user');
const { authenticateToken, authorizeRole } = require('../middleware/auth');

const router = express.Router();

// All routes require authentication
router.use(authenticateToken);

// Admin only routes
router.post('/', authorizeRole(['system_admin']), UserController.createUser);
router.get('/', authorizeRole(['system_admin']), UserController.getAllUsers);
router.get('/:id', authorizeRole(['system_admin']), UserController.getUserById);

module.exports = router;
```

### 9. src/routes/store.js
```javascript
const express = require('express');
const StoreController = require('../controllers/store');
const { authenticateToken, authorizeRole } = require('../middleware/auth');

const router = express.Router();

// Public routes
router.get('/', StoreController.getAllStores);
router.get('/:id', StoreController.getStoreById);

// Protected routes
router.use(authenticateToken);

// Admin only routes
router.post('/', authorizeRole(['system_admin']), StoreController.createStore);

// Store owner routes
router.get('/owner/dashboard', authorizeRole(['store_owner']), StoreController.getStoresByOwner);
router.get('/:id/dashboard', authorizeRole(['store_owner']), StoreController.getStoreDashboard);

module.exports = router;
```

### 10. src/routes/rating.js
```javascript
const express = require('express');
const RatingController = require('../controllers/rating');
const { authenticateToken, authorizeRole } = require('../middleware/auth');

const router = express.Router();

// All routes require authentication
router.use(authenticateToken);

// Normal user routes
router.post('/', authorizeRole(['normal_user']), RatingController.submitRating);
router.get('/store/:storeId/user', RatingController.getUserRating);

// Public routes (but still need authentication)
router.get('/store/:storeId', RatingController.getStoreRatings);

module.exports = router;
```

### 11. src/index.js
```javascript
const express = require('express');
const cors = require('cors');
require('dotenv').config();

const authRoutes = require('./routes/auth');
const userRoutes = require('./routes/user');
const storeRoutes = require('./routes/store');
const ratingRoutes = require('./routes/rating');

const app = express();

// Middleware
app.use(cors());
app.use(express.json());

// Routes
app.use('/api/auth', authRoutes);
app.use('/api/users', userRoutes);
app.use('/api/stores', storeRoutes);
app.use('/api/ratings', ratingRoutes);

// Basic error handling
app.use((err, req, res, next) => {
  console.error(err.stack);
  res.status(500).json({ message: 'Something went wrong!' });
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Server is running on port ${PORT}`);
});
```

## Frontend Source Files

### 1. src/context/AuthContext.jsx
```jsx
import { createContext, useState, useEffect } from 'react';
import { authService } from '../services/api';

const AuthContext = createContext(null);

export const AuthProvider = ({ children }) => {
  const [user, setUser] = useState(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    const storedUser = localStorage.getItem('user');
    if (storedUser) {
      setUser(JSON.parse(storedUser));
    }
    setLoading(false);
  }, []);

  const login = async (credentials) => {
    const response = await authService.login(credentials);
    const { user, token } = response.data;
    localStorage.setItem('token', token);
    localStorage.setItem('user', JSON.stringify(user));
    setUser(user);
  };

  const register = async (userData) => {
    const response = await authService.register(userData);
    const { user, token } = response.data;
    localStorage.setItem('token', token);
    localStorage.setItem('user', JSON.stringify(user));
    setUser(user);
  };

  const logout = () => {
    localStorage.removeItem('token');
    localStorage.removeItem('user');
    setUser(null);
  };

  const updatePassword = async (passwords) => {
    await authService.updatePassword(passwords);
  };

  return (
    <AuthContext.Provider 
      value={{ 
        user, 
        loading,
        login,
        register,
        logout,
        updatePassword
      }}
    >
      {children}
    </AuthContext.Provider>
  );
};

export default AuthContext;
```

### 2. src/hooks/useAuth.js
```javascript
import { useContext } from 'react';
import AuthContext from '../context/AuthContext';

export const useAuth = () => {
  const context = useContext(AuthContext);
  if (!context) {
    throw new Error('useAuth must be used within an AuthProvider');
  }
  return context;
};
```

### 3. src/services/api.js
```javascript
import axios from 'axios';

const API_URL = 'http://localhost:3000/api';

const api = axios.create({
  baseURL: API_URL,
  headers: {
    'Content-Type': 'application/json',
  },
});

// Add token to requests if it exists
api.interceptors.request.use((config) => {
  const token = localStorage.getItem('token');
  if (token) {
    config.headers.Authorization = `Bearer ${token}`;
  }
  return config;
});

// Auth services
export const authService = {
  login: (credentials) => api.post('/auth/login', credentials),
  register: (userData) => api.post('/auth/register', userData),
  updatePassword: (passwords) => api.put('/auth/password', passwords),
};

// User services
export const userService = {
  createUser: (userData) => api.post('/users', userData),
  getAllUsers: (filters) => api.get('/users', { params: filters }),
  getUserById: (id) => api.get(`/users/${id}`),
};

// Store services
export const storeService = {
  createStore: (storeData) => api.post('/stores', storeData),
  getAllStores: (filters) => api.get('/stores', { params: filters }),
  getStoreById: (id) => api.get(`/stores/${id}`),
  getStoresByOwner: () => api.get('/stores/owner/dashboard'),
  getStoreDashboard: (id) => api.get(`/stores/${id}/dashboard`),
};

// Rating services
export const ratingService = {
  submitRating: (ratingData) => api.post('/ratings', ratingData),
  getStoreRatings: (storeId) => api.get(`/ratings/store/${storeId}`),
  getUserRating: (storeId) => api.get(`/ratings/store/${storeId}/user`),
};

export default api;
```

### 4. src/components/Layout.jsx
```jsx
import { AppBar, Toolbar, Typography, Button, Container, Box } from '@mui/material';
import { Link as RouterLink, useNavigate } from 'react-router-dom';
import { useAuth } from '../hooks/useAuth';

const Layout = ({ children }) => {
  const { user, logout } = useAuth();
  const navigate = useNavigate();

  const handleLogout = () => {
    logout();
    navigate('/login');
  };

  return (
    <Box sx={{ display: 'flex', flexDirection: 'column', minHeight: '100vh' }}>
      <AppBar position="static">
        <Toolbar>
          <Typography
            variant="h6"
            component={RouterLink}
            to="/"
            sx={{ flexGrow: 1, textDecoration: 'none', color: 'inherit' }}
          >
            Store Rating App
          </Typography>
          
          {user ? (
            <>
              <Button 
                color="inherit" 
                component={RouterLink} 
                to="/dashboard"
              >
                Dashboard
              </Button>
              <Button 
                color="inherit"
                onClick={handleLogout}
              >
                Logout
              </Button>
            </>
          ) : (
            <>
              <Button 
                color="inherit" 
                component={RouterLink} 
                to="/login"
              >
                Login
              </Button>
              <Button 
                color="inherit" 
                component={RouterLink} 
                to="/register"
              >
                Register
              </Button>
            </>
          )}
        </Toolbar>
      </AppBar>

      <Container 
        component="main" 
        sx={{ 
          flexGrow: 1, 
          py: 4,
          display: 'flex',
          flexDirection: 'column'
        }}
      >
        {children}
      </Container>

      <Box
        component="footer"
        sx={{
          py: 3,
          px: 2,
          mt: 'auto',
          backgroundColor: (theme) =>
            theme.palette.mode === 'light'
              ? theme.palette.grey[200]
              : theme.palette.grey[800],
        }}
      >
        <Container maxWidth="sm">
          <Typography variant="body2" color="text.secondary" align="center">
            © {new Date().getFullYear()} Store Rating App. All rights reserved.
          </Typography>
        </Container>
      </Box>
    </Box>
  );
};

export default Layout;
```

### 5. src/components/PrivateRoute.jsx
```jsx
import { Navigate } from 'react-router-dom';
import { useAuth } from '../hooks/useAuth';

const PrivateRoute = ({ children, roles = [] }) => {
  const { user, loading } = useAuth();

  if (loading) {
    return <div>Loading...</div>;
  }

  if (!user) {
    return <Navigate to="/login" />;
  }

  if (roles.length > 0 && !roles.includes(user.role)) {
    return <Navigate to="/unauthorized" />;
  }

  return children;
};

export default PrivateRoute;
```

### 6. src/App.jsx
```jsx
import { BrowserRouter as Router, Routes, Route } from 'react-router-dom';
import { ThemeProvider, createTheme } from '@mui/material';
import { ToastContainer } from 'react-toastify';
import 'react-toastify/dist/ReactToastify.css';
import { AuthProvider } from './context/AuthContext';
import Layout from './components/Layout';
import PrivateRoute from './components/PrivateRoute';
import Login from './pages/Login';
import Register from './pages/Register';
import Dashboard from './pages/Dashboard';
import Home from './pages/Home';

// Create theme
const theme = createTheme({
  palette: {
    primary: {
      main: '#1976d2',
    },
    secondary: {
      main: '#dc004e',
    },
  },
});

function App() {
  return (
    <ThemeProvider theme={theme}>
      <AuthProvider>
        <Router>
          <Routes>
            <Route path="/login" element={<Login />} />
            <Route path="/register" element={<Register />} />
            <Route
              path="/dashboard"
              element={
                <PrivateRoute>
                  <Layout>
                    <Dashboard />
                  </Layout>
                </PrivateRoute>
              }
            />
            <Route
              path="/"
              element={
                <Layout>
                  <Home />
                </Layout>
              }
            />
          </Routes>
        </Router>
        <ToastContainer />
      </AuthProvider>
    </ThemeProvider>
  );
}

export default App;
```

### 7. src/pages/Home.jsx, Login.jsx, Register.jsx, and Dashboard.jsx
(These files were provided earlier in the conversation)

### Configuration Files

### 1. backend/.env
```env
PORT=3000
DB_HOST=localhost
DB_USER=postgres
DB_PASSWORD=your_password
DB_NAME=store_rating_db
JWT_SECRET=your_jwt_secret_key
```

### 2. backend/package.json
```json
{
  "name": "backend",
  "version": "1.0.0",
  "description": "Store Rating Application Backend",
  "main": "src/index.js",
  "scripts": {
    "start": "node src/index.js",
    "dev": "nodemon src/index.js",
    "test": "echo \"Error: no test specified\" && exit 1"
  },
  "keywords": [],
  "author": "",
  "license": "ISC",
  "dependencies": {
    "bcrypt": "^5.1.1",
    "cors": "^2.8.5",
    "dotenv": "^16.3.1",
    "express": "^4.18.2",
    "jsonwebtoken": "^9.0.2",
    "pg": "^8.11.3",
    "pg-pool": "^3.6.1"
  },
  "devDependencies": {
    "nodemon": "^3.0.1"
  }
}
```

### 3. frontend/package.json
```json
{
  "name": "frontend",
  "private": true,
  "version": "0.0.0",
  "type": "module",
  "scripts": {
    "dev": "vite",
    "build": "vite build",
    "preview": "vite preview"
  },
  "dependencies": {
    "@emotion/react": "^11.11.1",
    "@emotion/styled": "^11.11.0",
    "@mui/icons-material": "^5.14.3",
    "@mui/material": "^5.14.3",
    "@reduxjs/toolkit": "^1.9.5",
    "axios": "^1.4.0",
    "formik": "^2.4.3",
    "react": "^18.2.0",
    "react-dom": "^18.2.0",
    "react-redux": "^8.1.2",
    "react-router-dom": "^6.14.2",
    "react-toastify": "^9.1.3",
    "yup": "^1.2.0"
  },
  "devDependencies": {
    "@types/react": "^18.2.15",
    "@types/react-dom": "^18.2.7",
    "@vitejs/plugin-react": "^4.0.3",
    "vite": "^4.4.5"
  }
}
```

## Running the Application

1. Backend Setup:
```bash
cd backend
npm install
npm run dev
```

2. Frontend Setup:
```bash
cd frontend
npm install
npm run dev
```

3. Database Setup:
- Install PostgreSQL
- Create database and tables using schema.sql
- Update .env with your database credentials

The application will be available at:
- Backend API: http://localhost:3000
- Frontend: http://localhost:5173