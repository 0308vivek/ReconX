const express = require('express');
const path = require('path');
const rateLimit = require('express-rate-limit');

const app = express();
const PORT = process.env.PORT || 3000;

// Set EJS as templating engine
app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));

// Middlewares
app.use(express.static(path.join(__dirname, 'public')));
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// Request logging middleware
app.use((req, res, next) => {
    console.log(`[${new Date().toISOString()}] ${req.method} ${req.url}`);
    next();
});

// Rate limiting middleware
const limiter = rateLimit({
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: 100, // Limit each IP to 100 requests per `window` (here, per 15 minutes)
    standardHeaders: true, // Return rate limit info in the `RateLimit-*` headers
    legacyHeaders: false, // Disable the `X-RateLimit-*` headers
    message: 'Too many requests from this IP, please try again after 15 minutes'
});

// Apply rate limiting to all requests (could restrict to /scan)
app.use(limiter);

// Setup Routes
const scanRoute = require('./routes/scan');

app.get('/', (req, res) => {
    res.render('home');
});

// Added to serve dashboard EJS
app.get('/dashboard', (req, res) => {
    res.render('dashboard');
});

// Register the scan route
app.use('/scan', scanRoute);

// Centralized error handling
app.use((err, req, res, next) => {
    console.error(`[Error] ${err.message}`);
    res.status(500).json({ error: 'Internal Server Error', details: err.message });
});

app.listen(PORT, () => {
    console.log(`ReconX Server running on http://localhost:${PORT}`);
});
