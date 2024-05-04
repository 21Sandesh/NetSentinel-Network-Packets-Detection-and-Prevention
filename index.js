const express = require('express');
const path = require('path');
const cookieParser = require('cookie-parser');
const flash = require('express-flash');
const session = require('express-session');
const fs = require('fs');
const https = require('https');
require('dotenv').config();

const { connecttoMongoDB } = require('./connect');
const {restrictAccess} = require('./middlewares/auth');
const httpsConfig = require('./httpsConfig');

const app = express();
const PORT = 8001;

// Set up WebSocket server
const httpsServer = https.createServer({
  key: fs.readFileSync('./server.key'), // Update with your SSL key file
  cert: fs.readFileSync('./server.cert') // Update with your SSL certificate file
}, app);

app.use(session({
    secret: 'sandesh',
    resave: false,
    saveUninitialized: true,
    cookie: { secure: true } // Using HTTPS
}));

connecttoMongoDB(process.env.DBUrl).then(() => console.log("Connected to MongoDB")).catch((err) => console.log(err));

const staticRoute = require('./routes/staticRouter');
const handleuserRoute = require('./routes/handleuser');
const userRoute = require('./routes/user');

app.set("view engine", "ejs");
app.set("views", path.resolve("./views"));
app.use(express.static(path.join(__dirname, 'public')));


app.use(express.json());
app.use(express.urlencoded({ extended: false }));
app.use(cookieParser());
app.use(flash());

app.use("/auth", handleuserRoute);
app.use("/user", restrictAccess, userRoute);
app.use("/", staticRoute);


const port = 8001; // or any other port you prefer
const hostname = 'localhost';

// const port = process.env.PORT || 8001;
httpsConfig.createServer(app, port, hostname);