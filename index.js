const express = require('express');
const session = require('express-session');
const passport = require('passport');
const path = require('path');
const LocalStrategy = require("passport-local").Strategy;
const bcrypt = require("bcrypt");

const users=[];

const app = express();
const port = process.env.PORT || 8080;

app.use(express.json());
app.use(express.urlencoded({ extended: true }));

app.use(express.static(path.join(__dirname, 'public')))
app.set('view engine', 'pug');

app.get('/', (req, res) => { 
   res.render('index');
 });

app.use(session({
     secret: 'Alex63',
     resave: false,
     saveUninitialized: false,
     cookie: {
       httpOnly: true,
       secure: false,
       domain: 'localhost',
       maxAge: 1000 * 60 * 60, // 1 hour
     },
   })
 );

//PASSPORT INITIAL
 app.use(passport.initialize());
 app.use(passport.session());
 passport.use(
     new LocalStrategy({ usernameField: 'email'}, (email, password, done) => {
       const user = users.find((user) => user.email === email);
       if (!user) {
         return done(null, false, { message: 'Incorrect email or password.' });
       }
       bcrypt.compare(password, user.password, (err, isMatch) => {
         if (err) return done(err);
         if (!isMatch) return done(null, false, { message: 'Incorrect email or password.' });
         return done(null, user);
       });
     })
   );
  passport.serializeUser((user, done) => {
    done(null, user.id);
  });
  
  passport.deserializeUser((id, done) => {
    const user = users.find((user) => user.id === id);
    done(null, user);
  });

//Routes
app.post('/register', async (req, res) => {
   const { email, password } = req.body;
   const existingUser = users.find(user => user.email === email);
 
   if (existingUser) {
     return res.status(400).send('This user already exists');
   }
 
   const hashPassword = await bcrypt.hash(password, 8);
   users.push({ id: Date.now().toString(), email, password: hashPassword });
   res.status(201).json({ message: 'User registered successfully.' });
   console.log("users===>",users)
 });
 
 app.post('/login', passport.authenticate('local', {
   successRedirect: '/protected',
   failureRedirect: '/login',
 }));
 
 app.post('/logout', (req, res) => {
   req.logout((err) => {
     if (err) return res.status(500).json({ message: 'Logout failed.' });
     res.status(200).json({ message: 'Logged out successfully.' });
   });
 });
 
 function isAuthenticated(req, res, next) {
   if (req.isAuthenticated()) {
     return next();
   }
   res.status(401).json({ message: 'Unauthorized' });
 }
 
app.get('/protected', isAuthenticated, (req, res) => {
   res.status(200).json({ message: 'This is a protected route!' });
 });

app.listen(port, () => {
   console.log(`Server listening on port ${port}`);
});