//jshint esversion:6
require('dotenv').config();
const express = require('express');
const bodyParser = require('body-parser');
const ejs = require('ejs');
const mongoose = require('mongoose');
const _ = require('lodash');
const {Db} = require('mongodb');
const session = require('express-session');
const passport = require('passport');
const passportLocalMongoose = require('passport-local-mongoose');
const {authenticate} = require('passport');
const GoogleStrategy = require('passport-google-oauth20').Strategy;
const findOrCreate = require('mongoose-find-or-create');
const FacebookStrategy = require('passport-facebook').Strategy;
const LocalStrategy = require('passport-local').Strategy;

const app = express();

app.set('view engine', 'ejs');

app.use(
  session({
    secret: process.env.SECRET,
    resave: false,
    saveUninitialized: false,
  })
);

app.use(passport.initialize());
app.use(passport.session());

app.use(bodyParser.urlencoded({extended: true}));

app.use(express.static('public'));

mongoose.set('strictQuery', true);
mongoose.connect('mongodb://127.0.0.1:27017/account', {useNewUrlParser: true});

const accountSchema = new mongoose.Schema({
  username: String,
  password: String,
  googleId: String,
  facebookId: String,
  secret: String,
});

accountSchema.plugin(passportLocalMongoose);
accountSchema.plugin(findOrCreate);

const Account = mongoose.model('Account', accountSchema);

passport.use(Account.createStrategy());

passport.serializeUser((user, done) => {
  done(null, user.id);
});

passport.deserializeUser((id, done) => {
  Account.findById(id, (err, user) => {
    done(err, user);
  });
});

passport.use(
  new GoogleStrategy(
    {
      clientID: process.env.CLIENT_ID,
      clientSecret: process.env.CLIENT_SECRET,
      callbackURL: 'http://localhost:3000/auth/google/secrets',
    },
    function (accessToken, refreshToken, profile, cb) {
      Account.findOrCreate({googleId: profile.id}, function (err, user) {
        return cb(err, user);
      });
    }
  )
);

passport.use(
  new FacebookStrategy(
    {
      clientID: process.env.FB_APP_ID,
      clientSecret: process.env.FB_SECRET,
      callbackURL: 'http://localhost:3000/auth/facebook/secrets',
    },
    function (accessToken, refreshToken, profile, cb) {
      Account.findOrCreate({facebookId: profile.id}, function (err, user) {
        return cb(err, user);
      });
    }
  )
);

app.get('/', function (req, res) {
  res.render('home');
});

app.get('/auth/google', passport.authenticate('google', {scope: ['profile']}));

app.get('/auth/google/secrets', passport.authenticate('google', {failureRedirect: '/login'}), function (req, res) {
  // Successful authentication, redirect home.
  res.redirect('/secrets');
});

app.get('/auth/facebook', passport.authenticate('facebook'));

app.get('/auth/facebook/secrets', passport.authenticate('facebook', {failureRedirect: '/login'}), function (req, res) {
  // Successful authentication, redirect home.
  res.redirect('/secrets');
});

app.get('/login', function (req, res) {
  res.render('login', {text: ''});
});

app.get('/register', function (req, res) {
  res.render('register', {registerEmail: ''});
});

app.get('/logout', (req, res) => {
  req.logout(function (err) {
    if (err) {
      console.log(err);
    }
    res.redirect('/');
  });
});

app.get('/secrets', (req, res) => {
  Account.find({secret: {$ne: null}}, (err, foundAccounts) => {
    if (err) {
      console.log(err);
    } else {
      if (foundAccounts) {
        res.render('secrets', {allSecrets: foundAccounts});
      }
    }
  });
});

app.get('/submit', (req, res) => {
  if (req.isAuthenticated()) {
    res.render('submit');
  } else {
    res.redirect('/login');
  }
});

app.post('/register', function (req, res) {
  Account.register({username: req.body.username}, req.body.password, (err, result) => {
    if (err) {
      res.render('register', {registerEmail: 'Email already registered'});
    } else {
      passport.authenticate('local')(req, res, () => {
        res.redirect('/secrets');
      });
    }
  });
});

app.post('/login', function (req, res) {
  const user = new Account({
    username: req.body.username,
    password: req.body.password,
  });
  passport.authenticate('local', function (err, users) {
    if (err) {
      console.log(err);
    }
    if (!users) {
      return res.render('login', {text: 'Credential is not valid!'});
    }
    req.logIn(user, function (err) {
      if (err) {
        console.log(err);
      }

      return res.redirect('/secrets');
    });
  })(req, res);
});

app.post('/submit', (req, res) => {
  const secret = req.body.secret;

  Account.findById(req.user.id, (err, foundAccount) => {
    if (err) {
      console.log(err);
    } else {
      foundAccount.secret = secret;
      foundAccount.save(() => {
        res.redirect('/secrets');
      });
    }
  });
});

app.listen(3000, function () {
  console.log('Server started on port 3000');
});

// app.post('/register', function (req, res) {
//   bcrypt.hash(req.body.password, saltRounds, function (err, hash) {
//     const account = new Account({
//       username: req.body.username,
//       password: hash,
//     });
//     if (!err) {
//       Account.findOne({}, (err, foundUser) => {
//         if (!err) {
//           if (account.username === foundUser.username) {
//             res.render('register', {registerEmail: 'Already Registered Proceed to login'});
//           } else {
//             account.save();
//             res.render('secrets');
//           }
//         } else {
//           console.log(err);
//         }
//       });
//     }
//   });
// });

// app.post('/login', function (req, res) {
//   const username = req.body.username;
//   const password = req.body.password;

//   Account.findOne({username: username}, function (err, foundAccount) {
//     if (err) {
//       console.log(err);
//     } else {
//       if (foundAccount) {
//         bcrypt.compare(password, foundAccount.password, function (err, result) {
//           if (result == true) {
//             res.render('secrets');
//           } else {
//             res.render('login', {text: 'Wrong Email or Password'});
//           }
//         });
//       }
//     }
//   });
// });
