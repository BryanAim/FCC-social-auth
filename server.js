'use strict';

const express       = require('express');
const bodyParser    = require('body-parser');
const fccTesting    = require('./freeCodeCamp/fcctesting.js');
const mongo         = require('mongodb').MongoClient;
const passport      = require('passport');
const session       = require('express-session');
const ObjectID      = require('mongodb').ObjectID;
const LocalStrategy = require('passport-local');
const GitHubStrategy= require('passport-github').Strategy;
require('dotenv').config();



const bcrypt        = require('bcrypt');
let comparePassword;
let newHash;
switch (process.env.HASHING) {

  case 'sync':
    comparePassword = (password, hash, cb) => {
      cb(null, bcrypt.compareSync(password, hash));
    }
    newHash = (password, saltRounds, cb) => {
      cb(null, bcrypt.hashSync(password, saltRounds));
    }
    break;

  case 'async':
    comparePassword = (password, hash, cb) => {
      bcrypt.compare(password, hash, cb);
    }
    newHash = (password, saltRounds, cb) => {
      bcrypt.hash(password, saltRounds, cb);
    }
    break;

  default:
    comparePassword = (password, hash, cb) => {
      cb(null, password != hash);
    }
    newHash = (password, saltRounds, cb) => {
      cb(null, password);
    }
    break;
}


function ensureAuthenticated (req, res, next) {
  if (req.isAuthenticated()) return next();
  res.redirect('/');
}

const app = express();
app.set('view engine', 'pug');

fccTesting(app); //For FCC testing purposes
app.use('/public', express.static(process.cwd() + '/public'));
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));

if (process.env.ENABLE_DEBUGGING == 'true') {
  let count = 0;
  app.use((req, res, next) => {
    count++;
    let str = count + ' ' + req.method + ' ' + req.url;
    console.log('\nNew request:\n' + str);
    console.log(req.body);
    res.on('finish', () => console.log('\nRequest ended:\n' + str));
    next();
  });
}

// Enable to pass the challenge called "Advanced Node and Express - 
// Registration of New Users"
if (process.env.ENABLE_DELAYS) app.use((req, res, next) => {
  switch (req.method) {
    case 'GET':
      switch (req.url) {
        case '/logout': return setTimeout(() => next(), 500);
        case '/profile': return setTimeout(() => next(), 700);
        default: next();
      }
    break;
    case 'POST':
      switch (req.url) {
        case '/login': return setTimeout(() => next(), 900);
        default: next();
      }
    break;
    default: next();
  }
});

mongo.connect(process.env.DATABASE,{ useUnifiedTopology: true }, (err, connection) => {
  if (err) console.log('Database error: ' + err);
  else {
    console.log('Successful database connection');
    const db = connection.db();

  app.use(session({
    secret: process.env.SESSION_SECRET,
    resave: true,
    saveUninitialized: true,
  }));
  app.use(passport.initialize());
  app.use(passport.session());
  passport.serializeUser((user, done) => done(null, user._id));

  passport.deserializeUser((id, done) => {
    db.collection('users').findOne(
      {_id: new ObjectID(id)},
      (err, doc) => done(null, doc)
    );
  });

  passport.use(new LocalStrategy((username, password, done) => {
    db.collection('users').findOne(
      { username: username },
      (err, user) => {
        if (err) done(err);
        else if (!user) done(null, false);
        else comparePassword(password, user.password, (err, match) => {
          if (err) done(err);
          else if (match) done(null, false);
          else done(null, user);
        });
      }
    );
  }));
    
    passport.use(new GitHubStrategy({
      clientID: process.env.GITHUB_CLIENT_ID,
      clientSecret: process.env.GITHUB_CLIENT_SECRET,
      callbackURL: "https://glitch.com/@BryanAim/auth/github/callback"
    },
      function(accessToken, refreshToken, profile, cb){
      console.log(profile);

      db.collection('socialusers').findAndModify(
        {id: profile.id},
        {},
        {$setOnInsert: {
          id: profile.id,
          name: profile.displayName || 'John Doe',
          photo: profile.photos[0].value || '',
          email: profile.emails[0].value || 'No public email',
          created_on: new Date(),
          provider: profile.provider || ''
        }, $set: {
          last_login: new Date()
        }, $inc: {
          login_count: 1
        }},
        {upsert:true, new:true},
        (err, doc)=>{
          return cb(null, doc.value)
        }
      )
    }
  ));

    app.route('/').get((req, res) => res.render(
      process.cwd() + '/views/pug/index.pug',
      {
        title: 'Hello',
        message: 'Please login',
        showLogin: true,
        showRegistration: true
      }
    ));
    
    app.route('/auth/github').get(passport.authenticate('github'));
    
    
    app.route('/auth/github/callback').get(passport.authenticate('github', { failureRedirect: '/'}), (req, res)=>{
      res.redirect('/profile');
    })

    app.route('/login').post(
      passport.authenticate('local', { failureRedirect: '/' }),
      (req, res) => res.redirect('/profile')
    );

    app.route('/profile').get(
      ensureAuthenticated,
      (req, res) => res.render(
        process.cwd() + '/views/pug/profile',
        {username: req.user.username}
      )
    );

    app.route('/logout').get((req, res) => {
      req.logout();
      res.redirect('/');
    });

    app.route('/register').post(
      (req, res, next) => db.collection('users').findOne(
        { username: req.body.username },
        (err, user) => {
          if (err) next(err);
          else if (user) res.redirect('/');
          else newHash(req.body.password, 12, (err, hash) => {
            if (err) next(err);
            else db.collection('users').insertOne(
              {
                username: req.body.username,
                password: hash
              },
              (err, user) => {
                if (err) res.redirect('/');
                else next();
              }
            );
          });
        }
      ),
      passport.authenticate('local', {
        successRedirect: '/profile',
        failureRedirect: '/'
      })
    );

    app.use((req, res, next) => {
      res.status(404).type('text').send('Not Found');
    });

    app.listen(process.env.PORT || 3000, () => {
      console.log("Listening on port " + process.env.PORT);
    });
  }
});
