const express = require('express')
const logger = require('morgan')
const passport = require('passport')
const LocalStrategy = require('passport-local').Strategy
const jwt = require('jsonwebtoken')
const cookieParser = require('cookie-parser')
const fortune = require('fortune-teller');
const extractJwt = require('passport-jwt').ExtractJwt;
const jwtStrategy = require('passport-jwt').Strategy;
const crypto = require('crypto');

const jwtSecret = 'mykeeeyyyy'
const adages = [
  "A bird in the hand is worth two in the bush",
  "Actions speak louder than words",
  "All good things must come to an end",
  "Don't count your chickens before they hatch",
  "Every cloud has a silver lining",
];
const app = express()
const port = 3000

const key = 'keykeyyy'

app.use(logger('dev'))
app.use(cookieParser())

passport.use('username-password', new LocalStrategy(
  {
    usernameField: 'username',
    passwordField: 'password',
    session: false
  },
  function (username, password, done) {
    if (username === 'walrus' && password === 'walrus') {
      const user = { 
        username: 'walrus',
        description: 'the only user that deserves to contact the fortune teller'
      }
      return done(null, user)
    }
    return done(null, false) 
  }
))

app.use(express.urlencoded({ extended: true }))
app.use(passport.initialize()) 

const jwtOptions = {
  jwtFromRequest: extractJwt.fromAuthHeaderAsBearerToken('jwt'),
  secretOrKey: key
};

passport.use(new jwtStrategy(jwtOptions, (payload, done) => {
  // Verify the user's JWT here
  jwt.verify(payload, jwtOptions.secretOrKey, (err, user) => {
    if (err) {
      return done(err, false);
    }
    return done(null, user);
  });
}));

function authenticateToken(req, res, next) {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];
  if (token == null) return res.sendStatus(401); // Unauthorized

  jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
    if (err) return res.sendStatus(403); // Forbidden
    req.user = user;
    next();
  });
}


function getRandomAdage() {
  const randomIndex = Math.floor(Math.random() * adages.length);
  return adages[randomIndex];
}
app.get('/', jwt.verify, function(req, res) {
  const adage = getRandomAdage();
  res.send(adage);});

app.get('/login',
  (req, res) => {
    res.sendFile('login.html', { root: __dirname })
  }
)

app.post('/login', 
  passport.authenticate('username-password', { failureRedirect: '/login', session: false }),
  (req, res) => { 
    const jwtClaims = {
      sub: req.user.username,
      iss: 'localhost:3000',
      aud: 'localhost:3000',
      exp: Math.floor(Date.now() / 1000) + 604800, // 1 week (7×24×60×60=604800s) from now
      role: 'user'
    }

    const token = jwt.sign(jwtClaims, jwtOptions.secretOrKey)

    res.cookie('jwt', token, {httpOnly:true, secure:true} )

    res.redirect(`/?token=${token}`)

    console.log(`Token sent. Debug at https://jwt.io/?value=${token}`)
    console.log(`Token secret (for verifying the signature): ${jwtSecret.toString('base64')}`)
  }
)

app.get('/logout', (req, res) => {
  res.clearCookie('jwt');
  res.redirect('/');
});

app.use(function (err, req, res, next) {
  console.error(err.stack)
  res.status(500).send('Something broke!')
})

app.listen(port, () => {
  console.log(`Example app listening at http://localhost:${port}`)
})
