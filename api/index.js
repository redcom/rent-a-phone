const express = require('express');
const fs = require('fs');
const passport = require('passport');
const { Issuer, Strategy } = require('openid-client');
const passportJWT = require('passport-jwt');
const cookieSession = require('cookie-session');
const cookieParser = require('cookie-parser');
const bodyParser = require('body-parser');

const port = process.env.PORT || 8080;

// const Mongoose = require('mongoose')

const jwt = require('jsonwebtoken');
const crypto = require('crypto');
const User = require('./models/User');
const Token = require('./models/Token');

// encryption
const JWT_ENCRYPTION_KEY = process.env.JWT_ENCRYPTION_KEY;
const IV_LENGTH = 8;
function encrypt(text) {
  const iv = crypto.randomBytes(IV_LENGTH);
  const cipher = crypto.createCipheriv('aes128', new Buffer(JWT_ENCRYPTION_KEY), iv);
  let encrypted = cipher.update(text);

  encrypted = Buffer.concat([encrypted, cipher.final()]);

  return `${iv.toString('hex')}:${encrypted.toString('hex')}`;
}

function decrypt(text) {
  const textParts = text.split(':');
  const iv = new Buffer(textParts.shift(), 'hex');
  const encryptedText = new Buffer(textParts.join(':'), 'hex');
  const decipher = crypto.createDecipheriv('aes128', new Buffer(JWT_ENCRYPTION_KEY), iv);
  let decrypted = decipher.update(encryptedText);

  decrypted = Buffer.concat([decrypted, decipher.final()]);

  return decrypted.toString();
}

const extract = (request) => {
  console.log('extracting');
  const x = passportJWT.ExtractJwt.fromAuthHeaderWithScheme('Bearer');
  const token = x(request);
  console.log('token', token);
  return token;
};

const runServer = async () => {
  try {
    const mongoOptions = {
      reconnectTries: Number.MAX_VALUE, // Never stop trying to reconnect
      reconnectInterval: 500, // Reconnect every 500ms
      poolSize: 10, // Maintain up to 10 socket connections
      // If not connected, return errors immediately rather than waiting for reconnect
      bufferMaxEntries: 0,
    };

    // Mongoose.connect(process.env.MONGODB_URI, mongoOptions, (error) => {
    //   if (error) {
    //     console.log('error on connecting to mongodb')
    //     process.exit(1)
    //   }
    // })

    const yaraIssuer = await Issuer.discover(process.env.YARASSO_URI);
    const client = new yaraIssuer.Client({
      client_id: process.env.YARASSO_CLIENT_ID,
      client_secret: process.env.YARASSO_CLIENT_SECRET,
    });

    client.CLOCK_TOLERANCE = 1000;

    const params = {
      redirect_uri: process.env.YARASSO_REDIRECT_URL,
      scope: 'openid zoneinfo address email email_verified family_name gender given_name groups job_title nickname name profile phone_number',
    };

    const passReqToCallback = false;
    const usePKCE = false;

    console.log('instance?', typeof (client));
    passport.use('oidc', new Strategy({
      client, params, passReqToCallback, usePKCE,
    }, async (tokenSet, userinfo, done) => {
      console.log('got token', tokenSet, userinfo);
      const userDoc = {
        sub: userinfo.sub,
        given_name: userinfo.given_name,
        family_name: userinfo.family_name,
        email: userinfo.email,
        email_verified: userinfo.email_verified,
      };

      const tokenDoc = {
        type: tokenSet.token_type,
        access_token: tokenSet.access_token,
        refresh_token: tokenSet.refresh_token,
        id_token: tokenSet.id_token,
        expires_at: tokenSet.expires_at,
        scope: tokenSet.scope,
      };

      // const user = await User.findOrCreate({ sub: userinfo.sub }, userDoc)
      const user = {
        sub: 'test',
      };
      tokenDoc.user_id = user.sub;
      // const token = await Token.update({ user_id: user.sub }, tokenDoc, { upsert: true, overwrite: true })

      return done(null, user);
    }));

    passport.use(new passportJWT.Strategy({
      jwtFromRequest: extract,
      secretOrKey: process.env.JWT_PRIVATE_KEY,
      issuer: 'accounts.yara.com',
      audience: 'yara.com',
      // ignoreExpiration: true,
      // algorithms: ['HS256'],
      // passReqToCallback: true
    }, async (payload, done) => {
      console.log('>>>>>>>>>>>>> HERHEHEHREHRHERHERHEHREHR');
      const { data } = payload;
      const decrypted = JSON.parse(decrypt(data));
      console.log('>>>>>>>>>>>>>>>>>>>>>>>>>>> finding', decrypted._id);
      const user = await User.findOne({ sub: decrypted._id });
      const token = await Token.findOne({ user_id: decrypted._id });


      // check token expiration
      // const now = new Date().getTime()
      // const expires_at = token.created_at + token.expires_in
      // if (expires_at >= now) {
      //   console.log('token expired ... do refresh token')
      // }
      user.token = token;
      done(null, user);
    }));

    passport.serializeUser((user, done) => {
      done(null, user);
    });

    passport.deserializeUser((obj, done) => {
      done(null, obj);
    });

    const app = express();

    app.use(cookieParser());
    app.use(cookieSession({
      name: 'session',
      secret: 'foo',
      cookie: { secure: true },
    }));
    app.use(bodyParser.json());

    app.use(passport.initialize());
    app.use(passport.session());

    const userToken = async (user) => {
      if (user) {
        const rawdata = JSON.stringify({
          _id: user.sub,
        });
        const jwtopts = {
          iss: 'accounts.yara.com',
          issuer: 'accounts.yara.com',
          jwtid: user._id,
          jti: user._id,
          identity: user._id,
          aud: 'yara.com',
          audience: 'yara.com',
          algorithm: 'HS256',
          type: 'access',
          fresh: false,
        };

        const tojwt = encrypt(rawdata);
        const jwtToken = await jwt.sign({ data: tojwt, ...jwtopts }, process.env.JWT_PRIVATE_KEY);
        return jwtToken;
      }
      return null;
    };

    app.get('/auth', async (req, res) => {
      if (req.user) {
        console.log('log\n\n\n\n');
        const jwtToken = await userToken(req.user);
        res.setHeader('JWT', jwtToken);
        res.send('Logged in');
      } else {
        res.send('<a href="/auth/login">login</a> v8');
      }
    });

    app.get('/auth/login', passport.authenticate('oidc'));

    app.get('/auth/callback', passport.authenticate('oidc', { failureRedirect: '/auth/login' }), async (req, res) => {
      console.log('callback here');
      console.log(req.user);

      res.redirect('/auth?isApp=true');
    });

    app.get('/auth/profile', passport.authenticate('jwt', { session: false }), (req, res) => {
      console.log('authenticated on profile route');
      console.log(req.user);
      res.send(JSON.stringify(req.user));
    });

    if (process.env.NODE_ENV === 'development') {
      const https = require('https');
      const options = {
        key: fs.readFileSync('./certs/server.key'),
        cert: fs.readFileSync('./certs/server.crt'),
      };
      const server = https.createServer(options, app).listen(port, (error) => {
        if (error) {
          console.error(error);
        }
        console.log(`auth server (https) is listening on port ${port}!`);
      });
    } else {
      app.listen(port, (error) => {
        if (error) {
          console.error(error);
        }
        console.log(`auth server (https) is listening on port ${port}!`);
      });
    }
  } catch (error) {
    console.log('error', error);
  }
};


runServer();
