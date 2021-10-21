// LinuxServer Guacamole Client

//// Application Variables ////
var baseurl = process.env.SUBFOLDER || '/';
var crypto = require('crypto');
var ejs = require('ejs');
var express = require('express');
var app = require('express')();
var http = require('http').Server(app);
var cloudcmd = require('cloudcmd');
var bodyParser = require('body-parser');
var { pamAuthenticate, pamErrors } = require('node-linux-pam');
var CUSTOM_PORT = process.env.CUSTOM_PORT || 8888;
var baserouter = express.Router();

//// JupyterHub auth related code
const session = require('express-session');
const passport = require('passport');
const OAuth2Strategy = require('passport-oauth2');
const axios = require('axios')

const clientHubApiUrl = 'http://localhost:9000/fairdi/nomad/latest/north/hub/api'; // process.env.JUPYTERHUB_API_URL
const serverHubApiUrl = 'http://host.docker.internal:9000/fairdi/nomad/latest/north/hub/api';
const secret = process.env.JUPYTERHUB_API_TOKEN
const user = process.env.JUPYTERHUB_USER

const passportOptions = {
  authorizationURL: `${clientHubApiUrl}/oauth2/authorize`,
  tokenURL: `${serverHubApiUrl}/oauth2/token`,
  clientID: process.env.JUPYTERHUB_CLIENT_ID,
  clientSecret: secret,

}

passport.use(new OAuth2Strategy(
  passportOptions,
  function(accessToken, refreshToken, params, profile, done) {
    axios.get(`${serverHubApiUrl}/user`, {
      headers: { 'Authorization': `Bearer ${params['access_token']}`}
    }).then(response => {
      if (!response?.data?.name) {
        done('Cannot info for loggedin user to authorize access.', null);
      } else if (response?.data?.name !== user) {
        done('Logged in user does not match the container\'s user', null);
      } else {
        done(null, response.data);
      }
    }).catch(error => done(error, null))
  }
));

passport.serializeUser(function(user, done) {
  done(null, user);
});

passport.deserializeUser(function(user, done) {
  done(null, user);
});

baserouter.use(session({ secret: secret, cookie: { maxAge: 60000, path: baseurl }}))
baserouter.use(passport.initialize());
baserouter.use(passport.session());

function northAuth(req, res, next) {
  console.log('###', req.path)
  if (req.path === '') {
    return res.redirect(`${baseurl}north/login`);
  }
  if (req.path === '/north/login' || req.path === '/oauth_callback') {
    return next();
  }
  if (!req.user) {
    return res.redirect(`${baseurl}north/login`);
  }
  next();
};

baserouter.use(northAuth);

baserouter.get('/north/login', passport.authenticate('oauth2'));

baserouter.get('/oauth_callback',
  passport.authenticate('oauth2'),
  function(req, res) {
    res.redirect(baseurl);
  });


///// Guac Websocket Tunnel ////
var GuacamoleLite = require('guacamole-lite');
var clientOptions = {
  crypt: {
    cypher: 'AES-256-CBC',
    key: 'LSIOGCKYLSIOGCKYLSIOGCKYLSIOGCKY'
  },
  log: {
    verbose: false
  }
};
// Spinup the Guac websocket proxy on port 3000 if guacd is running
var guacServer = new GuacamoleLite({server: http,path:baseurl +'guaclite'},{host:'127.0.0.1',port:4822},clientOptions);
// Function needed to encrypt the token string for guacamole connections
var encrypt = (value) => {
  var iv = crypto.randomBytes(16);
  var cipher = crypto.createCipheriv(clientOptions.crypt.cypher, clientOptions.crypt.key, iv);
  let crypted = cipher.update(JSON.stringify(value), 'utf8', 'base64');
  crypted += cipher.final('base64');
  var data = {
    iv: iv.toString('base64'),
    value: crypted
  };
  return new Buffer(JSON.stringify(data)).toString('base64');
};

//// Public JS and CSS ////
baserouter.use('/public', express.static(__dirname + '/public'));
//// Embedded guac ////
baserouter.get("/", function (req, res) {
 if (req.query.login){
    var connectionstring = encrypt(
      {
        "connection":{
          "type":"rdp",
          "settings":{
            "hostname":"127.0.0.1",
            "port":"3389",
            "security": "any",
            "ignore-cert": true
          }
        }
      });
  }
  else{
    var connectionstring = encrypt(
      {
        "connection":{
          "type":"rdp",
          "settings":{
            "hostname":"127.0.0.1",
            "port":"3389",
            "username":"abc",
            "password":"abc",
            "security": "any",
            "ignore-cert": true
          }
        }
      });
  }
  res.render(__dirname + '/rdp.ejs', {token : connectionstring, baseurl: baseurl});
});
//// Web File Browser ////
baserouter.use(bodyParser.urlencoded({ extended: true }));
baserouter.get('/files', function (req, res) {
  res.send('Unauthorized');
  res.end();
});
baserouter.post('/files', function(req, res, next){
  var password = req.body.password;
  var options = {
    username: 'abc',
    password: password,
  };
  pamAuthenticate(options, function(err, code) {
    if (!err) {
      next();
    } else {
      res.send('Unauthorized');
      res.end();
    }
  });
});
baserouter.use('/files', cloudcmd({
  config: {
    root: '/',
    prefix: baseurl + 'files',
    terminal: false,
    console: false,
    configDialog: false,
    contact: false,
    auth: false,
    name: 'Files',
    log: false,
    keysPanel: false,
    oneFilePanel: true,
  }
}))

// Spin up application on CUSTOM_PORT with fallback to port 3000
app.use(baseurl, baserouter);
http.listen(CUSTOM_PORT, function(){
  console.log('listening on *:' + CUSTOM_PORT);
});
