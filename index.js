const express = require('express');
const bodyParser = require('body-parser');
const jwt = require('express-jwt');
const jwtAuthz = require('express-jwt-authz');
const jwksRsa = require('jwks-rsa');

const app = express();
const PORT = parseInt(process.env.PORT, 10) || 8080;

app.use(bodyParser.json());
app.use(bodyParser.urlencoded({extended: true}));

const checkJwt = jwt({
  // Dynamically provide a signing key
  // based on the kid in the header and
  // the signing keys provided by the JWKS endpoint.
  secret: jwksRsa.expressJwtSecret({
    cache: true,
    rateLimit: true,
    jwksRequestsPerMinute: 5,
    jwksUri: `https://dev-xh07lp0k.eu.auth0.com/.well-known/jwks.json`
  }),
  
  // Validate the audience and the issuer.
  audience: 'https://api-oauth',
  issuer: `https://dev-xh07lp0k.eu.auth0.com/`,
  algorithms: ['RS256']
});

const checkScopes = jwtAuthz(['read:messages']);

/**
 * CORS configurations
 */
app.all('/*', (req, res, next) => {
  // CORS headers
  res.header('Access-Control-Allow-Origin', '*');
  res.header('Access-Control-Allow-Methods', 'GET,PUT,POST,DELETE,OPTIONS');
  
  // Set custom headers for CORS
  res.header('Access-Control-Allow-Headers', 'Content-type,Accept,X-Access-Token,X-Key');
  if (req.method === 'OPTIONS') {
    res.status(200)
      .end();
  } else {
    next();
  }
});

app.get('/api/public', (req, res) => {
  res.status(200).json({
    message: 'Tiens du contenu public depuis l\'API'
  });
});

app.get('/api/secured', checkJwt, (req, res) => {
  res.status(200).json({
    message: 'Tiens du contenu privé depuis l\'API',
  });
});

app.get('/api/secured-scoped', checkJwt, checkScopes, function (req, res) {
  res.json({
    message: 'Tiens du contenu public depuis l\'API avec le scope read:messages'
  });
});

app.listen(PORT, () => {
  console.log(`Running on port: ${PORT}`);
});
