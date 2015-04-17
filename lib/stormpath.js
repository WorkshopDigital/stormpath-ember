'use strict';


var async = require('async');
var bodyParser = require('body-parser');
var csrf = require('csurf');
var express = require('express');
var expressVersion = require('express/package.json').version;
var stormpath = require('stormpath');

var authentication = require('./authentication');

var helpers = require('./helpers');
var version = require('../package.json').version;


/**
 * Initialize the Stormpath client.
 *
 * @method
 * @private
 *
 * @param {Object} app - The express application.
 *
 * @return {Function} A function which accepts a callback.
 */
function initClient(app) {
  return function(next) {
    var connection;
    var userAgent = 'stormpath-express/' + version + ' ' + 'express/' + expressVersion;

    if (app.get('stormpathCache') === 'memcached') {
      connection = app.get('stormpathCacheHost')  + ':' + app.get('stormpathCachePort');
    }

    var cacheOptions = {
      store: app.get('stormpathCache'),
      connection: connection || {
        host: app.get('stormpathCacheHost'),
        port: app.get('stormpathCachePort'),
      },
      ttl: app.get('stormpathCacheTTL'),
      tti: app.get('stormpathCacheTTI'),
      options: app.get('stormpathCacheOptions'),
    };

    if (app.get('stormpathApiKeyId') && app.get('stormpathApiKeySecret')) {
      app.set('stormpathClient', new stormpath.Client({
        apiKey: new stormpath.ApiKey(
          app.get('stormpathApiKeyId'),
          app.get('stormpathApiKeySecret')
        ),
        cacheOptions: cacheOptions,
        userAgent: userAgent,
      }));
      next();
    } else if (app.get('stormpathApiKeyFile')) {
      stormpath.loadApiKey(app.get('stormpathApiKeyFile'), function(err, apiKey) {
        app.set('stormpathClient', new stormpath.Client({
          apiKey: apiKey,
          cacheOptions: cacheOptions,
          userAgent: userAgent,
        }));
        next();
      });
    }
  };
}


/**
 * Initialize the Stormpath application.
 *
 * @method
 * @private
 *
 * @param {Object} app - The express application.
 *
 * @return {Function} A function which accepts a callback.
 */
function initApplication(app) {
  return function(next) {
    app.get('stormpathClient').getApplication(app.get('stormpathApplication'), function(err, application) {
      if (err) {
        throw err;
      }

      app.set('stormpathApplication', application);
      next();
    });
  };
}


/**
 * Initialize the Stormpath middleware.
 *
 * @method
 *
 * @param {Object} app - The express application.
 * @param {object} opts - A JSON hash of user supplied options.
 *
 * @return {Function} An express middleware.
 */
module.exports.init = function(app, opts) {
  var router = express.Router();
  opts = opts || {};

  var stormpathMiddleware = function(req, res, next) {
    async.series([
      function(callback) {
        helpers.getUser(req, res, callback);
      }
    ], function() {
      next();
    });
  };

  var urlMiddleware = function(req, res, next) {
    res.locals.url = req.protocol + '://' + req.get('host');
    next();
  };

  async.series([
    helpers.initSettings(app, opts),
    helpers.checkSettings(app),
    initClient(app),
    initApplication(app),
  ]);

  // Parse the request body.
  router.use(bodyParser.urlencoded({ extended: true }));

  // Initialize session middleware.
  // If the application doesn't provide one, we'll use our own.
  var sessionMiddleware = app.get('stormpathSessionMiddleware');

  if (sessionMiddleware) {
    router.use(require('cookie-parser')());
    router.use(sessionMiddleware);
  } else {
    var session = require('client-sessions');

    router.use(session({
      cookieName: 'stormpathSession',
      requestKey: 'session',
      secret: app.get('stormpathSecretKey'),
      duration: app.get('stormpathSessionDuration'),
      cookie: {
        httpOnly: true,
        maxAge: app.get('stormpathSessionDuration'),
        secure: app.get('stormpathEnableHttps'),
      }
    }));
  }

  // Build routes.
  app.use('/', router);
  return stormpathMiddleware;
};

/**
 * Expose the `login` middleware.
 *
 * @property login
 */
module.exports.login = authentication.login;


/**
 * Expose the `loginRequired` middleware.
 *
 * @property loginRequired
 */
module.exports.loginRequired = authentication.loginRequired;


/**
 * Expose the `groupsRequired` middleware.
 *
 * @property groupsRequired
 */
module.exports.groupsRequired = authentication.groupsRequired;


/**
 * Expose the `apiAuthenticationRequired` middleware.
 *
 * @property apiAuthenticationRequired
 */
module.exports.apiAuthenticationRequired = authentication.apiAuthenticationRequired;


/**
 * Expose the `forgotPassword` middleware.
 *
 * @property forgotPassword
 */
module.exports.forgotPassword = authentication.forgot;

module.exports.forgotReset = authentication.forgotChange;