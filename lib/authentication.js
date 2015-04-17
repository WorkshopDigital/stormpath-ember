'use strict';


var helpers = require('./helpers');
var stormpath = require('./stormpath');


/**
 * This callback, when called, will simply continue processing the HTTP
 * request.
 *
 * @callback nextCallback
 */


/**
 * Assert that a user is logged into an account before allowing the user to
 * continue.  If the user is not logged in, they will be redirected to the login
 * page.
 *
 * @method
 *
 * @param {Object} req - The http request.
 * @param {Object} res - The http response.
 * @param {nextCallback} next - The callback which is called to continue
 *   processing the request if the user is authenticated.
 */
module.exports.loginRequired = function(req, res, next) {
  if (!req.user) {
    res.json(401, {error: 'You are not logged in.'});
  } else {
    next();
  }
};


/**
 * Assert that a user is a member of one or more groups before allowing the user
 * to continue.  If the user is not logged in, or does not meet the group
 * requirements, they will be redirected to the login page.
 *
 * @method
 *
 * @param {String[]} groups - A list of groups to assert membership in.  Groups
 *   must be specified by group name.
 * @param {Boolean} [all=true] - Should we assert the user is a member of all groups,
 *   or just one?
 *
 * @returns {Function} Returns an express middleware which asserts a user's
 *   group membership, and only allows the user to continue if the assertions
 *   are true.
 */
module.exports.groupsRequired = function(groups, all) {
  all = all === false ? false : true;

  return function(req, res, next) {
    // Ensure the user is logged in.
    if (!req.user) {
      res.json(401, {error: 'You are not logged in.'});


    // If this user must be a member of all groups, we'll ensure that is the
    // case.
    } else {
      var done = groups.length;
      var safe = false;

      req.user.getGroups(function(err, grps) {
        if (err) {
          res.json(401, {error: err});

        } else {
          // Iterate through each group on the user's account, checking to see
          // whether or not it's one of the required groups.
          grps.each(function(group, c) {
            if (groups.indexOf(group.name) > -1) {
              if (!all || --done === 0) {
                safe = true;
                next();
              }
            }
            c();
          },
          // If we get here, it means the user didn't meet the requirements,
          // so we'll send them to the login page with the ?next querystring set.
          function() {
            if (!safe) {
              res.json(403, {error: "I'm sorry. You are not a member of this group."});
            }
          });
        }
      });
    }
  };
};


/**
 * Assert that a user has specified valid API credentials before allowing them
 * to continue.  If the user's credentials are invalid, a 401 will be returned
 * along with an appropriate error message.
 *
 * @method
 *
 * @param {Object} req - The http request.
 * @param {Object} res - The http response.
 * @param {nextCallback} next - The callback which is called to continue
 *   processing the request if the user is authenticated.
 */
module.exports.apiAuthenticationRequired = function(req, res, next) {
  if (!req.user) {
    res.json(401, { error: 'Invalid API credentials.' });
  } else {
    next();
  }
};

/**
 * Create a new Stomrpath user account, and render errors to the user if the
 * account couldn't be created for some reason.
 *
 * @method
 * @private
 *
 * @param {Object} req - The http request.
 * @param {Object} res - The http response.
 * @param {Object} form - The http form.
 *
 * @return {Function} Return a function which accepts an account hash and a
 *   callback.
 */
function createAccount(req, res, form) {
  var view = req.app.get('stormpathRegistrationView');

  return function(account, callback) {
    req.app.get('stormpathApplication').createAccount(account, function(err, account) {
      if (err) {
        helpers.render(view, res, { error: err.userMessage, form: form });
        callback(err);
      } else if (req.app.get('stormpathEnableAccountVerification') && account.status === 'UNVERIFIED') {
        helpers.render(req.app.get('stormpathAccountVerificationEmailSentView'), res, { email: account.email });
        callback();
      } else {
        req.session.user = account;
        res.locals.user = account;
        req.user = account;
        callback();
      }
    });
  };
}


/**
 * This controller logs in an existing user.  If there are any errors, an
 * error page is rendered.  If the process succeeds, the user will be logged in
 * and redirected.
 *
 * @method
 *
 * @param {Object} req - The http request.
 * @param {Object} res - The http response.
 */
module.exports.login = function(req, res, next) {
  if (req.user && req.app.get('stormpathEnableAutoLogin')) {
    var url = req.query.next || req.app.get('stormpathRedirectUrl');
    return res.json(401, {error: 'You are not logged in.'});
  }

  res.locals.app = req.app;
  //res.locals.csrfToken = req.csrfToken();

  req.app.get('stormpathApplication').authenticateAccount({
    username: req.body.username,
    password: req.body.password,
  }, function(err, result) {
    if (err) {
      res.json(401, { error: err.userMessage });
    } else {
      result.getAccount(function(err, account) {
        if (err) {
          res.json(401, { error: err.userMessage });
        } else {
          req.session.user = account;
          res.locals.user = account;
          req.user = account;

          next();
        }
      });
    }
  });
};


/**
 * This controller logs out an existing user, then redirects them to the
 * homepage.
 *
 * @method
 *
 * @param {Object} req - The http request.
 * @param {Object} res - The http response.
 */
module.exports.logout = function(req, res) {
  if (req.session) {
    req.session.destroy();
  }

  res.json({message: 'You have successfully logged out.'})
};



/**
 * This controller initializes the 'password reset' workflow for a user who has
 * forgotten his password.
 *
 * This will render a view, which prompts the user for their email address, then
 * sends a password reset email.
 *
 * The URL this controller is bound to, and the view used to render this page
 * can all be controlled via express-stormpath settings.
 *
 * @method
 *
 * @param {Object} req - The http request.
 * @param {Object} res - The http response.
 */
module.exports.forgot = function(req, res) {

  res.locals.app = req.app;

  req.app.get('stormpathApplication').sendPasswordResetEmail(req.body.username, function(err, token) {
    if (err) {
      res.json({ error: 'Our apologies, but we couldn&apos;t find that address.'});
    } else {
      res.json({ message: 'An email has been sent with instruction on how to complete your password reset request.'});
    }
  });  
};


/**
 * Allow a user to change his password.
 *
 * This can only happen if a user has reset their password, received the
 * password reset email, then clicked the link in the email which redirects them
 * to this controller.
 *
 * The URL this controller is bound to, and the view used to render this page
 * can all be controlled via express-stormpath settings.
 *
 * @method
 *
 * @param {Object} req - The http request.
 * @param {Object} res - The http response.
 */
module.exports.forgotChange = function(req, res) {

  res.locals.app = req.app;
  //res.locals.csrfToken = req.csrfToken();

  req.app.get('stormpathApplication').verifyPasswordResetToken(req.body.token, function(err, result) {
    if (err) {
      res.json({error: 'Your password could not be updated.'});
    } else {
      result.password = req.body.password;
      result.save(function(err, done) {
        if(err) {
          res.status(err.status).json({error: err.userMessage})
        } else {
          req.app.get('stormpathClient').getAccount('https://api.stormpath.com/v1/accounts/7dpwkme3CZX8Pxa95rZEO0', {expand: 'groups'}, function(err, account) {
            res.json({
              message: 'Hi '+account.givenName+', your password has been reset.',
              groups: account.groups
            });
          });
        }
      });
    }
  });

};


/**
 * Complete a user's account verification.
 *
 * This can only happen if a user has registered with the account verification
 * workflow enabled, and then clicked the link in their email which redirects
 * them to this controller.
 *
 * The URL this controller is bound to, and the view used to render this page
 * can all be controlled via express-stormpath settings.
 *
 * @method
 *
 * @param {Object} req - The http request.
 * @param {Object} res - The http response.
 */
module.exports.verificationComplete = function(req, res) {

  res.locals.app = req.app;

  req.app.get('stormpathClient').getCurrentTenant(function(err, tenant) {
    if (err) {
      res.send(400);
    } else {
      tenant.verifyAccountEmail(req.query.sptoken, function(err, account) {
        if (err) {
          res.send(400);
        } else {
          req.app.get('stormpathClient').getAccount(account.href, function(err, acc) {
            if (err) {
              res.send(500);
            } else {
              req.session.user = acc;
              res.locals.user = acc;
              req.user = acc;

              if (req.app.get('stormpathPostRegistrationHandler')) {
                req.app.get('stormpathPostRegistrationHandler')(req.user, res, function() {
                  helpers.render(req.app.get('stormpathAccountVerificationCompleteView'), res);
                });
              } else {
                helpers.render(req.app.get('stormpathAccountVerificationCompleteView'), res);
              }
            }
          });
        }
      });
    }
  });
};