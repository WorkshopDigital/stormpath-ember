'use strict';


var async = require('async');
var helpers = require('./helpers');


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
    return res.redirect(302, url);
  }

  res.locals.app = req.app;
  res.locals.csrfToken = req.csrfToken();

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

  res.redirect(req.app.get('stormpathPostLogoutRedirectUrl'));
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
  var view = req.app.get('stormpathForgotPasswordView');

  res.locals.app = req.app;
  res.locals.csrfToken = req.csrfToken();

  forms.forgotPasswordForm.handle(req, {
    // If we get here, it means the user is submitting a password reset
    // request, so we should attempt to send the user a password reset email.
    success: function(form) {
      req.app.get('stormpathApplication').sendPasswordResetEmail(form.data.email, function(err, token) {
        if (err) {
          helpers.render(view, res, { error: 'Invalid email address.', form: form });
        } else {
          res.redirect(req.app.get('stormpathPostForgotPasswordRedirectUrl'));
        }
      });
    },

    // If we get here, it means the user didn't supply required form fields.
    error: function(form) {
      var formErrors = helpers.collectFormErrors(form);
      helpers.render(view, res, { form: form, formErrors: formErrors });
    },

    // If we get here, it means the user is doing a simple GET request, so we
    // should just render the forgot password template.
    empty: function(form) {
      helpers.render(view, res, { form: form });
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
  var view = req.app.get('stormpathForgotPasswordChangeView');

  res.locals.app = req.app;
  res.locals.csrfToken = req.csrfToken();

  req.app.get('stormpathApplication').verifyPasswordResetToken(req.query.sptoken, function(err, account) {
    if (err) {
      res.send(400);
    } else {
      forms.changePasswordForm.handle(req, {
        // If we get here, it means the user is submitting a password change
        // request, so we should attempt to change the user's password.
        success: function(form) {
          if (form.data.password !== form.data.passwordAgain) {
            helpers.render(view, res, { error: 'Passwords do not match.', form: form });
          } else {
            account.password = form.data.password;
            account.save(function(err, done) {
              if (err) {
                helpers.render(view, res, { error: err.userMessage, form: form });
              } else {
                res.redirect(req.app.get('stormpathPostForgotPasswordChangeRedirectUrl'));                
              }
            })
          }
        },

        // If we get here, it means the user didn't supply required form fields.
        error: function(form) {
          // Special case: if the user is being redirected to this page for the
          // first time, don't display any error.
          if (form.data && !form.data.password && !form.data.passwordAgain) {
            helpers.render(view, res, { form: form });
          } else {
            var formErrors = helpers.collectFormErrors(form);
            helpers.render(view, res, { form: form, formErrors: formErrors });
          }
        },

        // If we get here, it means the user is doing a simple GET request, so we
        // should just render the forgot password template.
        empty: function(form) {
          helpers.render(view, res, { form: form });
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
  var view = req.app.get('stormpathAccountVerificationCompleteView');

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