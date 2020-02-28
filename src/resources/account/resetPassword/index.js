const securityUtil = require('security.util');
const validate = require('middlewares/validate');
const userService = require('resources/user/user.service');

const validator = require('./validator');


/**
 * Updates user password, used in combination with forgotPassword
 */
const handler = async (ctx) => {
  const { userId, password } = ctx.validatedRequest.value;

  const passwordHash = await securityUtil.getHash(password);
  const user = await userService.findOneAndUpdate(
    { _id: userId },
    {
      $set: {
        passwordHash,
      },
      $unset: {
        resetPasswordToken: 1,
      },
    },
  );

  ctx.body = userService.getPublic(user);
};

module.exports.register = (router) => {
  router.put('/resetPassword', validate(validator), handler);
};
