const express = require('express');
const router = express.Router();
const {check, validationResult} = require('express-validator');
const {
    asyncHandler,
    handleValidationErrors
} = require('./utils');
const bcrypt = require('bcryptjs');
const db = require('../db/models');
const {getUserToken, requireAuth} = require('../auth');

const validateUsername =
    check("username")
    .exists({
        checkFalsy: true
    })
    .withMessage("Please provide a username");

const validateEmailAndPassword = [
    check("email")
    .exists({
        checkFalsy: true
    })
    .isEmail()
    .withMessage("Please provide a valid email."),
    check("password")
    .exists({
        checkFalsy: true
    })
    .withMessage("Please provide a password."),
];

const validateCreateUser = [
    validateUsername,
    ...validateEmailAndPassword,
    handleValidationErrors
]


//sign up
router.post(
  "/",
  validateCreateUser,
  asyncHandler(async (req, res) => {
    console.log(req.body);
    const { email, password, username, firstName, lastName } = req.body;
    const hashedPassword = await bcrypt.hash(password, 10);
    console.log(
      { email, password, username, firstName, lastName },
      hashedPassword
    );
    const user = await db.User.build({
      email,
      hashedPassword,
      username,
      firstName,
      lastName,
      createdAt: new Date(),
      updatedAt: new Date(),
    });
    const validatorErrors = validationResult(req)
    console.log(validatorErrors);

    await user.save();

    console.log("USER POSTED");
    const token = getUserToken(user);

    res.status(201).json({ user: { id: user.id }, token });
  })
);

//log in
router.post(
  "/token",
  asyncHandler(async (req, res, next) => {
    const { email, password } = req.body;
    try {
      const user = await db.User.findOne({ where: { email: email } });
      const isPassword = await bcrypt.compare(
        password,
        user.hashedPassword.toString()
      );
      console.log(user);
      if (!isPassword) {
        const err = new Error("Login failed");
        err.status = 401;
        err.title = "Login failed";
        err.errors = ["The provided credentials were invalid."];
        return next(err);
      }
      const token = getUserToken(user);
      res.json({ token, user: { id: user.id } });
    } catch (e) {
      const err = new Error("Login failed");
      err.status = 401;
      err.title = "Login failed";
      err.errors = ["The provided credentials were invalid."];
      return next(err);
    }
  })
);

//get user profile page
router.get("/:id(\\d+)", requireAuth, asyncHandler(async (req, res) => {
    const userId = parseInt(req.params.id, 10);
    try{
        const user = await db.User.findByPk(userId);
        const checkins = await db.Checkin.findAll({
          where: { userId: userId },
          include: [ db.User,
            {
              model: db.Beer,
              include: db.Brewery,
            },
          ],
        });
        res.json({ user, checkins });
    }catch(err){console.log(err)}

}));


//update user profile info
router.put("/:id(\\d+)", requireAuth, asyncHandler(async (req, res) => {
    const userId = parseInt(req.params.id, 10);
    try{
        const user = await db.User.findByPk(userId);
        const {username, firstName, lastName, aboutYou, email} = req.body;
        await user.update({ username, firstName, lastName, aboutYou, email, updatedAt: new Date()});
        res.json({username, firstName, lastName, aboutYou, email, message:"Your account information has been successfully updated."});
    } catch(err){
        console.error(err);
        res.message = err;
        res.status(500).send();
    }
}));


//change password
router.put("/:id(\\d+)/password", requireAuth, asyncHandler(async (req, res) => {
    const userId = parseInt(req.params.id, 10);
    try{
        const user = await db.User.findByPk(userId);
        const {oldPassword, newPassword} = req.body;
        const isPassword = await bcrypt.compare(oldPassword, user.hashedPassword.toString());
        if(isPassword){
            const hashedPassword = await bcrypt.hash(newPassword, 10);
            await user.update({hashedPassword});
            const success = true
            res.json({user, message: "Your password has been successfully updated.", success});
        } else{
            const success = false;
            res.json({
              user,
              message: "There was a problem updating your password. Please try again.",
              success,
            });
        }
    } catch(err){
        console.error(err);
        res.message = err;
        res.status(500).send();
    }
}));

//delete account
router.delete("/:id(\\d+)/delete", requireAuth, asyncHandler(async (req, res) => {
    const userId = parseInt(req.params.id, 10);
    try{

        const { deletePassword, confirmDeletePassword } = req.body;
        if(deletePassword !== confirmDeletePassword){
            const success = false;
            res.json({
              user,
              message: "It looks like yor passwords didn't match. Please try again",
              success,
            });
        }
        const user = await db.User.findByPk(userId);
        const isPassword = await bcrypt.compare(deletePassword, user.hashedPassword.toString());
        if(isPassword){
            await db.Checkin.destroy({where: {
                userId: userId
            }})
            await db.List.destroy({where: {
                userId: userId
            }})
            await db.LikedBrewery.destroy({
              where: {
                userId: userId,
              },
            });
            await user.destroy();
            const success = true;
            res.json({user, message: "The user and all associated data has successfully been deleted.", success});
        } else{
            const success = false;
            res.json({
              user,
              message: "It seems you didn't enter the correct password. Please try again",
              success,
            });
        }
    } catch(err){
        console.error(err);
        res.message = err;
        res.status(500).send();
    }
}));



module.exports = router;
