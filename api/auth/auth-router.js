const router = require("express").Router();
const { checkUsernameExists, validateRoleName, generateToken } = require('./auth-middleware');
const bcrypt = require('bcryptjs');
// eslint-disable-next-line
const jwt = require('jsonwebtoken');
// eslint-disable-next-line
const { JWT_SECRET } = require("../secrets"); // use this secret!

const User = require('../users/users-model');

router.post("/register", validateRoleName, (req, res, next) => {
  /**
    [POST] /api/auth/register { "username": "anna", "password": "1234", "role_name": "angel" }

    response:
    status 201
    {
      "user"_id: 3,
      "username": "anna",
      "role_name": "angel"
    }
   */
    User.add(req.body)
      .then(registered => {
        res.status(201).json({ registered });
      })
      .catch(next)
});


router.post("/login", checkUsernameExists, (req, res, next) => {
  /**
    [POST] /api/auth/login { "username": "sue", "password": "1234" }

    response:
    status 200
    {
      "message": "sue is back!",
      "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.ETC.ETC"
    }

    The token must expire in one day, and must provide the following information
    in its payload:

    {
      "subject"  : 1       // the user_id of the authenticated user
      "username" : "bob"   // the username of the authenticated user
      "role_name": "admin" // the role of the authenticated user
    }
   */
    const { username, password } = req.body;

    User.findBy(username)
      .first()
      .then(user => {
        if (user && bcrypt.compareSync(password, user.password)) {
          const token = generateToken(user);

          res.status(200).json({
            message: `${user.username} is back!`,
            token: token
          });
        } else {
          res.status(401).json({ message: 'Invalid credentials' });
        }
      })
      .catch(next);
});

module.exports = router;
