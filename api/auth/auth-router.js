const router = require("express").Router();
const { checkUsernameExists, validateRoleName } = require('./auth-middleware');
const jwt = require("jsonwebtoken")
const { JWT_SECRET } = require("../secrets/index"); // use this secret!
const hasher = require("bcryptjs")

const {add, findBy} = require("../users/users-model")

router.post("/register", validateRoleName, async (req, res, next) => {
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

    let {body} = req

    const rounds = process.env.BCRYPT_ROUNDS || 8

    const hash = hasher.hashSync(body.password, rounds)

    body.password = hash

    try {
      const newUser = await add(body)
      res.status(201).json(newUser)
    } catch(err) {
      next(err)
    }

});


router.post("/login", checkUsernameExists, async (req, res, next) => {
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

    const {username, password} = req.body

    try {
      const userQuery = await findBy({username: username})
      if (userQuery && hasher.compareSync(password, userQuery.password)) {
        const token = tokenMaker(userQuery)
        res.status(200).json({
          message: `${userQuery.username} is back!`,
          token: token
        })
      } else {
        next({status: 401, message: 'invalid credentials'})
      }
    } catch(err) {
      next(err)
    }

});

const tokenMaker = user => {

  const payload = {
    subject: user.id,
    role_name: user.role_name,
    username: user.username
  }

  const options = {
    expiresIn: "1d"
  }

  return jwt.sign(payload, JWT_SECRET, options)

}

module.exports = router;
