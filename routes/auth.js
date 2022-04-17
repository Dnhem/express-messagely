const express = require("express");
const app = require("../app");
const router = new express.Router();
const ExpressError = require("../expressError");
const User = require("../models/user");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const { SECRET_KEY } = require("../config");
/** POST /login - login: {username, password} => {token}
 *
 * Make sure to update their last-login!
 *
 **/

router.post("/login", async (req, res, next) => {
  try {
    const { username, password } = req.body;
    if (!username || !password) {
      throw new ExpressError("Username/Password required", 400);
    }
    const authenticated = await User.authenticate(username, password);
    if (authenticated) {
      let token = jwt.sign({ username }, SECRET_KEY);
      return res.json({ msg: "Logged in.", token });
    }
    throw new ExpressError("Incorrect username/password", 400);
  } catch (e) {
    return next(e);
  }
});

/** POST /register - register user: registers, logs in, and returns token.
 *
 * {username, password, first_name, last_name, phone} => {token}.
 *
 *  Make sure to update their last-login!
 */

router.post("/register", async (req, res, next) => {
  try {
    let { username } = await User.register(req.body);
    let token = jwt.sign({ username }, SECRET_KEY);
    User.updateLoginTimestamp(username);
    return res.json({ msg: "Success.", token });
  } catch (e) {
    return next(e);
  }
});

module.exports = router;
