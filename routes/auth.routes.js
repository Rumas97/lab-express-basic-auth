const router = require("express").Router();
const bcrypt = require("bcryptjs");
const UserModel = require("../models/User.model");
let userInfo = {};

//GET Route for signup

router.get("/signup", (req, res) => {
  res.render("auth/signup");
});

router.post("/signup", (req, res, next) => {
  const { username, password } = req.body;
  if (!username || !password) {
    res.render("auth/signup", { msg: "Please fill out all the fields" });
    return;
  }
  if (!username.unique) {
    res.render("auth/signup", { msg: "Username taken" });
    return;
  }
  const salt = bcrypt.genSaltSync(12);
  const hash = bcrypt.hashSync(password, salt);
  UserModel.create({ username, password: hash })
    .then(() => {
      res.redirect("/");
    })
    .catch((err) => {
      next(err);
    });
});

//Routes for login

router.get("/signin", (req, res) => {
  res.render("auth/signin");
});

router.post("/signin", (req, res, next) => {
  const { username, password } = req.body;
  UserModel.findOne({ username })
    .then((response) => {
      if (!response) {
        res.render("auth/signin", {
          msg: "Username or password seems to be incorrect",
        });
      } else {
        bcrypt.compare(password, response.password).then((isMatching) => {
          //compare will return a true or a false
          if (isMatching) {
            req.session.userInfo = response;
            req.app.locals.isUserLoggedIn = true;
            res.redirect(`/main`);
          } else {
            res.render("auth/signin", {
              msg: "Username or password seems to be incorrect",
            });
          }
        });
      }
    })
    .catch((err) => {
      next(err);
    });
});

//Middleware
const authorize = (req, res, next) => {
  if (req.session.userInfo) {
    next();
  } else {
    res.redirect("/signin");
  }
};

router.get("/main", authorize, (req, res, next) => {
  const { username } = req.session.userInfo;
  res.render("main.hbs", { username });
});

router.get("/private", authorize, (req, res, next) => {
  const { username } = req.session.userInfo;
  res.render("private.hbs", { username });
});

module.exports = router;
