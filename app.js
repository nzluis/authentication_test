const express = require('express')
const path = require("path")
const session = require("express-session")
const passport = require("passport")
const LocalStrategy = require("passport-local").Strategy
const mongoose = require("mongoose")
const Schema = mongoose.Schema
const bcrypt = require('bcryptjs');
const dotenv = require('dotenv').config()

const mongoDb = process.env.DATABASE_URL
mongoose.connect(mongoDb, { useUnifiedTopology: true, useNewUrlParser: true })
const db = mongoose.connection
db.on("error", console.error.bind(console, "mongo connection error"))

const User = mongoose.model(
    "User",
    new Schema({
        username: { type: String, required: true },
        password: { type: String, required: true }
    })
)

const app = express()
app.set("views", __dirname)
app.set("view engine", "ejs")

app.use(session({ secret: "cats", resave: false, saveUninitialized: true }))

passport.use(
    new LocalStrategy((username, password, done) => {
      User.findOne({ username: username }).then(user => {
        if (!user) {
          return done(null, false, { message: "Incorrect username" });
        }
        bcrypt.compare(password, user.password, (err, res) => {
            if (res) {
              // passwords match! log user in
              return done(null, user)
            } else {
              // passwords do not match!
              console.log(err)
              return done(null, false, { message: "Incorrect password" })
            }
          })
      }).catch(err => {
        done(err)
      });
    })
  );

passport.serializeUser(function(user, cb) {
    process.nextTick(function() {
        cb(null, {id: user.id, username: user.username});
    });
});

passport.deserializeUser(function(user, cb) {
    process.nextTick(function() {
        return cb(null, user);
    });
});

app.use(passport.initialize())
app.use(passport.session())
app.use(express.urlencoded({ extended: false }))

app.get("/", (req, res) => {
    res.render("index", { user: req.user });
})

app.get("/sign-up", (req, res) => res.render("sign-up-form"));

app.post("/sign-up", (req, res) => {
    bcrypt.hash(req.body.password, 10, (err, hashedPassword) => {
        if(err){
        // if err, do something
            console.log(err)
        } else {
        // otherwise, store hashedPassword in DB
            const user = new User({
                username: req.body.username,
                password: hashedPassword
              }).save().then(()=>{
                  res.redirect("/");
              }).catch((err)=>{
                  console.log(err);
              })
        }
      });
    
  });

app.get("/log-out", (req, res, next) => {
    req.logout(function (err) {
      if (err) {
        return next(err);
      }
      res.redirect("/");
    });
});

app.post(
    "/log-in",
    passport.authenticate("local", {
      successRedirect: "/",
      failureRedirect: "/"
    })
);

app.listen(3000, () => console.log("app listening on port 3000!"))