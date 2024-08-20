'use strict'
 
//jshint esversion:6
 
// Required Packages
 
require("dotenv").config()
const express = require('express');
const bodyParser = require('body-parser');
const ejs = require('ejs');
const mongoose = require('mongoose');
 
// Mongoose Encryption Package
// const encrypt = require('mongoose-encryption'); // MONGOOSE ENCRYPTION
 
// MD5 Package
// const md5 = require('md5'); // MD5 ENCRYPTION
 
// BCRYPT Package and OptionsFile
// const bcrypt = require('bcrypt'); HASHING + SALTING
// const saltRounds = 10;
 
// Passport Package/Express-Sessions/PassportLocalMongoose
const session = require('express-session');
const passport = require('passport');
const passportLocalMongoose = require("passport-local-mongoose");
 
// OAuth
const GoogleStrategy = require('passport-google-oauth20').Strategy;
 
// FindOrCreate function for OAuth
const findOrCreate = require("mongoose-findorcreate")
 
// Initializing Express, EJS and BodyParser
 
const app = express();
 
app.use(express.static("public"));
app.set('view engine', 'ejs');
app.use(bodyParser.urlencoded({ extended: true }));
 
// Initialize Express-Session
 
app.use(session({
    secret: "AnotherBigAssSecret.",
    resave: false,
    saveUninitialized: true,
    cookie: {}
}));
 
// Initialize Passport
 
app.use(passport.initialize());
app.use(passport.session());
 
// MongoDB
 
main().catch(err => console.log(err));
 
async function main() {
  await mongoose.connect('mongodb://localhost:27017/userDB', {useNewUrlParser: true})};
 
// MongoDB Schema
 
const userSchema = new mongoose.Schema({
    email: String,
    password: String,
    googleId: String,
    secret: String
});
 
// PassportLocal plugin (similar to mongoose-encryption)
 
userSchema.plugin(passportLocalMongoose);
userSchema.plugin(findOrCreate);
 
// ENCRYPTING using mongoose.encryption
// const secret = process.env.SECRET;
// userSchema.plugin(encrypt, {secret: process.env.SECRET, encryptedFields: ["password"]});
 
// HASHING using md5
 
// use md5 package, add md5 function at the generation of the password and reading the password at login
 
// SALTING and HASHING using bcrypt
 
// use bcrypt methods in register/login pages
 
// MongoDB Model
 
const User = new mongoose.model("User", userSchema);
 
// Initializing and using passport-local-mongoose
 
// passport.use(User.createStrategy());
// passport.serializeUser(User.serializeUser());
// passport.deserializeUser(User.deserializeUser());
 
// Initializing strategy for OAuth
 
passport.use(User.createStrategy());
passport.serializeUser(function(user,done) {
    done(null, user);
});
passport.deserializeUser(async function(id, done) {
    let err, user
   try { user = await User.findById(id).exec();
    } catch (e) {
        err = e;
    };
    return done(err, user);
});
 
// OAuth
 
passport.use(new GoogleStrategy({
    clientID: process.env.CLIENT_ID,
    clientSecret: process.env.CLIENT_SECRET,
    callbackURL: "http://localhost:3000/auth/google/secrets",
    userProfileURL: "https://www.googleapis.com/oauth2/v3/userinfo"
  },
  function(accessToken, refreshToken, profile, cb) {
    User.findOrCreate({ googleId: profile.id }, function (err, user) {
      return cb(err, user);
    });
  }
));
 
// APP MAIN ROUTES
 
app.get('/', (req, res) => res.render("home"));
 
app.get("/auth/google", passport.authenticate("google", { scope: ["profile"] }));
 
app.get('/auth/google/secrets', 
  passport.authenticate('google', { failureRedirect: "/login" }),
  function(req, res) {
    res.redirect('/secrets');
  });
 
app.get('/login', (req, res) => res.render("login"));
 
app.get('/register', (req, res) => res.render("register"));
 
// LOGOUT ROUTE
 
app.get('/logout', (req, res, next) => {
    req.logout(function(err){
        if (err) {
            return next(err);
        }
        res.redirect("/");
    });
});
 
// Secrets page access when the session exists
 
app.get("/secrets", (req, res) => {
    User.find({"secret": {$ne: null}}).then(foundUsers => {
        res.render("secrets", {usersWithSecrets: foundUsers})
    }).catch(err => console.log(err));
});
 
// POST ROUTES
 
app.post("/register", (req, res) => {
 
    User.register({username: req.body.username}, req.body.password, function (err, user) {
        if (err) {
            console.log(err);
            res.redirect("/register")
        } else {
            passport.authenticate("local")(req, res, function(){
                res.redirect("/secrets");
            })
        }
    })
 
    // BCRYPT 
 
    // bcrypt.hash(req.body.password, saltRounds, function(err, hash) {
    //     const newUser = new User({
    //         email: req.body.username,
    //         password: hash
    //     });
    
    //     newUser.save().then(() => res.render("secrets")).catch((err) => console.log(err));
    // });
 
    // Mongoose Encryption and MD5
 
    // const newUser = new User({
    //     email: req.body.username,
    //     password: md5(req.body.password) // using md5 for password hashing
    // });
 
    // newUser.save().then(() => res.render("secrets")).catch((err) => console.log(err));
 
});
 
app.post("/login", async (req, res) => {
 
    // Login Form Data
 
    const user = new User({
        username: req.body.username,
        password: req.body.password
    });
 
    req.login(user, function (err) {
        if (err) {
            console.log("Login error log:", err);
            return;
        } else {
            passport.authenticate("local")(req, res, () => {
                res.redirect("/secrets");
        })};
    });
 
    // BCRYPT, MD5 and Mongoose Encryption
 
    // const username = req.body.username;
    // const password = req.body.password;
    // // const password = md5(req.body.password); //md5 check
 
 
    // User.findOne({ email: username}).then(foundUser => {
    //     if(foundUser) {
    //         bcrypt.compare(password, foundUser.password, function(err, result) {
    //             if (result === true) {
    //             res.render("secrets")
    //             }
    //         });
    //     }
    // }).catch(err => console.log(err));
});
 
app.route("/submit")
    .get((req, res) => {
        if (req.isAuthenticated()) {
            res.render("submit");
            return;
        }
        res.redirect("/login");
    })
    .post(async (req, res) => {
        if(req.isAuthenticated()){
            const submittedSecret = req.body.secret;
            const user = await User.findById(req.user._id).exec();
            user.secret = submittedSecret;
            await user.save().then(() => res.redirect("/secrets"));
            return;
        }
        res.redirect("/login");
    });
 
app.listen(3000, function(){
    console.log('Server started listening on port 3000.');
});