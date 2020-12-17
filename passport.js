require('dotenv').config();
const express = require("express");
const bodyParser = require("body-parser");
const ejs = require("ejs");
const mongoose = require('mongoose');
const app = express();
const session = require('express-session');
const passport = require('passport');
const passportLocalMongoose = require('passport-local-mongoose');
const GoogleStrategy = require('passport-google-oauth20').Strategy;
const FacebookStrategy = require('passport-facebook').Strategy;
const findOrCreate = require('mongoose-findorcreate');
app.set('view engine', 'ejs');

app.use(bodyParser.urlencoded({extended: true}));
app.use(express.static("public"));

app.use(session({
  secret: "Our little secret.",
  resave: false,
  saveUninitialized: false
}));

app.use(passport.initialize());//initialize passport
app.use(passport.session());//initialize session

mongoose.connect("mongodb://localhost:27017/userDB", {useNewUrlParser: true, useUnifiedTopology: true});
mongoose.set("useCreateIndex", true);

const userSchema = new mongoose.Schema({//database schema
  email: String,
  password: String,
  googleId: String,
  facebookId: String,
  secret: String
});

userSchema.plugin(passportLocalMongoose);
userSchema.plugin(findOrCreate);
//userSchema.plugin(encrypt, { secret: process.env.SECRET, encryptedFields: ['password'] });

const User = new mongoose.model("User", userSchema);
passport.use(User.createStrategy());

passport.serializeUser(function(user, done) { //when session is created it creates a cookie with user credentials
  done(null, user.id);
});

passport.deserializeUser(function(id, done) { //when user log out or closes the browser the cookie gets destroyed
  User.findById(id, function(err, user) {
    done(err, user);
  });
});

//create .env file and save all the user credentials in it and access it using process.env.CLIENT_ID
passport.use(new GoogleStrategy({ //OAuth passport code for google Authentication
    clientID: process.env.CLIENT_ID, //id from .env file you get from google
    clientSecret: process.env.CLIENT_SECRET, //secret from .env file you get from google
    callbackURL: "http://localhost:3000/auth/google/secrets",
    userProfileURL: "https://www.googleapis.com/oauth2/v3/userinfo"
  },
  function(accessToken, refreshToken, profile, cb) {
    console.log(profile);
    User.findOrCreate({ googleId: profile.id }, function (err, user) {
      return cb(err, user);
    });
  }
));

passport.use(new FacebookStrategy({  //OAuth passport code for facebook Authentication
    clientID: process.env.FACEBOOK_APP_ID,
    clientSecret: process.env.FACEBOOK_APP_SECRET,
    callbackURL: "http://localhost:3000/auth/facebook/secrets"
  },
  function(accessToken, refreshToken, profile, cb) {
    User.findOrCreate({ facebookId: profile.id }, function (err, user) {
      return cb(err, user);
    });
  }
));

app.get("/auth/google",//if button is clicked passport checks if the user is authenticated to google in the cookie
  passport.authenticate('google', { scope: ["profile"] })); //href of the button which goes to google page

  app.get("/auth/google/secrets", //redirect link you give to google credentials
    passport.authenticate('google', { failureRedirect: '/login' }),
    function(req, res) {
      // Successful authentication, redirect secrets.
      res.redirect("/secrets");
    });

    app.get('/auth/facebook',//if button is clicked passport checks if the user is authenticated to google in the cookie
  passport.authenticate('facebook'));

app.get('/auth/facebook/secrets', //redirect link you give to facebook credentials
  passport.authenticate('facebook', { failureRedirect: '/login' }),
  function(req, res) {
    // Successful authentication, redirect secrets.
    res.redirect('/secrets');
  });



  app.get("/secrets", function(req, res){ //if user goes to secrets page all the users secrets will be displayed without Authentication
    User.find({"secret": {$ne: null}}, function(err, foundUsers){ //search all the user for secrets and render on secrets page
      if(err){
        console.log(err);
      }else{
        res.render("secrets", {usersWithSecrets: foundUsers});
      }
    });
  });

  app.post("/register", function(req, res){ //if we get post request from the user
    User.register({username: req.body.username}, req.body.password, function(err, user){ //passport function register() to add username and and password(in hash) gets stored in the database
      if(err){
        res.redirect("/register");
      }else{
        passport.authenticate("local")(req, res, function(){
          res.redirect("/secrets"); //if user is registered redirect to secrets
        });
      }
    });

  });

  //bcrypt hash the password with no. of rounds of salt you add in parameters
  // bcrypt.hash(req.body.password, saltRounds,function(err, hash){
  //   const newUser =new User({
  //     email: req.body.username,
  //     password: hash
  //   });
  //   newUser.save(function(err){
  //     if(err){
  //       console.log(err);
  //     }else{
  //       res.render("secrets");
  //     }
  //   });
  // });

  app.post("/login", function(req, res){
  const user =new User({ //saves username and password to the database
    username:req.body.username,
    password:req.body.password
  });
    req.login(user, function(err){ //res.login is passport function it checks the username and password and authenticates the user
      if(err){
        console.log(err);
      }else{
        passport.authenticate("local")(req, res, function(){ //if authenticated redirectto secrets page
          res.redirect("/secrets");
        });
      }
    });

    //bcrypt function for authentication
    // const username = req.body.username;
    // const password = req.body.password;
    //
    // User.findOne({email: username}, function(err, foundUser){
    //   if(err){
    //     console.log(err);
    //   }else{
    //     if(foundUser){
    //       bcrypt.compare(password, foundUser.password, function(err, result){
    //         if(result===true){
    //           res.render("secrets");
    //         }
    //       });
    //
    //
    //       }
    //     }
    //
    // });
  });

  app.get("/submit", function(req, res){ //if authenticated in cookie and compare to database go to submit page
    if (req.isAuthenticated()){
      res.render("submit");
    }else{
      res.redirect("/login");
    }
  });

  app.post("/submit", function(req, res){ //if secret is submitted
    const submittedSecret = req.body.secret;
    console.log(req.user.id);
    User.findById(req.user.id, function(err, foundUser){//checks the user in the database
      if(err){
        console.log(err);
      }else{
        if(foundUser){//if user is found
          foundUser.secret = submittedSecret; //submitted secret gets in the database of the user who post it
          foundUser.save(function(){ //save the secret in the users data
            res.redirect("/secrets"); // once posted redirect to secrets page
          });
        }
      }
    });
  });

  app.get("/logout", function(req, res){
    req.logout(); //passport function which logout the page and clear the session(cookie)
    res.redirect("/"); //redirect to home page
  });

  app.listen(3000, function() {
    console.log("Server started on port 3000");
  });
