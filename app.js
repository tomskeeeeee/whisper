//Level 5 encryption - cookies and sessions using passport
require('dotenv').config();
const express = require("express");
const mongoose = require('mongoose');
const ejs = require('ejs');
// const md5 = require('md5');
const bcrypt = require('bcrypt');
const saltRounds = 10;
const _ = require("lodash");
const session = require('express-session');
const passport = require('passport');
const passportLocalMongoose = require('passport-local-mongoose');
const GoogleStrategy = require('passport-google-oauth20').Strategy;
const findOrCreate = require('mongoose-findorcreate');

const app = express();
app.use(express.json());
app.use(express.urlencoded({
  extended: true
}));
app.set('view engine', 'ejs');
app.use(express.static("public"));
//prepare to set up secure session
app.use(session({
  secret: 'The name of my dog is Rocky',
  resave: false,
  saveUninitialized: false
}));
//initialize passport and use it to set up session
app.use(passport.initialize());
app.use(passport.session());


mongoose.connect('mongodb://localhost:27017/userDB', {
  useNewUrlParser: true,
  useUnifiedTopology: true
});

const db = mongoose.connection;
db.on('error', console.error.bind(console, 'connection error:'));
db.once('open', function() {
  // we're connected!
  console.log("connected");
});
mongoose.set("useCreateIndex", true);

//remove mongoose encryption so we can use MD5 hashing
// const encrypt = require('mongoose-encryption');
//use encryption when defining the schema, not just a simple js object
const userSchema = new mongoose.Schema({
  email: String,
  password: String,
  googleId: String, //added when using Oath20 to auth using Google
  secrets: [String]
});
//add plug in so passwords can be hashed and salted and saved in DB
userSchema.plugin(passportLocalMongoose);
userSchema.plugin(findOrCreate);
//define secret long unguessable string to use for encryption algorith
// const secretPhrase = "Thisisareallylongunguessablesecretphrase";
//use the secret to encrypt using the Schema (BEFORE you define the model)
//don't want to encrypt entire database (usernanes also), just passwords
//could add more entries to encrypt within the arrow, separating with commas

const secretPhrase = process.env.SECRET_PHRASE;

const User = mongoose.model("User", userSchema);

passport.use(User.createStrategy());

// passport.serializeUser(User.serializeUser());
// passport.deserializeUser(User.deserializeUser());
// replaced these 2 lines with generic version below

passport.serializeUser(function(user, done) {
  done(null, user.id);
});

passport.deserializeUser(function(id, done) {
  User.findById(id, function(err, user) {
    done(err, user);
  });
});


passport.use(new GoogleStrategy({
    clientID: process.env.CLIENT_ID,
    clientSecret: process.env.CLIENT_SECRET,
    callbackURL: "http://localhost:3000/auth/google/secrets"
    //might need this for Google+
    //,userProfileURL:"https://www.googleapis.com/oath2/v3/userinfo"
  },
  //Google will send back accessToken - allows us to get data for the user
  //refreshToken - data acces lasts longer
  //profile - this contains their email,googleid, profile
  function(accessToken, refreshToken, profile, cb) {
    //user their google profile to either find that user or create one
    //if it does not exist
    //uses the npm package: mongoose-findorcreate
    console.log(profile);
    User.findOrCreate({ googleId: profile.id }, function (err, user) {
      //need to save googleId in our DB so we can find user next time
      //we added this field to our Schema, now it automatically saves it
      return cb(err, user);
    });
  }
));

app.get("/", function(req, res) {
  res.render("home");
});
//***********Login Route Actions *****//


app.route("/login")
  .get(function(req, res) {
    res.render("login");
  })
  .post(function(req, res) {
      let email = req.body.username;
      let password = req.body.password;
      const user = new User({
        username: email,
        password: password
      });
      // use passport to log this user in if authebticated
      req.login(user, function(err){
        if(err){
          console.log(err);
        }else{
          passport.authenticate("local")(req, res,function(){
            res.redirect("/secrets"); //store cookie, user is ok
          });

        }
      });
});

        //*****Register Route actions ********//
app.get("/register", function(req, res) {
    res.render("register");
  });

  app.post("/register", function(req, res) {
    //tap into the User model and use the register method on it
    //the register method comes from the passport-local-mongoose package
    //Its only because of the package taht we can avoid creating a new user,
    //saving our user and interacting with Mongoose directly
    //pass in username from HTML, password from HTML, get back a registered user!
        User.register({username: req.body.username}, req.body.password, function(err, user){
          if(err){
            console.log(err);
            res.redirect("/register");  //send back to try again
          }else{ //no errors, authenticate user using passport
            // use local authentication, only tirgger this callback if auth was a success
            passport.authenticate("local")(req, res, function(){
              //successfully set up cookie that saved a logged in session
              res.redirect("/secrets");
            });
          }
        });
      });

    //****************Secrets page routing************//
  app.get("/secrets", function(req, res){

User.find({"secrets":{$exists:true}}, function(err,foundUsers){
  if(foundUsers){ //some secrets exists, render secrets page
    //pass in variable with the foundUsers in it
    res.render("secrets", {usersWithSecrets: foundUsers});
  }
});


    //old code - don't need to check for auth, anybody can see this page
    // if(req.isAuthenticated()){ //already successfully logged in
    //   res.render("secrets");
    // }else{
    //   res.redirect("/login")
    // }
  });
  //***************Submit Page Routing ********//
  app.get("/submit", function(req, res){
    if(req.isAuthenticated()){ //already successfully logged in
      res.render("submit");
    }else{
      res.redirect("/login")
    }
  });

  app.post("/submit", function(req, res){
    const submittedSecret = req.body.secret;
    console.log(submittedSecret);
//console.log(req.user); //see the info saved by passport about this user
User.findById(req.user._id, function(err, foundUser){
  if(!err && foundUser){
    foundUser.secrets.push(submittedSecret);
    foundUser.save(function(){ //once save is complete,callback fun called
      console.log(req.user);//
    res.redirect("/secrets");
    });

  }
});
});

//******Logout Page Routing ***********//
app.get("/logout", function(req, res){
  //logout should delete cookies and return to login package
  //deauthenticate the user
  req.logout();
  res.redirect("/login");
})
//initiate authentication with Google
//Use google strategy, add a scoope
//already set up the google strategy
//should get pop up to sign in with google

app.get("/auth/google",
passport.authenticate("google", { scope:['profile']}));

//Need to let Google GET the page it is redirectiing to
//saves login session
//If we can authenicate locally now, send them to the secrets page
app.get("/auth/google/secrets",
  passport.authenticate('google', { failureRedirect: '/login' }),
  function(req, res) {
    // Successful authentication, redirect home.
    res.redirect("/secrets"); //secrets GET will check if authorized
  });






  app.listen(3000, function() {
    console.log("Server started on port 3000 ");
  });
