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
  password: String
});
//add plug in so passwords can be hashed and salted and saved in DB
userSchema.plugin(passportLocalMongoose);
//define secret long unguessable string to use for encryption algorith
// const secretPhrase = "Thisisareallylongunguessablesecretphrase";
//use the secret to encrypt using the Schema (BEFORE you define the model)
//don't want to encrypt entire database (usernanes also), just passwords
//could add more entries to encrypt within the arrow, separating with commas

const secretPhrase = process.env.SECRET_PHRASE;

const User = mongoose.model("User", userSchema);

passport.use(User.createStrategy());

passport.serializeUser(User.serializeUser());
passport.deserializeUser(User.deserializeUser());

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
        if(req.isAuthenticated()){ //already successfully logged in
          res.render("secrets");
        }else{
          res.redirect("/login")
        }
      });


app.get("/logout", function(req, res){
  //logout should delete cookies and return to login package
  //deauthenticate the user
  req.logout();
  res.redirect("/login");
})









            app.listen(3000, function() {
              console.log("Server started on port 3000 ");
            });
