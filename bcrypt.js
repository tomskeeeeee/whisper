require('dotenv').config();
const express = require("express");
const mongoose = require('mongoose');
const ejs = require('ejs');
// const md5 = require('md5');
const bcrypt = require('bcrypt');
const saltRounds = 10;
const _ = require("lodash");


const app = express();
app.use(express.json());
app.use(express.urlencoded({
  extended: true
}));
app.set('view engine', 'ejs');
app.use(express.static("public"));


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

//remove mongoose encryption so we can use MD5 hashing
// const encrypt = require('mongoose-encryption');
//use encryption when defining the schema, not just a simple js object
const userSchema = new mongoose.Schema({
  email: String,
  password: String
});
//define secret long unguessable string to use for encryption algorith
// const secretPhrase = "Thisisareallylongunguessablesecretphrase";
//use the secret to encrypt using the Schema (BEFORE you define the model)
//don't want to encrypt entire database (usernanes also), just passwords
//could add more entries to encrypt within the arrow, separating with commas

const secretPhrase = process.env.SECRET_PHRASE;
//remove this plugin so we can use MD5 hashing
// userSchema.plugin(encrypt, {secret: secretPhrase, encryptedFields: ["password"] });
const User = mongoose.model("User", userSchema);

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

      User.findOne({email: email}, function(err, foundUser) {
            if (foundUser) { //if username exists, check the password
              //check hashed stored (foundUser.password) pw with hashed login pw
              bcrypt.compare(password, foundUser.password, function(err, result) {
                if (result == true) { //passords match
                  res.render("secrets");
                } else {
                  res.send("User is not found. Check your username and password and try again");
                }
              })

             }
           })
         }
 		)
            //check if the email/username exits
            // User.findOne({email:email}, function(err, foundUser){
            //   console.log(foundUser.password);
            //
            //   //if username exists, check the password
            //   if(foundUser.password == password){
            //     res.render("secrets");  //username and password match!
            //   }else{
            //     res.send("User is not found. Check your username and password and try again");
            //   }
            // })



            //*****Register Route actions ********//
            app.route("/register")
              .get(function(req, res) {
                res.render("register");
              })
              .post(function(req, res) {
                //create user document
                let email = req.body.username;
                // let password = md5(req.body.password);

                bcrypt.hash(req.body.password, saltRounds, function(err, hash) {
                  if (!err) {
                    //generate new user using email and hashed pw
                    let newUser = new User({
                      email: email,
                      password: hash
                    });
                    newUser.save(function(err) {
                      if (err) {
                        console.log(err);
                      } else {
                        res.render("secrets");
                      }
                    });
                  } else {
                    res.send(err);
                  }
                });

              });









            app.listen(3000, function() {
              console.log("Server started on port 3000 ");
            });
