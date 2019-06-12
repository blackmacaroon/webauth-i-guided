const express = require("express");
const helmet = require("helmet");
const cors = require("cors");
const bcrypt = require("bcryptjs");

const db = require("./database/dbConfig.js");
const Users = require("./users/users-model.js");

const server = express();

server.use(helmet());
server.use(express.json());
server.use(cors());

server.get("/", (req, res) => {
  res.send("It's alive!");
});

server.post("/api/register", (req, res) => {
  let user = req.body;
  // hash the password when it's created
  const hash = bcrypt.hashSync(user.password, 12); // password gets rehashed 2 to the 12th times
  //replace user.password as the hash
  user.password = hash;
  Users.add(user)
    .then(saved => {
      res.status(201).json(saved);
    })
    .catch(error => {
      res.status(500).json(error);
    });
});

server.post("/api/login", (req, res) => {
  let { username, password } = req.body;

  Users.findBy({ username })
    .first()
    .then(user => {
      if (user && bcrypt.compareSync(password, user.password)) {
        res.status(200).json({ message: `Welcome ${user.username}!` });
      } else {
        res.status(401).json({ message: "Invalid Credentials" });
      }
    })
    .catch(error => {
      res.status(500).json(error);
    });
});

server.get("/api/users", restricted, (req, res) => {
  Users.find()
    .then(users => {
      res.json(users);
    })
    .catch(err => res.send(err));
});

//middleware
function restricted(req, res, next) {
  //read username and password from the headers and verify them
  const { username, password } = req.headers;
  if (username && password) {
    //read credentials from the headers
    //find user in db
    Users.findBy({ username })
      .first()
      .then(user => {
        //check that the passwords match
        if (user && bcrypt.compareSync(password, user.password)) {
          next();
        } else {
          // if passwords don't match. the request gets bounced with a 401
          res.status(401).json({ message: "Invalid Credentials" });
        }
      })
      .catch(error => {
        res.status(500).json(error);
      });
  } else {
    //if I don't find the user, the request gets bounced with a 401
    res.status(400).json({ message: "Please provide credentials" });
  }
}

const port = process.env.PORT || 5000;
server.listen(port, () => console.log(`\n** Running on port ${port} **\n`));
