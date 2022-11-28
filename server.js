const express = require("express");
const app = express();
const mysql = require("mysql");
const cors = require("cors");
const bcrypt = require("bcryptjs");
const saltRounds = 10;
const jwt = require("jsonwebtoken");
const e = require("express");
require("dotenv").config();
const nodemailer = require('nodemailer')
const crypto = require('crypto')

app.use(express.json());
app.use(cors());

// const db = mysql.createConnection({
//     user: 'root',
//     host: 'localhost',
//     password: 'password',
//     database: 'licenta',
// });

// const db = mysql.createPool({
//   user: "bd15dc91576544",
//   host: "eu-cdbr-west-03.cleardb.net",
//   password: "f4c3c981",
//   database: "heroku_97ce68b7de834ec",
// });

const db = mysql.createPool({
  user: "root",
  host: "containers-us-west-134.railway.app",
  password: "7HFSnQhZiOHeXo1feOZG",
  port : "6849",
  database: "railway",
});


//mail sender details
var transporter = nodemailer.createTransport({
  service: 'gmail',
  auth: {
    user: 'leagueofquizz@gmail.com',
    pass: 'ajvfiamllkfbbuzm'
  },
  tls:{
    rejectUnauthorized: false
  }
})

app.post("/register", (req, res) => {
  const username = req.body.username;
  const password = req.body.password;
  const email = req.body.email;

  bcrypt.hash(password, saltRounds, (err, hash) => {
    if (err) {
      console.log(err);
    }

    db.query(
      "SELECT * FROM users WHERE username = ? OR email = ?;",
      [username, email],
      (err, result) => {
        if (err) {
          console.log(err);
        }
        if (result.length > 0) {
          res.json({
            type: "error",
            message: "Register failed",
            description: "Email or username already exists",
          });
        } else {
          db.query(
            "SELECT pfp_name FROM profile_picture ORDER BY RAND() LIMIT 1;",
            (err, result2) => {
              if (err) {
                console.log(err);
              } else {
                let emailToken = crypto.randomBytes(32).toString('hex');
                db.query(
                  "INSERT INTO users (email, username, password, pfp, email_token) VALUES (?,?,?,?,?)",
                  [email, username, hash, result2[0].pfp_name, emailToken],
                  (err, result) => {
                    if (err) {
                      console.log(err);
                    } else {
                      //send verification mail
                      var mailOptions = {
                        from: ' "Verify your email" <leagueofquizz@gmail.com>',
                        to : email,
                        subject: 'LeagueOfQuiz Verify your email',
                        html:`<h2> ${username}!  Thanks for registering on our site</h2>
                              <h4>Please verify your mail</h4>
                              <a href="http://${req.headers.host}/user/verify-email?token=${emailToken}">verify your email</a>`
                      }

                      //sending mail
                      transporter.sendMail(mailOptions, function(error, info){
                        if(error)
                          console.log(error)
                        else
                        console.log("Verification email is sent to your gmail account")
                      })
                      res.json({
                        type: "success",
                        message: "Account successfully registered",
                        description: "",
                      });
                    }
                  }
                );
              }
            }
          );
        }
      }
    );
  });
});

const verifyJWT = (req, res, next) => {
  let token = req.headers["x-access-token"];
  if(token === undefined){
    token = req.body.token
  }
  if (!token) return res.json({ error: "User not logged in!" });

  try {
    const validToken = jwt.verify(token, "licentaSecret");
    req.user = validToken;
    if (validToken) {
      console.log(validToken);
      return next();
    }
  } catch (err) {
    return res.json({ error: err });
  }
};

app.get("/isUserAuth", verifyJWT, (req, res) => {
  db.query(
    "SELECT src FROM profile_picture WHERE pfp_name = (SELECT pfp FROM users WHERE id = ?)",
    req.user.id,
    (err, result) => {
      if (err) {
        console.log(err);
      } else {
        res.json({ user: req.user, result: result });
      }
    }
  );
});

app.post("/login", (req, res) => {
  const email = req.body.email;
  const password = req.body.password;

  db.query("SELECT * FROM users WHERE email = ?;", email, (err, result) => {
    if (err) {
      res.json({ err: err });
    }
    console.log(result);
    if (result.length > 0) {
      bcrypt.compare(password, result[0].password, (error, response) => {
        if (response) {
          const accessToken = jwt.sign(
            {
              email: result[0].email,
              username: result[0].username,
              id: result[0].id,
            },
            "licentaSecret"
          );
          db.query(
            "SELECT src FROM profile_picture WHERE pfp_name = (SELECT pfp FROM users WHERE id = ?)",
            result[0].id,
            (err, result2) => {
              if (err) {
                console.log(err);
              } else {
                res.json({
                  token: accessToken,
                  email: result[0].email,
                  username: result[0].username,
                  id: result[0].id,
                  pfp_src: result2[0].src,
                });
              }
            }
          );
        } else {
          res.json({ error: "Wrong email/password combination!" });
        }
      });
    } else {
      res.json({ error: "User doesn't exist" });
    }
  });
});

app.post("/select-champion", (req, res) => {
  id = req.body.id;
  gameType = req.body.game_type;
  dificulty = req.body.dificulty;
  db.query(
    "SELECT * FROM champions WHERE answer NOT IN (SELECT correct_answer FROM history WHERE user_id = ? AND game_type = ? AND user_answer=correct_answer) ORDER BY RAND() LIMIT 1;",
    [id, gameType],
    (err, result) => {
      if (err) {
        console.log(err);
      } else {
        if (dificulty === "img") res.json(result[0].img);
        else if (dificulty === "skin1") res.json(result[0].skin1);
      }
    }
  );
});

app.get("/champion-options", (req, res) => {
  db.query("SELECT answer FROM champions", (err, result) => {
    if (err) {
      console.log(err);
    } else {
      var final_result = [];
      for (var i = 0; i < result.length; i++) {
        final_result.push(
          result[i].answer.charAt(0).toUpperCase() +
            result[i].answer.slice(1).toLowerCase()
        );
      }
      res.json(final_result);
    }
  });
});

app.post("/hints-amount", (req, res) => {
  const id = req.body.id;
  db.query("SELECT hints FROM users WHERE id = ?", id, (err, result) => {
    if (err) {
      console.log(err);
    } else {
      res.json(result);
    }
  });
});

app.post("/check-answer", (req, res) => {
  const id = req.body.id;
  const imgpath = req.body.imgpath;
  const answer = req.body.answer;
  const gameType = req.body.game_type;
  const dificulty = req.body.dificulty;
  const username = req.body.username;
  let wrong;
  db.query(
    "SELECT * FROM champions WHERE ?? = ?",
    [dificulty, imgpath],
    (err, result) => {
      if (err) {
        console.log(err);
      } else {
        if (answer === result[0].answer) {
          if (gameType === "easy22") {
            db.query(
              "UPDATE users SET coins = coins + 1, easy22hint = easy22hint + 1, easy22correct = easy22correct + 1 WHERE id = ?",
              id,
              (err, result2) => {
                if (err) {
                  console.log(err);
                } else {
                  db.query(
                    "UPDATE users SET hints = IF(easy22hint=3, hints + 1, hints), easy22hint = IF(easy22hint=3, 0, easy22hint) WHERE id = ?;",
                    id,
                    (err, result3) => {
                      if (err) {
                        console.log(err);
                      } else {
                        if (result3.changedRows > 0){
                        db.query(
                          "INSERT INTO history (user_id, username, user_answer, correct_answer, game_type, bonus, date) VALUES (?,?,?,?,?,?,CURRENT_TIMESTAMP)",
                          [id, username, answer, result[0].answer, gameType, 1],
                          (err, result) => {
                            if (err) {
                              res.json({ err: err });
                            }
                            else{
                              res.json({
                                type: "success",
                                message: "Correct answer",
                                description: "+1 ShopPoints added to your account",
                                type2: "info",
                                message2:
                                  "You answered 3 times correctly. You receive 1 Hint Point",
                                description: "",
                              });
                            }
                          }
                        );
                        }
                        else {
                          db.query(
                            "INSERT INTO history (user_id, username, user_answer, correct_answer, game_type, date) VALUES (?,?,?,?,?,CURRENT_TIMESTAMP)",
                            [id, username, answer, result[0].answer, gameType],
                            (err, result) => {
                              if (err) {
                                res.json({ err: err });
                              }
                              else{
                                res.json({
                                  type: "success",
                                  message: "Correct answer",
                                  description: "+1 ShopPoints added to your account",
                                });
                              }
                            }
                          );
                        }
                      }
                    }
                  );
                }
              }
            );
          }

          if (gameType === "hard22") {
            db.query(
              "UPDATE users SET coins = coins + 2, hard22hint = hard22hint + 1, hard22correct = hard22correct + 1 WHERE id = ?",
              id,
              (err, result2) => {
                if (err) {
                  console.log(err);
                } else {
                  db.query(
                    "UPDATE users SET hints = IF(hard22hint=3, hints + 2, hints), hard22hint = IF(hard22hint=3, 0, hard22hint) WHERE id = ?;",
                    id,
                    (err, result3) => {
                      if (err) {
                        console.log(err);
                      } else {
                        if (result3.changedRows > 0){
                          db.query(
                            "INSERT INTO history (user_id, username, user_answer, correct_answer, game_type, bonus, date) VALUES (?,?,?,?,?,?,CURRENT_TIMESTAMP)",
                            [id, username, answer, result[0].answer, gameType, 2],
                            (err, result) => {
                              if (err) {
                                res.json({ err: err });
                              }
                              else{
                                res.json({
                                  type: "success",
                                  message: "Correct answer",
                                  description: "+2 ShopPoints added to your account",
                                  type2: "info",
                                  message2:
                                    "You answered 3 times correctly. You receive 2 Hint Points",
                                  description: "",
                                });
                              }
                            }
                          );
                          }
                        else {
                          db.query(
                            "INSERT INTO history (user_id, username, user_answer, correct_answer, game_type, date) VALUES (?,?,?,?,?,CURRENT_TIMESTAMP)",
                            [id, username, answer, result[0].answer, gameType],
                            (err, result) => {
                              if (err) {
                                res.json({ err: err });
                              }
                              else{
                                res.json({
                                  type: "success",
                                  message: "Correct answer",
                                  description: "+2 ShopPoints added to your account",
                                });
                              }
                            }
                          );
                        }
                      }
                    }
                  );
                }
              }
            );
          } else if (gameType === "easy44") {
            db.query(
              "UPDATE users SET coins = coins + 3, easy44hint = easy44hint + 1, easy44correct = easy44correct + 1 WHERE id = ?",
              id,
              (err, result2) => {
                if (err) {
                  console.log(err);
                } else {
                  db.query(
                    "UPDATE users SET hints = IF(easy44hint=3, hints + 3, hints), easy44hint = IF(easy44hint=3, 0, easy44hint) WHERE id = ?;",
                    id,
                    (err, result3) => {
                      if (err) {
                        console.log(err);
                      } else {
                        if (result3.changedRows > 0){
                          db.query(
                            "INSERT INTO history (user_id, username, user_answer, correct_answer, game_type, bonus, date) VALUES (?,?,?,?,?,?,CURRENT_TIMESTAMP)",
                            [id, username, answer, result[0].answer, gameType, 3],
                            (err, result) => {
                              if (err) {
                                res.json({ err: err });
                              }
                              else{
                                res.json({
                                  type: "success",
                                  message: "Correct answer",
                                  description: "+3 ShopPoints added to your account",
                                  type2: "info",
                                  message2:
                                    "You answered 3 times correctly. You receive 3 Hint Points",
                                  description: "",
                                });
                              }
                            }
                          );
                          }
                        else {
                          db.query(
                            "INSERT INTO history (user_id, username, user_answer, correct_answer, game_type, date) VALUES (?,?,?,?,?,CURRENT_TIMESTAMP)",
                            [id, username, answer, result[0].answer, gameType],
                            (err, result) => {
                              if (err) {
                                res.json({ err: err });
                              }
                              else{
                                res.json({
                                  type: "success",
                                  message: "Correct answer",
                                  description: "+3 ShopPoints added to your account",
                                });
                              }
                            }
                          );
                          
                        }
                      }
                    }
                  );
                }
              }
            );
          } else if (gameType === "hard44") {
            db.query(
              "UPDATE users SET coins = coins + 5, hard44hint = hard44hint + 1, hard44correct = hard44correct + 1 WHERE id = ?",
              id,
              (err, result2) => {
                if (err) {
                  console.log(err);
                } else {
                  db.query(
                    "UPDATE users SET hints = IF(hard44hint=3, hints + 5, hints), hard44hint = IF(hard44hint=3, 0, hard44hint) WHERE id = ?;",
                    id,
                    (err, result3) => {
                      if (err) {
                        console.log(err);
                      } else {
                        if (result3.changedRows > 0){
                          db.query(
                            "INSERT INTO history (user_id, username, user_answer, correct_answer, game_type, bonus, date) VALUES (?,?,?,?,?,?,CURRENT_TIMESTAMP)",
                            [id, username, answer, result[0].answer, gameType, 5],
                            (err, result) => {
                              if (err) {
                                res.json({ err: err });
                              }
                              else{
                                res.json({
                                  type: "success",
                                  message: "Correct answer",
                                  description: "+5 ShopPoints added to your account",
                                  type2: "info",
                                  message2:
                                    "You answered 3 times correctly. You receive 5 Hint Points",
                                  description: "",
                                });
                              }
                            }
                          );
                          }
                          
                        else {
                          db.query(
                            "INSERT INTO history (user_id, username, user_answer, correct_answer, game_type, date) VALUES (?,?,?,?,?,CURRENT_TIMESTAMP)",
                            [id, username, answer, result[0].answer, gameType],
                            (err, result) => {
                              if (err) {
                                res.json({ err: err });
                              }
                              else{
                                res.json({
                                  type: "success",
                                  message: "Correct answer",
                                  description: "+5 ShopPoints added to your account",
                                });
                              }
                            }
                          );
                          
                        }
                      }
                    }
                  );
                }
              }
            );
          }
        } else {
          if (gameType === "easy22") wrong = "easy22wrong";
          else if (gameType === "hard22") wrong = "hard22wrong";
          else if (gameType === "easy44") wrong = "easy44wrong";
          else if (gameType === "hard44") wrong = "hard44wrong";
          db.query(
            "UPDATE users SET ?? = ?? + 1 WHERE id = ?",
            [wrong, wrong, id],
            (err, result2) => {
              if (err) {
                console.log(err);
              } else {
                db.query(
                  "INSERT INTO history (user_id, username, user_answer, correct_answer, game_type, date) VALUES (?,?,?,?,?,CURRENT_TIMESTAMP)",
                  [id, username, answer, result[0].answer, gameType],
                  (err, result) => {
                    if (err) {
                      res.json({ err: err });
                    }
                    else{
                      res.json({
                        type: "error",
                        message: "Wrong answer",
                        description: "",
                      });
                    }
                  }
                );
              }
            }
          );
        }
      }
    }
  );
});

app.post("/hint", (req, res) => {
  const id = req.body.id;
  db.query("SELECT hints FROM users WHERE id = ?", id, (err, result) => {
    if (err) {
      console.log(err);
    } else {
      if (result[0].hints <= 0) {
        res.json({
          type: "error",
          message: "Not enough hint points",
          description: "You can buy some from SHOP",
        });
      } else {
        db.query(
          "UPDATE users SET hints = hints - 1 WHERE id = ?",
          id,
          (err, result) => {
            if (err) console.log(err);
            else {
              res.json({
                type: "success",
                message: "Hint used!",
                description: "",
              });
            }
          }
        );
      }
    }
  });
});

app.post("/myprofile", (req, res) => {
  const id = req.body.id;
  db.query("SELECT * FROM users WHERE id = ?", id, (err, result) => {
    if (err) {
      console.log(err);
    } else {
      res.json(result);
    }
  });
});

app.get("/pfp-options", (req, res) => {
  db.query("SELECT pfp_name, src FROM profile_picture", (err, result) => {
    if (err) {
      console.log(err);
    } else {
      res.json(result);
    }
  });
});

app.post("/coins-amount", (req, res) => {
  const id = req.body.id;
  db.query("SELECT coins FROM users WHERE id = ?", id, (err, result) => {
    if (err) {
      console.log(err);
    } else {
      res.json(result);
    }
  });
});

app.post("/change-pfp", (req, res) => {
  const id = req.body.id;
  const pfp_name = req.body.pfp_name;
  db.query(
    "UPDATE users SET pfp = ? WHERE id = ?",
    [pfp_name, id],
    (err, result) => {
      if (err) {
        console.log(err);
      } else {
        db.query(
          "SELECT src FROM profile_picture WHERE pfp_name = ?",
          pfp_name,
          (err, result) => {
            if (err) {
              console.log(err);
            } else {
              res.json({
                type: "success",
                message: "Avatar updated!",
                description: "",
                pfp_src: result[0].src,
              });
            }
          }
        );
      }
    }
  );
});

app.post("/user-history", (req, res) => {
  const id = req.body.id;
  db.query("SELECT * FROM history WHERE user_id = ? ORDER BY date DESC", id, (err, result) => {
    if (err) {
      console.log(err);
    } else {
      res.json(result);
    }
  });
});

app.post("/change-username", verifyJWT, (req, res) => {
  const id = req.body.id;
  const username = req.body.username;
  if(req.user.id === id){
    db.query(
      "SELECT username FROM users WHERE username = ?",
      username,
      (err, result) => {
        if (err) {
          console.log(err);
        } else {
          if (result.length > 0) {
            res.json({
              type: "error",
              message: "Username is already taken",
              description: "",
            });
          } else {
            db.query("UPDATE users SET username = ? WHERE id = ?", [username,id], (err, result) => {
              if (err) {
                console.log(err);
              } else {
                res.json({
                  type: "success",
                  message: "Username updated successfully",
                  description: "",
                });
              }
            });
          }
        }
      }
    );
  }
  else{
    res.json({
      error: "This token does not belong to your account"
    });
  }
  
});

app.listen(process.env.PORT || 3001, () => {
  console.log("Server running at http://localhost:3001");
});
