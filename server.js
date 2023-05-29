const express = require("express");
const app = express();
const mysql = require("mysql");
const cors = require("cors");
const bcrypt = require("bcryptjs");
const saltRounds = 10;
const jwt = require("jsonwebtoken");
const e = require("express");
require("dotenv").config();
const nodemailer = require("nodemailer");
const crypto = require("crypto");

var emails = require("./emails");
var emailVerification = emails.emailVerification;
var forgotPassword = emails.forgotPassword;

app.use(express.json());
app.use(cors());

let validGameIds = [];
const secretKey = "secret-key";

const http = require("http").createServer(app);
const io = require("socket.io")(http, {
  cors: {
    origin: "https://leagueofquiz.netlify.app",
    credentials: true,
  },
});

// Keep track of all the rooms and their players
const rooms = {};

// Function to verify the token
const verifyToken = (userToken) => {
  let token = userToken;

  if (!token) return "User not logged in!";

  try {
    const validToken = jwt.verify(token, "licentaSecret");
    if (validToken) {
      return validToken;
    }
  } catch (err) {
    return err;
  }
};

// Randomly generate room codes
const generateRoomCode = () => {
  let code = Math.random().toString(36).substring(2, 6).toUpperCase();
  while (rooms[code]) {
    code = Math.random().toString(36).substring(2, 6).toUpperCase();
  }
  return code;
};

// get champion
const getNextChampion = async (easy22, easy44, hard22, hard44) => {
  let options = [];
  if (easy22) options.push("easy22");
  if (easy44) options.push("easy44");
  if (hard22) options.push("hard22");
  if (hard44) options.push("hard44");
  let randomIndex = Math.floor(Math.random() * options.length);
  let option = options[randomIndex];

  return new Promise((resolve, reject) => {
    db.query(
      "SELECT * FROM champions ORDER BY RAND() LIMIT 1;",
      (err, result) => {
        if (err) {
          reject(err);
        } else {
          if (option === "easy22" || option === "easy44")
            resolve({
              championSelectedSrc: result[0].img,
              dificulty: option,
              championSelected: result[0].answer,
            });
          else if (option === "hard22" || option === "hard44")
            resolve({
              championSelectedSrc: result[0].skin1,
              dificulty: option,
              championSelected: result[0].answer,
            });
        }
      }
    );
  });
};

// get usernames and pfps
const getUserAndPfps = async (token1, token2) => {
  let user1 = verifyToken(token1);
  let user1Username = user1.username;
  let user2 = verifyToken(token2);
  let user2Username = user2.username;

  return new Promise((resolve, reject) => {
    db.query(
      "SELECT u.id, p.src FROM profile_picture p JOIN users u ON (p.pfp_name = u.pfp AND (u.id = ? OR u.id = ?));",
      [user1.id, user2.id],
      (err, result) => {
        if (err) {
          reject(err);
        } else {
          if (user1.id === result[0].id)
            resolve({
              player1Username: user1Username,
              player2Username: user2Username,
              user1Pfp: result[0].src,
              user2Pfp: result[1].src,
            });
          else
            resolve({
              player1Username: user1Username,
              player2Username: user2Username,
              user1Pfp: result[1].src,
              user2Pfp: result[0].src,
            });
        }
      }
    );
  });
};

// Random select picture to make it visible
function changeRandomFalseToTrue(array) {
  const falseValues = array.reduce((acc, currentValue, currentIndex) => {
    if (!currentValue) {
      acc.push(currentIndex);
    }
    return acc;
  }, []);

  if (falseValues.length === 0) {
    return array;
  }

  const randomIndex =
    falseValues[Math.floor(Math.random() * falseValues.length)];
  array[randomIndex] = true;

  return array;
}

// roomsAvailable method
function roomsAvailable(){
  let arrayRooms = Object.keys(rooms);
  if(arrayRooms.length === 0)
    io.emit("roomsAvailable", arrayRooms);
  else{
    let jsonRooms = {};
    let userInfo;
    for (const roomCode in rooms){
      userInfo = verifyToken(rooms[roomCode].playersToken[0])
      jsonRooms[roomCode] = {
      roomCode: roomCode,
      host: userInfo.username,
      password: (rooms[roomCode].password === null || rooms[roomCode].password === '') ? 'NO' : 'YES',
      easy22: (rooms[roomCode].easy22) ? "YES" : "NO",
      easy44: (rooms[roomCode].easy44) ? "YES" : "NO",
      hard22: (rooms[roomCode].hard22) ? "YES" : "NO",
      hard44: (rooms[roomCode].hard44) ? "YES" : "NO",
      seconds22: (rooms[roomCode].seconds22 === '') ? "-" : rooms[roomCode].seconds22,
      seconds44: (rooms[roomCode].seconds44 === '') ? "-" : rooms[roomCode].seconds44,
      status: (rooms[roomCode].playersId.length === 2) ? "Full" : "1/2"
      }
    }
    io.emit("roomsAvailable", jsonRooms);
  }

}

io.on("connection", (socket) => {
  roomsAvailable();
  console.log(rooms);
  console.log("a user connected");

  socket.on("createRoom", (data) => {
    const roomCode = generateRoomCode();
    // rooms[roomCode] = [socket.id]

    rooms[roomCode] = {
      playersId: [socket.id],
      playersToken: [data.token],
      currentChampion: null,
      dificulty: "",
      password: data.password,
      player1correct: 0,
      player1wrong: 0,
      player2correct: 0,
      player2wrong: 0,
      player1score: 0,
      player2score: 0,
      easy22: data.easy22,
      easy44: data.easy44,
      hard22: data.hard22,
      hard44: data.hard44,
      seconds22: data.seconds22,
      seconds44: data.seconds44,
      partsVisible22: [false, false, false, false],
      partsVisible44: [
        false,
        false,
        false,
        false,
        false,
        false,
        false,
        false,
        false,
        false,
        false,
        false,
        false,
        false,
        false,
        false,
      ],
    };
    socket.join(roomCode);
    socket.emit("roomCreated", roomCode);
    console.log(rooms);
    roomsAvailable();
  });

  socket.on("joinRoom", (data) => {
    if (!rooms[data.roomCode]) {
      socket.emit("invalidRoom");
      return;
    }

    if (
      rooms[data.roomCode].password !== "" &&
      rooms[data.roomCode].password !== null &&
      (data.password === "" || data.password === null)
    ) {
      socket.emit("passwordRequired");
      return;
    }

    if (
      data.password !== rooms[data.roomCode].password &&
      rooms[data.roomCode].password !== "" &&
      rooms[data.roomCode].password !== ""
    ) {
      socket.emit("incorrectPassword");
      return;
    }

    if (rooms[data.roomCode].playersId.length === 2) {
      socket.emit("roomFull");
      return;
    }
    rooms[data.roomCode].playersId.push(socket.id);
    rooms[data.roomCode].playersToken.push(data.token);

    socket.join(data.roomCode);
    const userInfo = verifyToken(data.token);
    io.to(rooms[data.roomCode].playersId[0]).emit(
      "playerJoined",
      userInfo.username
    );
    socket.emit("roomJoined", data.roomCode);

    // choose champion
    const emitNewChampion = async () => {
      let usernamesAndPfps = await getUserAndPfps(
        rooms[data.roomCode].playersToken[0],
        rooms[data.roomCode].playersToken[1]
      );
      let champion = await getNextChampion(
        rooms[data.roomCode].easy22,
        rooms[data.roomCode].easy44,
        rooms[data.roomCode].hard22,
        rooms[data.roomCode].hard44
      );
      io.to(rooms[data.roomCode].playersId).emit("newChampion", {
        champion: champion,
        seconds22: rooms[data.roomCode].seconds22,
        seconds44: rooms[data.roomCode].seconds44,
        player1Username: usernamesAndPfps.player1Username,
        player2Username: usernamesAndPfps.player2Username,
        user1Pfp: usernamesAndPfps.user1Pfp,
        user2Pfp: usernamesAndPfps.user2Pfp,
      });
      rooms[data.roomCode].currentChampion = champion.championSelected;
      rooms[data.roomCode].dificulty = champion.dificulty;
    };
    emitNewChampion();
    roomsAvailable();
  });

  // choosing a new part from the champion to be visible
  socket.on("gameInProgress", (data) => {
    if (data.goodToChoose && socket.id === rooms[data.roomCode].playersId[0]) {
      if (data.dificulty === "easy22" || data.dificulty === "hard22") {
        let randomVisible = changeRandomFalseToTrue(
          rooms[data.roomCode].partsVisible22
        );
        io.to(rooms[data.roomCode].playersId).emit(
          "newChampionVisible",
          randomVisible
        );
      } else {
        let randomVisible = changeRandomFalseToTrue(
          rooms[data.roomCode].partsVisible44
        );
        io.to(rooms[data.roomCode].playersId).emit(
          "newChampionVisible",
          randomVisible
        );
      }
    }
  });

  //choose a new champion
  socket.on("newChampion", (data) => {
    if (socket.id === rooms[data.roomCode].playersId[0]) {
      // choose champion
      const emitNewChampion = async () => {
        let champion = await getNextChampion(
          rooms[data.roomCode].easy22,
          rooms[data.roomCode].easy44,
          rooms[data.roomCode].hard22,
          rooms[data.roomCode].hard44
        );
        if (
          champion.dificulty === "easy22" ||
          champion.dificulty === "hard22"
        ) {
          rooms[data.roomCode].partsVisible22 = [false, false, false, false];
          let randomVisible = changeRandomFalseToTrue(
            rooms[data.roomCode].partsVisible22
          );
          io.to(rooms[data.roomCode].playersId).emit("newChampionNewGame", {
            champion: champion,
            visibilityData: randomVisible,
            text: `The correct answer was ${rooms[data.roomCode].currentChampion}`,
          });
        } else {
          rooms[data.roomCode].partsVisible44 = [
            false,
            false,
            false,
            false,
            false,
            false,
            false,
            false,
            false,
            false,
            false,
            false,
            false,
            false,
            false,
            false,
          ];
          let randomVisible = changeRandomFalseToTrue(
            rooms[data.roomCode].partsVisible44
          );
          io.to(rooms[data.roomCode].playersId).emit("newChampionNewGame", {
            champion: champion,
            visibilityData: randomVisible,
            text: `The correct answer was ${rooms[data.roomCode].currentChampion}`,
          });
        }

        rooms[data.roomCode].currentChampion = champion.championSelected;
        rooms[data.roomCode].dificulty = champion.dificulty;
      };

      emitNewChampion();
    }
  });

  // check the answer
  socket.on("checkAnswer", (data) => {
    let score, totalScore;
    let championsToCheckLower = data.championsToCheck.map((t) =>
      t.toLowerCase()
    );
    const index = rooms[data.roomCode].playersId.indexOf(socket.id);

    if (data.answer === rooms[data.roomCode].currentChampion) {
      index === 0
        ? (rooms[data.roomCode].player1correct += 1)
        : (rooms[data.roomCode].player2correct += 1);

      switch (rooms[data.roomCode].dificulty) {
        case "easy22":
          index === 0
            ? (rooms[data.roomCode].player1score += 1, score = 1)
            : (rooms[data.roomCode].player2score += 1, score = 1);

          break;
        case "hard22":
          index === 0
            ? (rooms[data.roomCode].player1score += 2, score = 2)
            : (rooms[data.roomCode].player2score += 2, score = 2);
          break;
        case "easy44":
          index === 0
            ? (rooms[data.roomCode].player1score += 3, score = 3)
            : (rooms[data.roomCode].player2score += 3, score = 3);
          break;
        case "hard44":
          index === 0
            ? (rooms[data.roomCode].player1score += 5, score = 5)
            : (rooms[data.roomCode].player2score += 5, score = 5);
          break;
      }

      index === 0
        ? (totalScore = rooms[data.roomCode].player1score)
        : (totalScore = rooms[data.roomCode].player2score);

      io.to(rooms[data.roomCode].playersId[index]).emit("correctAnswerP1", {
        type: "success",
        text: "Correct answer",
        description: `+${score} score. Total score: ${totalScore}`,
        p1correct: rooms[data.roomCode].player1correct,
        p2correct: rooms[data.roomCode].player2correct,
        p1score: rooms[data.roomCode].player1score,
        p2score: rooms[data.roomCode].player2score
      });
      const userInfo = verifyToken(rooms[data.roomCode].playersToken[index]);
      let otherIndex = index === 0 ? 1 : 0;
      io.to(rooms[data.roomCode].playersId[otherIndex]).emit(
        "correctAnswerP2",
        {
          type: "info",
          text: `${userInfo.username} answered correctly`,
          description: `The answer was ${
            data.answer.charAt(0).toUpperCase() + data.answer.slice(1)
          }`,
          p1correct: rooms[data.roomCode].player1correct,
          p2correct: rooms[data.roomCode].player2correct,
          p1score: rooms[data.roomCode].player1score,
          p2score: rooms[data.roomCode].player2score
        }
      );
      // choose champion
      const emitNewChampion = async () => {
        let champion = await getNextChampion(
          rooms[data.roomCode].easy22,
          rooms[data.roomCode].easy44,
          rooms[data.roomCode].hard22,
          rooms[data.roomCode].hard44
        );
        if (
          champion.dificulty === "easy22" ||
          champion.dificulty === "hard22"
        ) {
          rooms[data.roomCode].partsVisible22 = [false, false, false, false];
          let randomVisible = changeRandomFalseToTrue(
            rooms[data.roomCode].partsVisible22
          );
          io.to(rooms[data.roomCode].playersId).emit("newChampionNewGame", {
            champion: champion,
            visibilityData: randomVisible,
          });
        } else {
          rooms[data.roomCode].partsVisible44 = [
            false,
            false,
            false,
            false,
            false,
            false,
            false,
            false,
            false,
            false,
            false,
            false,
            false,
            false,
            false,
            false,
          ];
          let randomVisible = changeRandomFalseToTrue(
            rooms[data.roomCode].partsVisible44
          );
          io.to(rooms[data.roomCode].playersId).emit("newChampionNewGame", {
            champion: champion,
            visibilityData: randomVisible,
          });
        }

        rooms[data.roomCode].currentChampion = champion.championSelected;
        rooms[data.roomCode].dificulty = champion.dificulty;
      };

      emitNewChampion();
    } else if (championsToCheckLower.includes(data.answer)) {
      index === 0
        ? (rooms[data.roomCode].player1wrong += 1)
        : (rooms[data.roomCode].player2wrong += 1);
      io.to(rooms[data.roomCode].playersId[index]).emit("wrongAnswerP1", {
        type: "error",
        error: "Wrong answer", p1wrong: rooms[data.roomCode].player1wrong, p2wrong: rooms[data.roomCode].player2wrong
      });
      const userInfo = verifyToken(rooms[data.roomCode].playersToken[index]);
      let otherIndex = index === 0 ? 1 : 0;
      io.to(rooms[data.roomCode].playersId[otherIndex]).emit("wrongAnswerP2", {
        type: "info",
        error: `${userInfo.username} answered wrong: ${
          data.answer.charAt(0).toUpperCase() + data.answer.slice(1)
        }`, p1wrong: rooms[data.roomCode].player1wrong, p2wrong: rooms[data.roomCode].player2wrong
      });
    }
  });

  // manually disconnect
  socket.on("gameOver", (data) => {
    const index = rooms[data.roomCode].playersId.indexOf(socket.id);
    const userInfo = verifyToken(rooms[data.roomCode].playersToken[index]);
    io.to(rooms[data.roomCode].playersId).emit("gameOverStats", {
      type: "info",
      message: `${userInfo.username} decided to stop the game`
    });
    delete rooms[data.roomCode];
    roomsAvailable();
  });

  // roomsAvailable
  socket.on("roomsAvailable", () => {
    roomsAvailable();
  });

  socket.on("disconnect", () => {
    console.log("user disconnected");
    // Remove the disconnected socket from its room
    for (const roomCode in rooms) {
      const index = rooms[roomCode].playersId.indexOf(socket.id);
      if (index !== -1) {
      const userInfo = verifyToken(rooms[roomCode].playersToken[index]);
      io.to(rooms[roomCode].playersId).emit("gameOverStats", {
        type: "info",
        message: `${userInfo.username} left the game`
      });
      delete rooms[roomCode];
      roomsAvailable();
      break;
    }
      // if (index !== -1) {
      //   rooms[roomCode].playersId.splice(index, 1);
      //   rooms[roomCode].playersToken.splice(index, 1);
      //   if (rooms[roomCode].playersId.length === 0) {
      //     delete rooms[roomCode];
      //   }
      //   break;
      // }
    }
  });
});

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
  user: process.env.DB_ROOT,
  host: process.env.DB_HOST,
  password: process.env.DB_PASSWORD,
  port: process.env.DB_PORT,
  database: process.env.DB_DATABSE,
});

//mail sender details
var transporter = nodemailer.createTransport({
  service: process.env.MAIL_SERVICE,
  auth: {
    user: process.env.MAIL_USER,
    pass: process.env.MAIL_PASS,
  },
  tls: {
    rejectUnauthorized: false,
  },
});

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
            "SELECT pfp_name FROM profile_picture WHERE id BETWEEN 1 AND 10 ORDER BY RAND() LIMIT 1;",
            (err, result2) => {
              if (err) {
                console.log(err);
              } else {
                let emailToken = crypto.randomBytes(32).toString("hex");

                db.query(
                  "INSERT INTO users (email, username, password, pfp, email_token, forgot_token, owned_items, date) VALUES (?,?,?,?,?,?,?,CURRENT_TIMESTAMP)",
                  [
                    email,
                    username,
                    hash,
                    result2[0].pfp_name,
                    emailToken,
                    "",
                    `{"picture": ["pfp1","pfp2","pfp3","pfp4","pfp5","pfp6","pfp7","pfp8","pfp9","pfp10"],"background": ["color1"]}`,
                  ],
                  (err, result) => {
                    if (err) {
                      console.log(err);
                    } else {
                      //send verification mail
                      var mailOptions = {
                        from: ' "Verify your email" <leagueofquizz@gmail.com>',
                        to: email,
                        subject: "LeagueOfQuiz Verify your email",
                        html: emailVerification(
                          result.insertId,
                          username,
                          emailToken
                        ),
                      };

                      //sending mail
                      transporter.sendMail(mailOptions, function (error, info) {
                        if (error) console.log(error);
                        else
                          console.log(
                            "Verification email is sent to your gmail account"
                          );
                      });
                      res.json({
                        type: "success",
                        message: "Account successfully registered",
                        description:
                          "We sent a verification link on email. Check your inbox",
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

app.get("/users/:id/verify-email", (req, res) => {
  const userId = req.params.id;
  const token = req.query.token;
  db.query(
    "SELECT email_token FROM users WHERE id = ?",
    userId,
    (err, result) => {
      if (err) {
        console.log(err);
      } else {
        if (result.length > 0) {
          if (token === result[0].email_token) {
            db.query(
              "UPDATE users SET is_verified = true, email_token = '' WHERE id = ?",
              userId,
              (err, result) => {
                if (err) console.log(err);
                else {
                  res.json({
                    type: "success",
                    message: "Email verified successfully!",
                    description: "",
                  });
                }
              }
            );
          } else {
            res.json({
              type: "error",
              message: "Invalid link",
              description: "",
            });
          }
        } else {
          res.json({
            type: "error",
            message: "Invalid link",
            description: "",
          });
        }
      }
    }
  );
});

const verifyJWT = (req, res, next) => {
  let token = req.headers["x-access-token"];

  if (!token) return res.json({ error: "User not logged in!" });

  try {
    const validToken = jwt.verify(token, "licentaSecret");
    req.user = validToken;
    if (validToken) {
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
        db.query(
          "SELECT coins FROM users WHERE id = ?",
          req.user.id,
          (err, result2) => {
            if (err) {
              console.log(err);
            } else {
              res.json({
                user: req.user,
                result: result,
                user_coins: result2[0].coins,
              });
            }
          }
        );
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
                db.query(
                  "SELECT is_verified FROM users WHERE email = ?",
                  email,
                  (err, result3) => {
                    if (err) {
                      console.log(err);
                    } else {
                      if (result3[0].is_verified) {
                        res.json({
                          token: accessToken,
                          email: result[0].email,
                          username: result[0].username,
                          id: result[0].id,
                          pfp_src: result2[0].src,
                          coins: result[0].coins,
                          type: "success",
                          message: "Logged in successfully",
                          description: "",
                        });
                      } else {
                        let emailToken = crypto.randomBytes(32).toString("hex");
                        db.query(
                          "UPDATE users SET email_token = ? WHERE email = ?",
                          [emailToken, email],
                          (err, result4) => {
                            if (err) console.log(err);
                            else {
                              //send verification mail
                              var mailOptions = {
                                from: ' "Verify your email" <leagueofquizz@gmail.com>',
                                to: email,
                                subject: "LeagueOfQuiz Verify your email",
                                html: emailVerification(
                                  result[0].id,
                                  result[0].username,
                                  emailToken
                                ),
                              };

                              //sending mail
                              transporter.sendMail(
                                mailOptions,
                                function (error, info) {
                                  if (error) console.log(error);
                                  else console.log("Resent verification email");
                                }
                              );
                              res.json({
                                type: "error",
                                message: "Account unverified",
                                description:
                                  "We sent another verification link on email. Check your inbox",
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
        } else {
          res.json({
            type: "error",
            message: "Login failed",
            description: "Wrong email/password combination!",
          });
        }
      });
    } else {
      res.json({
        type: "error",
        message: "Login failed",
        description: "Email doesn't exist",
      });
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
        if(result.length === 0) {
          res.json({
            type: "info",
            message: "You have already completed this mode"
          });
          return;
        }
        const gameId = crypto.randomBytes(16).toString("hex");
        const signature = crypto
          .createHmac("sha256", secretKey)
          .update(gameId)
          .digest("hex");
        validGameIds.push(gameId);
        if (dificulty === "img")
          res.json({
            img: result[0].img,
            gameId: gameId,
            signature: signature,
          });
        else if (dificulty === "skin1")
          res.json({
            img: result[0].skin1,
            gameId: gameId,
            signature: signature,
          });
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
  const gameId = req.body.gameId;

  let wrong;

  if (!validGameIds.includes(gameId)) {
    return res.json({ error: "Invalid game ID" });
  }
  const signature = crypto
    .createHmac("sha256", secretKey)
    .update(gameId)
    .digest("hex");
  if (signature !== req.body.signature) {
    return res.json({ error: "Invalid signature" });
  }

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
              "UPDATE users SET coins = coins + 1, easy22hint = easy22hint + 1, easy22correct = easy22correct + 1, rank_points = rank_points + 1 WHERE id = ?",
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
                        if (result3.changedRows > 0) {
                          db.query(
                            "INSERT INTO history (user_id, username, user_answer, correct_answer, game_type, bonus, date) VALUES (?,?,?,?,?,?,CURRENT_TIMESTAMP)",
                            [
                              id,
                              username,
                              answer,
                              result[0].answer,
                              gameType,
                              1,
                            ],
                            (err, result) => {
                              if (err) {
                                res.json({ err: err });
                              } else {
                                validGameIds = validGameIds.filter(
                                  (id) => id !== gameId
                                );
                                res.json({
                                  type: "success",
                                  message: "Correct answer",
                                  description:
                                    "+1 ShopPoints added to your account",
                                  coins: 1,
                                  type2: "info",
                                  message2:
                                    "You answered 3 times correctly. You receive 1 Hint Point",
                                  description: "",
                                });
                              }
                            }
                          );
                        } else {
                          validGameIds = validGameIds.filter(
                            (id) => id !== gameId
                          );
                          db.query(
                            "INSERT INTO history (user_id, username, user_answer, correct_answer, game_type, date) VALUES (?,?,?,?,?,CURRENT_TIMESTAMP)",
                            [id, username, answer, result[0].answer, gameType],
                            (err, result) => {
                              if (err) {
                                res.json({ err: err });
                              } else {
                                res.json({
                                  type: "success",
                                  message: "Correct answer",
                                  description:
                                    "+1 ShopPoints added to your account",
                                  coins: 1,
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
              "UPDATE users SET coins = coins + 2, hard22hint = hard22hint + 1, hard22correct = hard22correct + 1, rank_points = rank_points + 2 WHERE id = ?",
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
                        if (result3.changedRows > 0) {
                          db.query(
                            "INSERT INTO history (user_id, username, user_answer, correct_answer, game_type, bonus, date) VALUES (?,?,?,?,?,?,CURRENT_TIMESTAMP)",
                            [
                              id,
                              username,
                              answer,
                              result[0].answer,
                              gameType,
                              2,
                            ],
                            (err, result) => {
                              if (err) {
                                res.json({ err: err });
                              } else {
                                validGameIds = validGameIds.filter(
                                  (id) => id !== gameId
                                );
                                res.json({
                                  type: "success",
                                  message: "Correct answer",
                                  description:
                                    "+2 ShopPoints added to your account",
                                  coins: 2,
                                  type2: "info",
                                  message2:
                                    "You answered 3 times correctly. You receive 2 Hint Points",
                                  description: "",
                                });
                              }
                            }
                          );
                        } else {
                          db.query(
                            "INSERT INTO history (user_id, username, user_answer, correct_answer, game_type, date) VALUES (?,?,?,?,?,CURRENT_TIMESTAMP)",
                            [id, username, answer, result[0].answer, gameType],
                            (err, result) => {
                              if (err) {
                                res.json({ err: err });
                              } else {
                                validGameIds = validGameIds.filter(
                                  (id) => id !== gameId
                                );
                                res.json({
                                  type: "success",
                                  message: "Correct answer",
                                  description:
                                    "+2 ShopPoints added to your account",
                                  coins: 2,
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
              "UPDATE users SET coins = coins + 3, easy44hint = easy44hint + 1, easy44correct = easy44correct + 1, rank_points = rank_points + 3 WHERE id = ?",
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
                        if (result3.changedRows > 0) {
                          db.query(
                            "INSERT INTO history (user_id, username, user_answer, correct_answer, game_type, bonus, date) VALUES (?,?,?,?,?,?,CURRENT_TIMESTAMP)",
                            [
                              id,
                              username,
                              answer,
                              result[0].answer,
                              gameType,
                              3,
                            ],
                            (err, result) => {
                              if (err) {
                                res.json({ err: err });
                              } else {
                                validGameIds = validGameIds.filter(
                                  (id) => id !== gameId
                                );
                                res.json({
                                  type: "success",
                                  message: "Correct answer",
                                  description:
                                    "+3 ShopPoints added to your account",
                                  coins: 3,
                                  type2: "info",
                                  message2:
                                    "You answered 3 times correctly. You receive 3 Hint Points",
                                  description: "",
                                });
                              }
                            }
                          );
                        } else {
                          db.query(
                            "INSERT INTO history (user_id, username, user_answer, correct_answer, game_type, date) VALUES (?,?,?,?,?,CURRENT_TIMESTAMP)",
                            [id, username, answer, result[0].answer, gameType],
                            (err, result) => {
                              if (err) {
                                res.json({ err: err });
                              } else {
                                validGameIds = validGameIds.filter(
                                  (id) => id !== gameId
                                );
                                res.json({
                                  type: "success",
                                  message: "Correct answer",
                                  description:
                                    "+3 ShopPoints added to your account",
                                  coins: 3,
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
              "UPDATE users SET coins = coins + 5, hard44hint = hard44hint + 1, hard44correct = hard44correct + 1, rank_points = rank_points + 5 WHERE id = ?",
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
                        if (result3.changedRows > 0) {
                          db.query(
                            "INSERT INTO history (user_id, username, user_answer, correct_answer, game_type, bonus, date) VALUES (?,?,?,?,?,?,CURRENT_TIMESTAMP)",
                            [
                              id,
                              username,
                              answer,
                              result[0].answer,
                              gameType,
                              5,
                            ],
                            (err, result) => {
                              if (err) {
                                res.json({ err: err });
                              } else {
                                validGameIds = validGameIds.filter(
                                  (id) => id !== gameId
                                );
                                res.json({
                                  type: "success",
                                  message: "Correct answer",
                                  description:
                                    "+5 ShopPoints added to your account",
                                  coins: 5,
                                  type2: "info",
                                  message2:
                                    "You answered 3 times correctly. You receive 5 Hint Points",
                                  description: "",
                                });
                              }
                            }
                          );
                        } else {
                          db.query(
                            "INSERT INTO history (user_id, username, user_answer, correct_answer, game_type, date) VALUES (?,?,?,?,?,CURRENT_TIMESTAMP)",
                            [id, username, answer, result[0].answer, gameType],
                            (err, result) => {
                              if (err) {
                                res.json({ err: err });
                              } else {
                                validGameIds = validGameIds.filter(
                                  (id) => id !== gameId
                                );
                                res.json({
                                  type: "success",
                                  message: "Correct answer",
                                  description:
                                    "+5 ShopPoints added to your account",
                                  coins: 5,
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
                    } else {
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
          message: "Not enough HintPoints",
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

app.post("/users/info", (req, res) => {
  const username = req.body.username;
  db.query(
    "SELECT * FROM users WHERE username = ?",
    username,
    (err, result) => {
      if (err) {
        console.log(err);
      } else {
        res.json(result);
      }
    }
  );
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

app.post("/change-pfp", verifyJWT, (req, res) => {
  const id = req.user.id;
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

app.post("/change-bg", verifyJWT, (req, res) => {
  const id = req.user.id;
  const bg_name = req.body.bg_name;
  db.query(
    "UPDATE users SET background_leaderboard = ? WHERE id = ?",
    [bg_name, id],
    (err, result) => {
      if (err) {
        console.log(err);
      } else {
        res.json({
          type: "success",
          message: "Leaderboard background color updated!",
          description: "",
        });
      }
    }
  );
});

app.post("/user-history", (req, res) => {
  const id = req.body.id;
  db.query(
    "SELECT * FROM history WHERE user_id = ? ORDER BY date DESC",
    id,
    (err, result) => {
      if (err) {
        console.log(err);
      } else {
        res.json(result);
      }
    }
  );
});

app.post("/users/user-history", (req, res) => {
  const username = req.body.username;
  db.query(
    "SELECT * FROM history WHERE username = ? ORDER BY date DESC",
    username,
    (err, result) => {
      if (err) {
        console.log(err);
      } else {
        res.json(result);
      }
    }
  );
});

app.post("/change-username", verifyJWT, (req, res) => {
  const id = req.user.id;
  const username = req.body.username;
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
          db.query(
            "UPDATE users SET username = ? WHERE id = ?",
            [username, id],
            (err, result) => {
              if (err) {
                console.log(err);
              } else {
                const accessToken = jwt.sign(
                  {
                    email: req.user.email,
                    username: req.body.username,
                    id: req.user.id,
                  },
                  "licentaSecret"
                );
                res.json({
                  type: "success",
                  message: "Username updated successfully",
                  description: "",
                  token: accessToken,
                });
              }
            }
          );
        }
      }
    }
  );
});

app.post("/forgot-password", (req, res) => {
  const email = req.body.email;
  db.query(
    "SELECT id,username FROM users WHERE email = ?",
    email,
    (err, result) => {
      if (err) {
        console.log(err);
      } else {
        if (result.length === 0) {
          res.json({
            type: "error",
            message: "Email not found",
            description: "",
          });
        } else {
          let forgotToken = crypto.randomBytes(32).toString("hex");
          db.query(
            "UPDATE users SET forgot_token = ? WHERE email = ?",
            [forgotToken, email],
            (err, result2) => {
              if (err) console.log(err);
              else {
                //send verification mail
                var mailOptions = {
                  from: ' "Reset your password" <leagueofquizz@gmail.com>',
                  to: email,
                  subject: "LeagueOfQuiz Reset your password",
                  html: forgotPassword(
                    result[0].id,
                    result[0].username,
                    forgotToken
                  ),
                };

                //sending mail
                transporter.sendMail(mailOptions, function (error, info) {
                  if (error) console.log(error);
                  else
                    console.log(
                      "reset pass email is sent to your gmail account"
                    );
                });
                res.json({
                  type: "success",
                  message: "Check your email for password reset instructions",
                  description: "",
                });
              }
            }
          );
        }
      }
    }
  );
});

app.get("/users/:id/reset-pass", (req, res) => {
  const userId = req.params.id;
  const token = req.query.token;
  db.query(
    "SELECT forgot_token, username FROM users WHERE id = ?",
    userId,
    (err, result) => {
      if (err) {
        console.log(err);
      } else {
        if (result.length > 0) {
          if (token === result[0].forgot_token) {
            res.json({
              type: "success",
              message: "Valid link",
              description: "",
              username: result[0].username,
            });
          } else {
            res.json({
              type: "error",
              message: "Invalid link",
              description: "",
            });
          }
        } else {
          res.json({
            type: "error",
            message: "Invalid link",
            description: "",
          });
        }
      }
    }
  );
});

app.post("/reset-password", (req, res) => {
  const userId = req.body.id;
  const token = req.body.token;
  const password = req.body.password;
  db.query(
    "SELECT forgot_token,password FROM users WHERE id = ?",
    userId,
    (err, result) => {
      if (err) {
        console.log(err);
      } else {
        if (result.length > 0) {
          if (token === result[0].forgot_token && token !== "") {
            bcrypt.compare(password, result[0].password, (error, response) => {
              if (response) {
                res.json({
                  type: "error",
                  message:
                    "New password must be different from currect password",
                  description: "",
                });
              } else {
                bcrypt.hash(password, saltRounds, (err, hash) => {
                  if (err) {
                    console.log(err);
                  } else {
                    db.query(
                      "UPDATE users SET forgot_token = '', password = ? WHERE id = ?",
                      [hash, userId],
                      (err, result2) => {
                        if (err) console.log(err);
                        else {
                          res.json({
                            type: "success",
                            message: "Password changed successfully",
                            description: "",
                          });
                        }
                      }
                    );
                  }
                });
              }
            });
          } else {
            res.json({
              type: "error",
              message: "Invalid link",
              description: "",
            });
          }
        } else {
          res.json({
            type: "error",
            message: "Invalid link",
            description: "",
          });
        }
      }
    }
  );
});

app.post("/change-password", verifyJWT, (req, res) => {
  const userId = req.user.id;
  const currentPassword = req.body.currentPassword;
  const newPassword = req.body.newPassword;
  db.query("SELECT password FROM users WHERE id = ?", userId, (err, result) => {
    if (err) {
      console.log(err);
    } else {
      bcrypt.compare(currentPassword, result[0].password, (error, response) => {
        if (response) {
          bcrypt.compare(newPassword, result[0].password, (error, response) => {
            if (response) {
              res.json({
                type: "error",
                message: "New password must be different from currect password",
                description: "",
              });
            } else {
              bcrypt.hash(newPassword, saltRounds, (err, hash) => {
                if (err) {
                  console.log(err);
                } else {
                  db.query(
                    "UPDATE users SET  password = ? WHERE id = ?",
                    [hash, userId],
                    (err, result2) => {
                      if (err) console.log(err);
                      else {
                        res.json({
                          type: "success",
                          message: "Password changed successfully",
                          description: "",
                        });
                      }
                    }
                  );
                }
              });
            }
          });
        } else {
          res.json({
            type: "error",
            message: "Wrong current password",
            description: "",
          });
        }
      });
    }
  });
});

app.get("/leaderboard", (req, res) => {
  db.query(
    "SELECT id, username, pfp, rank_points, background_leaderboard, easy22correct, easy22wrong, hard22correct, hard22wrong, easy44correct, easy44wrong, hard44correct, hard44wrong FROM users ORDER BY rank_points DESC",
    (err, result) => {
      if (err) {
        console.log(err);
      } else {
        db.query(
          "SELECT pfp_name, src FROM profile_picture",
          (err, result2) => {
            if (err) {
              console.log(err);
            } else {
              res.json({ result, result2 });
            }
          }
        );
      }
    }
  );
});

app.get("/shop-pfps", (req, res) => {
  db.query(
    "SELECT pfp_name, src, shop.price FROM profile_picture INNER JOIN shop ON profile_picture.pfp_name = shop.item WHERE pfp_name in (SELECT item FROM shop where item_type = 'pfp')",
    (err, result) => {
      if (err) {
        console.log(err);
      } else {
        res.json(result);
      }
    }
  );
});

app.get("/shop-bg", (req, res) => {
  db.query(
    "SELECT item, price FROM shop WHERE item_type = 'bg'",
    (err, result) => {
      if (err) {
        console.log(err);
      } else {
        res.json(result);
      }
    }
  );
});

app.post("/user-pfps", verifyJWT, (req, res) => {
  const id = req.user.id;
  db.query(
    "SELECT t2.pfp_name, t2.src FROM users as t1 JOIN profile_picture as t2 ON JSON_EXTRACT(t1.owned_items, '$.picture') LIKE CONCAT('%', t2.pfp_name, '%') AND t1.id = ?;",
    id,
    (err, result) => {
      if (err) {
        console.log(err);
      } else {
        res.json(result);
      }
    }
  );
});

app.post("/user-bg", verifyJWT, (req, res) => {
  const id = req.user.id;
  db.query(
    "SELECT t2.bg_name FROM users as t1 JOIN background_colors as t2 ON JSON_EXTRACT(t1.owned_items, '$.background') LIKE CONCAT('%', t2.bg_name, '%') AND t1.id = ?;",
    id,
    (err, result) => {
      if (err) {
        console.log(err);
      } else {
        res.json(result);
      }
    }
  );
});

app.post("/buy-item", verifyJWT, (req, res) => {
  const id = req.user.id;
  const item_name = req.body.item_name;
  const item_type = req.body.item_type;
  if (item_type !== "hintPoints") {
    db.query(
      "SELECT price FROM shop WHERE item = ?",
      item_name,
      (err, result) => {
        if (err) {
          console.log(err);
        } else {
          db.query(
            "SELECT coins FROM users WHERE id = ?",
            id,
            (err, result2) => {
              if (err) {
                console.log(err);
              } else {
                if (result2[0].coins < result[0].price) {
                  res.json({
                    type: "error",
                    message: "Not enough ShopPoints",
                    description: "",
                  });
                } else {
                  db.query(
                    "UPDATE users SET coins = coins - ? WHERE id = ?",
                    [result[0].price, id],
                    (err, result3) => {
                      if (err) console.log(err);
                      else {
                        if (item_type === "pfp") {
                          db.query(
                            "UPDATE users SET owned_items = JSON_ARRAY_APPEND(owned_items, '$.picture', ?) where id = ?",
                            [item_name, id],
                            (err, result4) => {
                              if (err) {
                                console.log(err);
                              } else {
                                res.json({
                                  type: "success",
                                  message: "Item bought successfully",
                                  description: "Check profile to see it",
                                  coins: result2[0].coins - result[0].price,
                                });
                              }
                            }
                          );
                        } else {
                          db.query(
                            "UPDATE users SET owned_items = JSON_ARRAY_APPEND(owned_items, '$.background', ?) where id = ?",
                            [item_name, id],
                            (err, result4) => {
                              if (err) {
                                console.log(err);
                              } else {
                                res.json({
                                  type: "success",
                                  message: "Item bought successfully",
                                  description: "Check profile to see it",
                                  coins: result2[0].coins - result[0].price,
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
            }
          );
        }
      }
    );
  } else {
    db.query("SELECT coins FROM users WHERE id = ?", id, (err, result) => {
      if (err) {
        console.log(err);
      } else {
        if (result[0].coins - item_name * 3 > 0) {
          db.query(
            "UPDATE users SET coins = coins - ? WHERE id = ?",
            [item_name * 3, id],
            (err, result2) => {
              if (err) console.log(err);
              else {
                db.query(
                  "UPDATE users SET hints = hints + ? WHERE id = ?",
                  [item_name, id],
                  (err, result3) => {
                    if (err) console.log(err);
                    else {
                      res.json({
                        type: "success",
                        message: "HintPoints bought successfully",
                        description: "",
                        coins: result[0].coins - item_name * 3,
                      });
                    }
                  }
                );
              }
            }
          );
        } else {
          res.json({
            type: "error",
            message: "Not enough ShopPoints",
            description: "",
          });
        }
      }
    });
  }
});

app.get("/home-stats", (req, res) => {
  db.query("SELECT COUNT(*) FROM users", (err, result) => {
    if (err) {
      console.log(err);
    } else {
      db.query("SELECT COUNT(*) FROM history", (err, result2) => {
        if (err) {
          console.log(err);
        } else {
          db.query(
            "SELECT COUNT(*) FROM history where user_answer=correct_answer",
            (err, result3) => {
              if (err) {
                console.log(err);
              } else {
                res.json({
                  users: Object.values(result[0])[0],
                  history: Object.values(result2[0])[0],
                  correct_history: Object.values(result3[0])[0],
                });
              }
            }
          );
        }
      });
    }
  });
});

http.listen(process.env.PORT || 3001, () => {
  console.log("Server running at https://daniel-licenta-api.herokuapp.com");
});
