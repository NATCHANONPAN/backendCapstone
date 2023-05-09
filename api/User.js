const express = require("express");
const router = express.Router();
const axios = require("axios");
// import axios from "axios";

// token for user
const JWT = require("jsonwebtoken");

// auth
const auth = require("../middleware/auth");

// mongodb user model
const User = require("./../models/User");

// mongodb userimage model
const UserImage = require("./../models/UserImage");

// mongodb userimage model
const ImageInfo = require("./../models/ImageInfo");

// mongodb user verification model
const UserVerification = require("./../models/UserVerification");

// mongodb user verification model
const PasswordReset = require("./../models/PasswordReset");

// email handler
const nodemailer = require("nodemailer");

// unique string
const { v4: uuidv4 } = require("uuid");

// env variables
require("dotenv").config();

// Password handler
const bcrypt = require("bcryptjs");

// path for static verified page
const path = require("path");

// history
const { authCourse, authPage } = require("../middleware/authRole");

// nodemailer stuff
let transporter = nodemailer.createTransport({
  service: "gmail",
  host: "smtp.gmail.com",
  port: 465,
  secure: true,
  auth: {
    user: process.env.AUTH_EMAIL,
    pass: process.env.AUTH_PASS,
  },
});

// Signup
router.post("/signup", (req, res) => {
  let { name, email, password, confirmPass } = req.body;
  name = name.trim();
  email = email.trim();
  password = password.trim();
  confirmPass = confirmPass.trim();

  if (name == "" || email == "" || password == "" || confirmPass == "") {
    res.json({
      status: "FAILED",
      message: "Empty input fields",
    });
  } else if (!/^[\w-\.]+@([\w-]+\.)+[\w-]{2,4}$/.test(email)) {
    res.json({
      status: "FAILED",
      message: "Invalid email enter",
    });
  } else if (password.length < 8) {
    res.json({
      status: "FAILED",
      message: "Invalid is too short",
    });
  } else if (password != confirmPass) {
    res.json({
      status: "FAILED",
      message: "password not match",
    });
  } else {
    // checking if user already exists
    User.find({ name }, { email })
      .then((result) => {
        if (result.length) {
          // A user already exists
          res.json({
            status: "FAILED",
            message: "User with the provided email or name already exists",
          });
        } else {
          // try to create new user
          const saltRounds = 10;
          bcrypt
            .hash(password, saltRounds)
            .then((hashedPassword) => {
              const newUser = new User({
                name,
                email,
                password: hashedPassword,
                verified: false,
                role: "user",
              });
              // create token
              const token = JWT.sign(
                { userId: newUser._id, name, email, userRole: newUser.role },
                process.env.TOKEN_KEY,
                { expiresIn: "12h" }
              );
              // console.log(JWT.decode(token));
              newUser.token = token;
              newUser
                .save()
                .then((result) => {
                  sendVerificationEmail(result, res);
                })
                .catch((err) => {
                  res.json({
                    status: "FAILED",
                    message: "An error occurred while saving account",
                  });
                });
            })
            .catch((err) => {
              res.json({
                status: "FAILED",
                message: "An error occurred while hashing password",
              });
            });
        }
      })
      .catch((err) => {
        console.log(err);
        res.json({
          status: "FAILED",
          message: "An error occurred while checking for existing user",
        });
      });
  }
});

// send verification email
const sendVerificationEmail = ({ _id, email }, res) => {
  // url to be used in the email
  const CurrentUrl = "http://localhost:5000/";

  const uniqueString = uuidv4() + _id;

  // mail options
  const mailOptions = {
    from: process.env.AUTH_EMAIL,
    to: email,
    subject: "Verify your email",
    html: `<p>Verify your email address to complete the signup and login into your account.</p><p>This link 
    <b>expires in 6 hours</b>.</p><p>Press <a href=${
      CurrentUrl + "user/verify/" + _id + "/" + uniqueString
    }>here</
    a> to proceed.</p>`,
  };

  // hash the uniqueString
  const saltRounds = 10;
  bcrypt
    .hash(uniqueString, saltRounds)
    .then((hashedUniqueString) => {
      // set value in userverification collection
      const newVerification = new UserVerification({
        userId: _id,
        uniqueString: hashedUniqueString,
        createdAt: Date.now(),
        expiresAt: Date.now() + 21600000,
      });
      newVerification
        .save()
        .then(() => {
          transporter
            .sendMail(mailOptions)
            .then(() => {
              // email sent and verification record saved
              res.json({
                status: "PENDING",
                message: "Verification email sent",
              });
            })
            .catch((error) => {
              console.log(error);
              res.json({
                status: "FAILED",
                message: "Verification email failed",
              });
            });
        })
        .catch((error) => {
          console.log(error);
          res.json({
            status: "FAILED",
            message: "Couldn't save verification email data",
          });
        });
    })
    .catch(() => {
      res.json({
        status: "FAILED",
        message: "An error occurred while hashing email data",
      });
    });
};

//  verify email
router.get("/verify/:userId/:uniqueString", (req, res) => {
  let { userId, uniqueString } = req.params;

  UserVerification.find({ userId })
    .then((result) => {
      if (result.length > 0) {
        // user verification record exist so we proceed
        const { expiresAt } = result[0];
        const hashedUniqueString = result[0].uniqueString;
        // checking for expire unique string
        if (expiresAt < Date.now()) {
          // record has expire so delete it
          UserVerification.deleteOne({ userId })
            .then((result) => {
              User.deleteOne({ _id: userId })
                .then(() => {
                  let message = "Link has expired. Please sign up again.";
                  res.redirect(`/user/verified/error=true&message=${message}`);
                })
                .catch((error) => {
                  let message =
                    "Clearing user with expire unique string failed";
                  res.redirect(`/user/verified/error=true&message=${message}`);
                });
            })
            .catch((error) => {
              console.log(error);
              let message =
                "An error occurred while clearing expire user verification record";
              res.redirect(`/user/verified/error=true&message=${message}`);
            });
        } else {
          // valid record exist so we validate the user string
          // first compare the hashed unique
          bcrypt
            .compare(uniqueString, hashedUniqueString)
            .then((result) => {
              if (result) {
                // string match

                User.updateOne({ _id: userId }, { verified: true })
                  .then(() => {
                    UserVerification.deleteOne({ userId })
                      .then(() => {
                        // res.sendFile(path.join(__dirname, "./../views/verified.html"));
                        res.sendFile("./../views/verified.html");
                      })
                      .catch((error) => {
                        console.log(error);
                        let message =
                          "An error occurred while finalizing success verification.";
                        res.redirect(
                          `/user/verified/error=true&message=${message}`
                        );
                      });
                  })
                  .catch((error) => {
                    console.log(error);
                    let message =
                      "An error occurred while updating user record to show verification.";
                    res.redirect(
                      `/user/verified/error=true&message=${message}`
                    );
                  });
              } else {
                // exist record but incorrect verification details passed
                let message =
                  "Invalid verification details passed. check your inbox";
                res.redirect(`/user/verified/error=true&message=${message}`);
              }
            })
            .catch((error) => {
              let message = "An error occurred while comparing unique strings ";
              res.redirect(`/user/verified/error=true&message=${message}`);
            });
        }
      } else {
        // user verification doesn't exist
        let message =
          "Account record doesn't exist or has been verified already. Please sign up or login ";
        res.redirect(`/user/verified/error=true&message=${message}`);
      }
    })
    .catch((error) => {
      console.log(error);
      let message =
        "An error occurred while checking for existing user verification record";
      res.redirect(`/user/verified/error=true&message=${message}`);
    });
});

// Verified page route
router.get("/verified", (req, res) => {
  res.sendFile("https://backend-chulacapstone.vercel.app/views/verified.html");
});

// Signin
router.post("/signin", (req, res) => {
  let { name, password } = req.body;
  name = name.trim();
  password = password.trim();

  if (name == "" || password == "") {
    res.json({
      status: "FAILED",
      message: "Empty credentials supplied",
    });
  } else {
    // check if user exist
    User.find({ name })
      .then((data) => {
        if (data.length) {
          // User exist
          // check if user is verified
          if (!data[0].verified) {
            res.json({
              status: "FAILED",
              message: "Email hasn't been verified yet. check your inbox",
            });
          } else {
            const hashedPassword = data[0].password;
            bcrypt
              .compare(password, hashedPassword)
              .then((result) => {
                if (result) {
                  // create token
                  const token = JWT.sign(
                    {
                      userId: data[0]._id,
                      name: data[0].name,
                      email: data[0].email,
                      userRole: data[0].role,
                    },
                    process.env.TOKEN_KEY,
                    { expiresIn: "12h" }
                  );
                  const filter = { name };
                  const update = { token: token };
                  User.updateOne(filter, update)
                    .then(() => {})
                    .catch((err) => {
                      console.log(err);
                      res.json({
                        status: "FAILED",
                        message: "error occur when update role",
                      });
                    });
                  data[0].token = token;
                  // console.log(JWT.decode(token))
                  res.json({
                    status: "SUCCESS",
                    message: "Signin successful",
                    data: data,
                  });
                } else {
                  res.json({
                    status: "FAILED",
                    message: "Invalid password",
                  });
                }
              })
              .catch((err) => {
                res.json({
                  status: "FAILED",
                  message: "An error occurred while comparing password",
                });
              });
          }
        } else {
          res.json({
            status: "FAILED",
            message: "Invalid credentials entered",
          });
        }
      })
      .catch((err) => {
        res.json({
          status: "FAILED",
          message: "An error occurred while searching for existing user",
        });
      });
  }
});

// Change Password
router.post("/changePassword", auth, (req, res) => {
  let { name, password, newPassword } = req.body;

  // check if user exist
  User.find({ name })
    .then((data) => {
      if (data.length) {
        const hashedPassword = data[0].password;
        bcrypt
          .compare(password, hashedPassword)
          .then((result) => {
            if (result) {
              // change password
              const saltRounds = 10;
              bcrypt
                .hash(newPassword, saltRounds)
                .then((hashedNewPassword) => {
                  // update user password
                  User.updateOne(
                    { _id: data[0] },
                    { password: hashedNewPassword }
                  )
                    .then(() => {
                      res.json({
                        status: "SUCCESS",
                        message: "Change password successfully",
                      });
                    })
                    .catch((error) => {
                      console.log(error);
                      res.json({
                        status: "FAILED",
                        message: "Change password failed",
                      });
                    });
                })
                .catch((error) => {
                  console.log(error);
                  res.json({
                    status: "FAILED",
                    message: "An error occurred while hashing new password",
                  });
                });
            } else {
              res.json({
                status: "FAILED",
                message: "Old password doesn't matched",
              });
            }
          })
          .catch((err) => {
            res.json({
              status: "FAILED",
              message: "An error occurred while comparing password",
            });
          });
      } else {
        res.json({
          status: "FAILED",
          message: "Invalid credentials entered",
        });
      }
    })
    .catch((err) => {
      res.json({
        status: "FAILED",
        message: "An error occurred while searching for existing user",
      });
    });
});

// Password reset stuff
router.post("/requestPasswordReset", (req, res) => {
  const { email, redirectUrl } = req.body;

  // check if email exist
  User.find({ email })
    .then((data) => {
      if (data.length) {
        // user exist

        // check if user is verified
        if (!data[0].verified) {
          res.json({
            status: "FAILED",
            message: "Email hasn't been verified yet. Check your inbox",
          });
        } else {
          sendResetEmail(data[0], redirectUrl, res);
        }
      } else {
        res.json({
          status: "FAILED",
          message: "No account with the supplied email exists",
        });
      }
    })
    .catch((error) => {
      console.log(error);
      res.json({
        status: "FAILED",
        message: "An error occurred while checking for existing user",
      });
    });
});

// send password reset email
const sendResetEmail = ({ _id, email }, redirectUrl, res) => {
  const resetString = uuidv4() + _id;

  // first we clear all existing reser recourds
  PasswordReset.deleteMany({ userId: _id })
    .then((result) => {
      // reset records deleted successfully
      // now we send the email

      // mail options
      const mailOptions = {
        from: process.env.AUTH_EMAIL,
        to: email,
        subject: "Password Reset",
        html: `<p>We heard that you lost the password.</p><p>Don't worry, use the link below to reset it</p>
    <p>This link <b>expires in 60 minutes</b>.</p><p>Press <a href=${
      redirectUrl + "/" + _id + "/" + resetString
    }>here</a> to proceed.</p>`,
      };

      // hash the reset string
      const saltRounds = 10;
      bcrypt
        .hash(resetString, saltRounds)
        .then((hashedResetString) => {
          // set value in password reset collection
          const newPasswordReset = new PasswordReset({
            userId: _id,
            resetString: hashedResetString,
            createdAt: Date.now(),
            expiresAt: Date.now() + 3600000,
          });

          newPasswordReset
            .save()
            .then(() => {
              transporter
                .sendMail(mailOptions)
                .then(() => {
                  // reset email sent and password reset record saved
                  res.json({
                    status: "PENDING",
                    message: "Password reset email sent",
                  });
                })
                .catch((error) => {
                  console.log(error);
                  res.json({
                    status: "FAILED",
                    message: "Password reset email failed",
                  });
                });
            })
            .catch((error) => {
              console.log(error);
              res.json({
                status: "FAILED",
                message: "Couldn't save password reset data",
              });
            });
        })
        .catch((error) => {
          console.log(error);
          res.json({
            status: "FAILED",
            message: "An error occurred while hashing the password reset data",
          });
        });
    })
    .catch((error) => {
      console.log(error);
      res.json({
        status: "FAILED",
        message: "clearing existing password reset records failed",
      });
    });
};

// Actually reset the password
router.post("/resetPassword", (req, res) => {
  let { userId, resetString, newPassword } = req.body;

  PasswordReset.find({ userId })
    .then((result) => {
      if (result.length > 0) {
        // password reset record exist so we proceed

        const { expiresAt } = result[0];
        const hashedResetString = result[0].resetString;
        // checking for expired reset string
        if (expiresAt < Date.now()) {
          PasswordReset.deleteOne({ userId })
            .then(() => {
              // reset record delete successfully
              res.json({
                status: "FAILED",
                message: "Password reset link expired",
              });
            })
            .catch((error) => {
              console.log(error);
              res.json({
                status: "FAILED",
                message: "clearing password reset record failed",
              });
            });
        } else {
          // valid reset record exist so we validate the reset string
          // first compare the hashed reset string

          bcrypt
            .compare(resetString, hashedResetString)
            .then((result) => {
              if (result) {
                // string match
                // hash password again

                const saltRounds = 10;
                bcrypt
                  .hash(newPassword, saltRounds)
                  .then((hashedNewPassword) => {
                    // update user password
                    User.updateOne(
                      { _id: userId },
                      { password: hashedNewPassword }
                    )
                      .then(() => {
                        // update complete now delete reset record
                        PasswordReset.deleteOne({ userId })
                          .then(() => {
                            // both user record and reset record updated
                            res.json({
                              status: "SUCCESS",
                              message: "Password has been reset successfully",
                            });
                          })
                          .catch((error) => {
                            console.log(error);
                            res.json({
                              status: "FAILED",
                              message:
                                "An error occurred while finalizing password reset",
                            });
                          });
                      })
                      .catch((error) => {
                        console.log(error);
                        res.json({
                          status: "FAILED",
                          message: "Updating user password failed",
                        });
                      });
                  })
                  .catch((error) => {
                    console.log(error);
                    res.json({
                      status: "FAILED",
                      message: "An error occurred while hashing new password",
                    });
                  });
              } else {
                // existing record but incorrect reset string passed
                res.json({
                  status: "FAILED",
                  message: "Invalid password reset details passed",
                });
              }
            })
            .catch((error) => {
              console.log(error);
              res.json({
                status: "FAILED",
                message: "comparing password reset string failed",
              });
            });
        }
      } else {
        // password reset record doesn't exist
        res.json({
          status: "FAILED",
          message: "Password reset request not found",
        });
      }
    })
    .catch((error) => {
      console.log(error);
      res.json({
        status: "FAILED",
        message: "checking for existing password reset record failed",
      });
    });
});

///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// S3
const multer = require("multer");
const sharp = require("sharp");
const crypto = require("crypto");
const {
  s3Client,
  uploadFile,
  deleteFile,
  getObjectSignedUrl,
} = require("../s3.js");

// app.set('view engine', 'ejs')
// app.use(express.static("public"))

const storage = multer.memoryStorage();
const upload = multer({ storage: storage });

const generateFileName = (bytes = 32) =>
  crypto.randomBytes(bytes).toString("hex");

router.post("/index/image", auth, async (req, res) => {
  const { imagename } = req.body;
  let temp = await getObjectSignedUrl(imagename);
  let imageUrl = temp[0];
  let str = temp[1];
  const token = req.headers["x-access-token"];
  const data = JWT.decode(token);

  UserImage.findOne(
    { username: data.name, imagename: imagename },
    { text: 1, label: 1, _id: 0 }
  )
    .then((result) => {
      res.json({
        imageurl: imageUrl,
        string: str,
        text: result.text,
        label: result.label,
      });
    })
    .catch((err) => {
      res.json({
        status: "FAILED",
        message: "an error occurred while getting an image",
      });
    });
});

router.post("/posts", auth, upload.single("image"), async (req, res) => {
  // Decode the base64 string to a buffer
  const buffer = Buffer.from(req.body.enc, "base64");
  // const file = req.file;
  // const caption = req.body.caption
  const token = req.headers["x-access-token"];
  const data = JWT.decode(token);
  const imageName =
    data.name + "-" + generateFileName() + "-" + req.body.imgname; //generateFileName()

  const fileBuffer = buffer; //await sharp(file.buffer).toBuffer();
  console.log(fileBuffer);
  // .resize({ height: 500, width: 1080, fit: "contain" })
  // .toBuffer()
  await uploadFile(fileBuffer, imageName);
  // save to db
  const newUserImage = new UserImage({
    username: data.name,
    imagename: imageName,
    text: req.body.text,
    label: "",
  });

  newUserImage
    .save()
    .then()
    .catch((err) => {
      console.log(err);
      res.json({
        status: "FAILED",
        message: "an error occurred while saving image to s3",
      });
    });

  res.status(201).json({ status: "save to s3 done", imagename: imageName });
});

// get all own user's images
router.get("/userimg", auth, (req, res) => {
  const data = JWT.decode(req.headers["x-access-token"]);
  UserImage.find(
    { username: data.name },
    { imagename: 1, text: 1, label: 1, _id: 0 }
  )
    .then((result) => {
      res.json(result);
    })
    .catch((err) => {
      console.log(err);
      res.json({
        status: "FAILED",
        message: "an error occurred while get userimage",
      });
    });
});

// user delete their own image
router.post("/deletePost", auth, async (req, res) => {
  // const id = +req.params.id
  // const post = await prisma.posts.findUnique({where: {id}})
  const data = JWT.decode(req.headers["x-access-token"]);
  const { imageName } = req.body;

  await deleteFile(imageName);

  UserImage.deleteOne({ username: data.name, imagename: imageName })
    .then(() => {
      res.json({ status: "SUCCESS", message: "UserImage deleted" });
    })
    .catch((err) => {
      res.json({
        status: "FAILED",
        message: "an error occurred while deleting userImage",
      });
    });
});

// add text to image
router.post("/addtext", auth, (req, res) => {
  const data = JWT.decode(req.headers["x-access-token"]);
  const { imageName, newText } = req.body;

  UserImage.updateOne(
    { username: data.name, imagename: imageName },
    { text: newText }
  )
    .then(() => {
      res.status(200).json({ status: "SUCCESS", message: "update completed" });
    })
    .catch((err) => {
      res.json({
        status: "FAILED",
        message: "an error occurred while updating new text.",
      });
    });
});

// add label to image
router.post("/addlabel", auth, (req, res) => {
  const data = JWT.decode(req.headers["x-access-token"]);
  const { imageName, newLabel } = req.body;

  UserImage.updateOne(
    { username: data.name, imagename: imageName },
    { label: newLabel }
  )
    .then(() => {
      res.status(200).json({ status: "SUCCESS", message: "update completed" });
    })
    .catch((err) => {
      res.json({
        status: "FAILED",
        message: "an error occurred while updating new label.",
      });
    });
});
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

// sent image to model
router.post("/sent/model", auth, (req, res) => {
  let { isConvertedRaw, base64image } = req.body;
  let endpoint = "http://18.142.56.142:5000/ocr";
  if (isConvertedRaw) {
    endpoint = "http://18.142.56.142:5000/ocr_raw";
  }
  const a = { image: base64image };

  const b = {
    headers: { "Content-Type": "application/json", Accept: "application/json" },
  };

  axios
    .post(endpoint, a, b)
    .then((response) => {
      res.json({ status: "SUCCESS", message: response.data });
    })
    .catch((error) => {
      res.json({
        status: "FAILED",
        message: "an error occurred when sending image to model",
      });
      if (error.response) {
        // handle 4xx or 5xx responses
        console.log(error.response.data);
        console.log(error.response.status);
        console.log(error.response.headers);
      } else if (error.request) {
        // handle request errors (such as a network failure)
        console.log(error.request);
      } else {
        // handle other errors
        console.log("Error", error.message);
      }
    });
});

module.exports = router;
