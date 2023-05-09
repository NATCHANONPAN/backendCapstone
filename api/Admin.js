const express = require("express");
const Adminrouter = express.Router();

// token for user
const JWT = require('jsonwebtoken');

// mongodb user model
const User = require("./../models/User");

// auth
const auth = require('../middleware/auth');

// check role
const {authRole} = require("../middleware/authRole");

// mongodb userimage model
const UserImage = require("./../models/UserImage");

const {s3Client, uploadFile, deleteFile, getObjectSignedUrl} = require("../s3.js");

// get all user list
Adminrouter.get("/userlist", auth, authRole(["admin"]), (req, res) => {
    User.find({}, {name:1,_id:0}).then((result) => {
        res.json(result)
    }).catch(err => {
        console.log(err);
        res.json({status:"FAILED", message:"an error occurred while get all user"})
    })});

// get images of selected user
Adminrouter.get('/userimg', auth, authRole(["admin"]), (req, res) => {
    UserImage.find({username:req.body.name}, {imagename: 1, text:1, label:1, _id:0}).then((result) => {
        res.json(result)
    }).catch(err => {
        console.log(err);
        res.json({status:"FAILED", message:"an error occurred while get userimage"})
    })
});

// admin delete user's image
Adminrouter.post("/deletePost", auth, authRole(["admin"]), async (req, res) => {
    // const id = +req.params.id
    // const post = await prisma.posts.findUnique({where: {id}})
    const data = JWT.decode(req.headers["x-access-token"]);
    const {username,imageName} = req.body;
  
    await deleteFile(imageName)
  
    UserImage.deleteOne({username:username, imagename:imageName}).then(() => {
      res.json({status: "SUCCESS", message: "UserImage deleted"})
    }).catch(err => {
      res.json({status: "FAILED", message: "an error occurred while deleting userImage"})
    })
  })

// admin get an image of user
Adminrouter.post("/index/image", auth, authRole(["admin"]), async (req, res) => {
    const {username, imagename} = req.body;
    let temp = await getObjectSignedUrl(imagename);
    let imageUrl = temp[0];
    let str = temp[1];

    const token = req.headers['x-access-token'];
    const data = JWT.decode(token);

    UserImage.findOne({username:username, imagename:imagename},{text:1, label:1, _id: 0 }).then((result) => {
        console.log(result);
        res.json({imageurl:imageUrl, string:str, text:result.text, label:result.label})
    }).catch(err => {
        res.json({status:"FAILED", message:'an error occurred while getting an image'})
    })
  })


  module.exports = Adminrouter;