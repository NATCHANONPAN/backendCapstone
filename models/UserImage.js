const mongoose = require("mongoose");
const Schema = mongoose.Schema;

const UserImageSchema = new Schema({
  username: String,
  imagename: String,
  text: String,
  label: String,
  boundingbox: [],
});

const UserImage = mongoose.model("UserImage", UserImageSchema);

module.exports = UserImage;