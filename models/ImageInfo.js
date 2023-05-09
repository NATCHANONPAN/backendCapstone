const mongoose = require("mongoose");
const Schema = mongoose.Schema;

const ImageInfoSchema = new Schema({
  name: String,
  text: String,
  label: String,
  boundingbox: [],
});

const ImageInfo = mongoose.model("ImageInfo", ImageInfoSchema);

module.exports = ImageInfo;