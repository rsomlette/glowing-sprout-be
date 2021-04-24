const { Schema, model } = require("mongoose");

const RecipeSchema = new Schema({
  name: {
    type: String,
    required: true,
  },
  category: {
    type: [String],
    required: true,
  },
  description: {
    type: String,
    required: true,
  },
  instructions: {
    type: [String],
    required: true,
  },
  createdDate: {
    type: Date,
    default: Date.now,
  },
  likes: {
    type: Number,
    default: 0,
  },
  author: {
    type: String,
    required: true,
  },
});

module.exports = model("Recipe", RecipeSchema);
