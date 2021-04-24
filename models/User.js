const { Schema, model } = require("mongoose");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const env = require("../config/env");
const { ApolloError } = require("apollo-server");

const createToken = (user, secret, expiresIn) => {
  const { username, email, _id } = user;
  console.log(user);
  return jwt.sign({ username, email }, secret, { expiresIn });
};

const getUser = async (token) => {
  console.log("1.", token);
  if (!token) return null;

  const bearer = token.split(" ");
  const bearerToken = bearer[1];

  try {
    const user = await jwt.verify(bearerToken, env.SECRET);

    console.log("2.", user);
    return user;
  } catch (err) {
    if (err.name === "TokenExpiredError") {
      throw new ApolloError("Token expired", 401);
    }
    return null;
  }
};

const verifyPassword = async (password, userPassword) =>
  await bcrypt.compare(password, userPassword);

const UserSchema = new Schema({
  username: {
    type: String,
    required: true,
    unique: true,
  },
  password: {
    type: String,
    required: true,
  },
  email: {
    type: String,
    required: true,
  },
  joinDate: {
    type: Date,
    default: Date.now,
  },
  favorites: {
    type: [Schema.Types.ObjectId],
    ref: "Recipe",
  },
});

UserSchema.pre("save", function (next) {
  var user = this;

  // only hash the password if it has been modified (or is new)
  if (!user.isModified("password")) return next;

  // generate a salt
  bcrypt.genSalt(parseInt(env.SALT_WORK_FACTOR || 10, 10), (err, salt) => {
    if (err) return next(err);

    // hash the password along with our new salt
    bcrypt.hash(user.password, salt, (err, hash) => {
      if (err) return next(err);

      // override the cleartext password with the hashed one
      user.password = hash;
      next();
    });
  });
});

module.exports = {
  User: model("User", UserSchema),
  createToken,
  getUser,
  verifyPassword,
};
