const { ApolloError } = require("apollo-server");
const env = require("../config/env");
const Recipe = require("../models/Recipe");
const { User, verifyPassword, createToken } = require("../models/User");

const resolvers = {
  Query: {
    recipes: async (root, args, { currentUser }) => {
      if (!currentUser) return null;
      return await Recipe.find({});
    },
    users: () => User.find({}),
    viewer: async (root, args, { currentUser }) => {
      if (!currentUser) return null;
      console.log("currentUser: ", currentUser);
      const user = await User.findOne({
        username: currentUser.username,
      }).populate({
        path: "favorites",
        model: "Recipe",
      });
      console.log("RESULT: ", user);
      return user;
    },
  },
  Mutation: {
    addRecipe: async (
      root,
      { name, description, category, instructions, author },
      context
    ) => {
      const newRecipe = await new Recipe({
        name,
        description,
        category,
        instructions,
        author,
      }).save();
      return newRecipe;
    },
    login: async (root, { username, password }) => {
      const user = await User.findOne({ username });
      if (!user) throw new Error("User not found");
      const isValidPassword = await verifyPassword(password, user.password);
      if (!isValidPassword) throw new Error("Invalid password");
      return { token: createToken(user, env.SECRET, "1hr") };
    },
    signupUser: async (root, { username, email, password }) => {
      const user = await User.findOne({ username });
      if (user) throw new Error("User already exist");
      const newUser = await new User({ username, email, password }).save();
      return { token: createToken(newUser, env.SECRET, "1hr") };
    },
  },
};

module.exports = resolvers;
