const { gql } = require("apollo-server-express");

const typeDefs = gql`
  type Recipe {
    _id: ID
    name: String!
    category: [String]!
    description: String!
    instructions: [String]!
    createdDate: String
    likes: Int
    username: String
  }

  type User {
    _id: ID
    username: String!
    password: String!
    email: String!
    joinDate: String
    favorites: [Recipe]
  }

  type Query {
    recipes: [Recipe]
    users: [User]
    viewer: User
  }

  type Mutation {
    addRecipe(
      name: String!
      category: String!
      description: String!
      instructions: String!
      author: String!
    ): Recipe
    signupUser(username: String!, email: String!, password: String!): Token
    login(username: String!, password: String!): Token
  }

  type Token {
    token: String!
  }
`;

module.exports = typeDefs;
