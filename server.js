const { ApolloServer } = require("apollo-server");
const mongoose = require("mongoose");
const logger = require("pino")();

const env = require("./config/env");

const typeDefs = require("./graphql/schema");
const resolvers = require("./graphql/resolvers");
const { getUser } = require("./models/User");

const server = new ApolloServer({
  typeDefs,
  resolvers,
  logger,
  formatError: (err) => {
    logger.warn(err);
    return err;
  },
  context: async ({ req }) => {
    // Note! This example uses the `req` object to access headers,
    // but the arguments received by `context` vary by integration.
    // This means they will vary for Express, Koa, Lambda, etc.!
    //
    // To find out the correct arguments for a specific integration,
    // see the `context` option in the API reference for `apollo-server`:
    // https://www.apollographql.com/docs/apollo-server/api/apollo-server/

    // Get the user token from the headers.

    return {
      currentUser: await getUser(req.headers.authorization),
    };
  },
});

mongoose
  .connect(env.MONGO_URI, {
    useNewUrlParser: true,
    useUnifiedTopology: true,
    useCreateIndex: true,
  })
  .then(() => logger.info("📚  Connected to the database"))
  .catch((err) => logger.error("💥  ", err));

mongoose.connection.once("open", () =>
  logger.info("🔮  Connected to a MongoDB instance")
);

mongoose.connection.on("error", (error) => logger.error(error));

server.listen().then(({ url }) => logger.info(`🚀  Server ready at ${url}`));
