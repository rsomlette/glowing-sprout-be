const dotenv = require("dotenv");

const env = dotenv.config();

if (env.error) throw env.error;

module.exports = env.parsed;
