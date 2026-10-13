const { FuzzedDataProvider } = require("@jazzer.js/core");
const commandExists = require("/work/target");

module.exports.fuzz = function (data) {
  const provider = new FuzzedDataProvider(data);
  const name = provider.consumeRemainingAsString();
  try {
    commandExists.sync(name);
  } catch (e) {
    if (e && e.name === "Finding") throw e;
  }
};
