const crypto = require("crypto");

const CONFIRMATION_TOKEN_BYTES = 32;

function createConfirmationToken() {
  const token = crypto.randomBytes(CONFIRMATION_TOKEN_BYTES).toString("hex");
  return {
    token,
    tokenHash: hashConfirmationToken(token)
  };
}

function hashConfirmationToken(token) {
  return crypto.createHash("sha256").update(token).digest("hex");
}

function isValidConfirmationToken(token) {
  return typeof token === "string" && /^[a-f0-9]{64}$/.test(token);
}

module.exports = {
  createConfirmationToken,
  hashConfirmationToken,
  isValidConfirmationToken
};
