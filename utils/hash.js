/**
 * Hash password function
 */
const crypto = require('crypto');

const hashPassword = (password) => {
  const salt = crypto.randomBytes(32).toString('hex');
  const hash = crypto.pbkdf2Sync(password, salt, 100000, 64, 'sha512').toString('hex');
  return `${salt}:${hash}`;
};

const checkPassword = (password, hashedPassword) => {
  const [salt, hash] = hashedPassword.split(':');
  const newHash = crypto.pbkdf2Sync(password, salt, 100000, 64, 'sha512').toString('hex');
  return newHash === hash;
};

module.exports = { hashPassword, checkPassword };