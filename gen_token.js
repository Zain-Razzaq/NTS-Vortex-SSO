const crypto = require('crypto');
const jwt = require('jsonwebtoken');

// Mirrors the real NTS CRM token shape (see email from Sajid's team) so it
// can be used to test /auth/sso locally against the iss/aud/jti checks.
console.log(
  jwt.sign(
    {
      jti: crypto.randomUUID(),
      name: 'Test User',
      email: 'test@example.com',
      sub: '90587',
    },
    'testsecret',
    {
      algorithm: 'HS256',
      issuer: 'crm.ntsconnect.com',
      audience: 'authenticated',
      expiresIn: '5m',
    }
  )
);
