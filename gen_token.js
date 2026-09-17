const jwt = require('jsonwebtoken');
console.log(jwt.sign({email:'test@example.com', name:'Test User'}, 'testsecret', {algorithm:'HS256'}));
