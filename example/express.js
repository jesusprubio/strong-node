'use strict'

// To disable the debug stuff in the client side start this with:
// NODE_ENV=production node example/express

const express = require('express');

const app = express();


app.get('/', (req, res) => res.send('Hi world!'));

// Uncomment to solve the risk.
// app.disable('x-powered-by');

// Force an error.
app.get('/break', (req, res) => { throw new Error('Oh no!'); });


app.listen(3000, () => console.log('Listening on: http://localhost:3000'));
