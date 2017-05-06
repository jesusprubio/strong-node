'use strict'

const Hapi = require('hapi');

const server = new Hapi.Server();


server.connection({
  host: 'localhost',
  port: 3000,
});

server.route({
  method: 'GET',
  path: '/',
  handler: (req, rep) => reply('Hi world!'),
});

server.route({
  method: 'GET',
  path: '/break',
  handler: (req, rep) => { throw new Error('Oh no!'); },
});


server.start((err) => {
  if (err) { throw err; }

  console.log(`Listening on: ${server.info.uri}`);
});
