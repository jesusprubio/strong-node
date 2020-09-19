'use strict'

const Hapi = require('@hapi/hapi');

const init = async () => {

    const server = Hapi.server({
        port: 3000,
        host: 'localhost'
    });

    server.route({
      method: 'GET',
      path: '/',
      handler: () => 'Hi world!!'
    });

    server.route({
      method: 'GET',
      path: '/break',
      handler: () => {
        throw new Error('Oh no!');
      }
    });

    await server.start();
    console.log(`Listening on: ${server.info.uri}`);
};

init();
