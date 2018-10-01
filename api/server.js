import express from 'express'
import { ApolloServer } from 'apollo-server-express'
import fs from 'fs'
import https from 'https'
import resolvers from './graphql/resolvers'
import typeDefs from './graphql/schema'

const configurations = {
  // Note: You may need sudo to run on port 443
  production: { ssl: true, port: 443, hostname: 'pinstery.com' },
  development: { ssl: false, port: 4000, hostname: 'localhost' },
}

const environment = process.env.NODE_ENV || 'production'
const config = configurations[environment]

const apollo = new ApolloServer({ typeDefs, resolvers })

const app = express()
apollo.applyMiddleware({ app })

const server = https.createServer(
  {
    key: fs.readFileSync('../ssl/privkey.pem'),
    cert: fs.readFileSync('../ssl/fullchain.pem'),
  },
  app,
)

server.listen({ port: config.port }, () => console.log(
  '🚀 Server ready at',
  `http${config.ssl ? 's' : ''}://${config.hostname}:${config.port}${apollo.graphqlPath}`,
))
