FROM node:22-alpine
WORKDIR /app

# Copy the entire package (we're testing our own middleware)
COPY package*.json ./
COPY lib ./lib

# Copy only the server file
COPY test/docker/backend/server.js ./server.js

EXPOSE 3000
CMD ["node", "server.js"]
