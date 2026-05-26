FROM node:20-alpine

# Install pg client tools (optional, useful for debugging)
RUN apk add --no-cache postgresql-client

WORKDIR /usr/src/app

COPY package*.json ./

RUN npm ci --only=production

COPY . .

EXPOSE 5013

# The application handles automatic DB creation & migration on start.
CMD ["npm", "start"]
