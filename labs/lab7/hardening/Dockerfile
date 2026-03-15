FROM node:20-alpine

WORKDIR /app

RUN addgroup -S appgroup && adduser -S appuser -G appgroup

COPY package*.json ./

RUN npm install --production

COPY . .

USER appuser

EXPOSE 3000

CMD ["node", "server.js"]
