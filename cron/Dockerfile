FROM node:20-slim
WORKDIR /
COPY package*.json ./
RUN npm install --production
COPY . .
CMD ["node", "index.js"]
