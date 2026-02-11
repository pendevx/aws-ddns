FROM node:20-slim
WORKDIR /app
COPY package.json /app
COPY pnpm-lock.yaml /app
RUN npm install --omit=dev
COPY . .
CMD ["node", "cron.js"]
