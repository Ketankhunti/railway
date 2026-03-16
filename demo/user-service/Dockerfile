FROM node:20-slim
WORKDIR /app
COPY package.json .
RUN npm install --production
COPY app.js .
LABEL rail.project="proj_demo"
LABEL rail.service="user-service"
LABEL rail.env="production"
EXPOSE 8002
CMD ["node", "app.js"]
