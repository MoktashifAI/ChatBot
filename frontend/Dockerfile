# Frontend Dockerfile for React app
FROM node:18-alpine AS build

WORKDIR /app

COPY package.json package-lock.json ./
RUN npm ci

COPY . .
RUN npm run build

# Production image
FROM node:18-alpine AS prod
WORKDIR /app

# Install serve to serve static files
RUN npm install -g serve

# Copy build output from previous stage
COPY --from=build /app/build ./build

EXPOSE 3000

CMD ["serve", "-s", "build", "-l", "3000"] 
