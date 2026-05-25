# Stage 1: Build React Production Package
FROM node:20-alpine AS build

WORKDIR /app

# Copy package descriptors and run fast install
COPY package*.json ./
RUN npm install

# Copy source and compile code
COPY . .
RUN npm run build

# Stage 2: Load lightweight static webserver (Nginx)
FROM nginx:1.25-alpine

# Copy built files from the first stage
COPY --from=build /app/dist /usr/share/nginx/html

# Overwrite default Nginx configs with our proxy configurations
COPY nginx.conf /etc/nginx/conf.d/default.conf

EXPOSE 80

CMD ["nginx", "-g", "daemon off;"]
