FROM node:22-alpine

WORKDIR /app

# Copy package files
COPY package*.json ./

# Install dependencies (akan dikompilasi untuk Linux)
RUN npm install --production

# Copy source code
COPY . .

# Expose port
EXPOSE 3000

# Start server
CMD ["npm", "start"]
