# Intentionally using an older base image with known vulnerabilities
FROM node:18-alpine

WORKDIR /app

# Copy package files
COPY package*.json ./

# Install dependencies (including dev deps for TypeScript)
RUN npm install

# Copy application
COPY . .

# Build TypeScript with proper settings
RUN npx tsc vulnerable-api.ts --outDir dist --esModuleInterop --module commonjs --target ES2020 --lib ES2020 --moduleResolution node --skipLibCheck

# Expose port
EXPOSE 3000

# Run the vulnerable API
CMD ["node", "dist/vulnerable-api.js"]
