# Multi-stage build for CloudGuard Obsidian Command Center
FROM node:20-alpine AS builder

WORKDIR /app

# Install build dependencies
COPY package*.json ./
RUN npm ci

# Copy source code and build production bundle
COPY . .
RUN npm run build

# Production runtime stage with Nginx
FROM nginx:alpine

# Create SSL directory and copy TLS certificates
RUN mkdir -p /etc/nginx/ssl
COPY ssl/ /etc/nginx/ssl/

# Copy custom Nginx configuration
COPY nginx.conf /etc/nginx/conf.d/default.conf

# Copy compiled static assets from builder stage
COPY --from=builder /app/dist /usr/share/nginx/html

EXPOSE 80 443

HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 \
    CMD wget --quiet --tries=1 --spider --no-check-certificate https://localhost/health || exit 1

CMD ["nginx", "-g", "daemon off;"]
