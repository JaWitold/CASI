FROM nginx:latest

# Copy your custom Nginx configuration
COPY nginx.conf /etc/nginx/conf.d/default.conf

# Copy SSL/TLS certificates and private key
COPY ssl/ /etc/nginx/ssl/
COPY index.html /usr/share/nginx/html/index.html