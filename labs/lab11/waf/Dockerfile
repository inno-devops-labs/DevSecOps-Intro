FROM owasp/modsecurity-crs:4.25.1-nginx-alpine-lts

USER root

RUN mkdir -p /var/log/modsec \
    && chown nginx:nginx /var/log/modsec

RUN sed -i '/^proxy_ssl_certificate /d; /^proxy_ssl_certificate_key /d' /etc/nginx/templates/includes/proxy_backend_ssl.conf.template
