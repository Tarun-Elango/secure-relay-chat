FROM nginx:alpine
COPY nginx.conf /etc/nginx/nginx.conf
RUN rm -f /etc/nginx/conf.d/default.conf
EXPOSE 80
CMD sh -c "curl -v http://function-bun.railway.internal:8080/ 2>&1 | head -30 && nginx -g 'daemon off;'"
