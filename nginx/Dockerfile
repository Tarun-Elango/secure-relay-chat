FROM nginx:alpine
COPY nginx.conf /etc/nginx/nginx.conf
RUN rm -f /etc/nginx/conf.d/default.conf
EXPOSE 80
CMD sh -c "\
  echo '=== DNS ===' && \
  nslookup function-bun.railway.internal && \
  echo '=== CURL IPv6 ===' && \
  curl -v --max-time 5 'http://function-bun.railway.internal:8080/' && \
  echo '=== NGINX ===' && \
  nginx -g 'daemon off;'"
