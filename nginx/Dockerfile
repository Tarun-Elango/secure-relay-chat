FROM nginx:alpine
COPY nginx.conf /etc/nginx/nginx.conf
RUN rm -f /etc/nginx/conf.d/default.conf
EXPOSE 80
CMD sh -c "nginx -T && apk add --no-cache curl && echo 'Testing backend...' && curl --max-time 2 http://function-bun.railway.internal:8080 || echo 'server 1 failed' && curl --max-time 2 http://function-bun-copy.railway.internal:8080 || echo 'server 2 failed' && nginx -g 'daemon off;'"
