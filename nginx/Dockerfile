FROM nginx:alpine
COPY nginx.conf /etc/nginx/nginx.conf
RUN rm -f /etc/nginx/conf.d/default.conf
EXPOSE 80
CMD sh -c "nginx -T && apk add --no-cache curl && curl http://function-bun.railway.internal && curl function-bun-copy.railway.internal && nginx -g 'daemon off;'"
