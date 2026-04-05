FROM nginx:alpine
COPY nginx.conf /etc/nginx/nginx.conf
RUN rm -f /etc/nginx/conf.d/default.conf
EXPOSE 80
CMD sh -c "
nginx -T &&
apk add --no-cache curl &&
curl http://server-1.railway.internal &&
curl http://server-2.railway.internal &&
nginx -g 'daemon off;'
"
