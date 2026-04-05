FROM nginx:alpine
COPY nginx.conf /etc/nginx/nginx.conf
RUN rm -f /etc/nginx/conf.d/default.conf
EXPOSE 80
CMD sh -c "nginx -T && nslookup server-1.railway.internal && nginx -g 'daemon off;'"
