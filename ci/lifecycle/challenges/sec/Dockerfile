FROM busybox:1.36 AS base
RUN mkdir /challenge /www

FROM base AS challenge
ARG FLAG
RUN echo "{\"flag\":\"$FLAG\"}" > /challenge/metadata.json && echo sec > /www/index.html
CMD ["httpd", "-f", "-p", "4242", "-h", "/www"]

EXPOSE 4242
# PUBLISH 4242 AS http
