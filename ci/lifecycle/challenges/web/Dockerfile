FROM busybox:1.36 AS base
RUN mkdir /challenge /www

FROM base AS challenge
ARG FLAG
COPY version.txt /www/index.html
RUN echo "{\"flag\":\"$FLAG\"}" > /challenge/metadata.json
RUN echo "notes" > /notes.txt && tar czf /challenge/artifacts.tar.gz -C / notes.txt
CMD ["httpd", "-f", "-p", "4242", "-h", "/www"]

EXPOSE 4242
# PUBLISH 4242 AS http
