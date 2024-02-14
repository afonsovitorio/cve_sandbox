FROM httpd:latest

COPY ./payload/ /usr/local/apache2/htdocs/
COPY ./apache/httpd.conf /usr/local/apache2/conf/
COPY ./apache/httpd-ssl.conf /usr/local/apache2/conf/extra/
COPY ./apache/server.key /usr/local/apache2/conf/
COPY ./apache/server.crt /usr/local/apache2/conf/
