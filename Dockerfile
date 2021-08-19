FROM centos:latest
LABEL author="felipe mattos"
LABEL name="ssl-pooch docker image"

ARG TZ
ENV TZ ${TZ}

COPY --chown=root:root ./ /ssl-pooch/
RUN yum update -y && yum install -y crontabs openssl mktemp sed wget bc && \
    chmod +x /ssl-pooch/ssl-pooch.sh && \
    chmod +x /ssl-pooch/conf/config.ssl-pooch.env && \
    ln /ssl-pooch/ssl-pooch.sh /usr/bin/ssl-pooch && \
    ln -sf /usr/share/zoneinfo/${TZ} /etc/localtime && \
    echo "* * * * * root  echo "crontab-test" >> /tmp/cron-test.log 2>&1 > /dev/null" >> /etc/crontab

WORKDIR /ssl-pooch
ENTRYPOINT ["/usr/sbin/crond", "-n"]
