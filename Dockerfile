FROM registry.cn-shenzhen.aliyuncs.com/jenkinsxio/builder-maven:0.1.645
MAINTAINER jiubian
RUN yum -y install tcpdump net-tools
ADD bin/envCtl /usr/bin/envCtl

