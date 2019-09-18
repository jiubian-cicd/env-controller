FROM golang:1.12.7
ENV GO111MODULE on
WORKDIR /go/src/github.com/jiubian-cicd/env-controller/
COPY . .
RUN make build


FROM registry.cn-shenzhen.aliyuncs.com/jenkinsxio/builder-maven:0.1.645
MAINTAINER jiubian
RUN yum -y install tcpdump net-tools
RUN helm plugin install https://github.com/AliyunContainerService/helm-acr
COPY --from=0 /go/src/github.com/jiubian-cicd/env-controller/bin/envctl  /usr/bin/envctl
ENTRYPOINT ["envctl"]
CMD ["controller", "environment"]
