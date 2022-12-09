# syntax=docker/dockerfile:1

FROM python:3.10-alpine

LABEL org.opencontainers.image.authors="wangyihanger@gmail.com"

RUN sed -i 's/dl-cdn.alpinelinux.org/mirrors.ustc.edu.cn/g' /etc/apk/repositories
RUN apk update
RUN apk add git

RUN git clone https://github.com/WangYihang/GitHacker.git
RUN cd GitHacker && pip install -r requirements.txt && python setup.py install

ENTRYPOINT ["githacker"]