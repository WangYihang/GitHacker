# syntax=docker/dockerfile:1

FROM python:3.10-alpine

LABEL org.opencontainers.image.authors="wangyihanger@gmail.com"

RUN sed -i 's/dl-cdn.alpinelinux.org/mirrors.ustc.edu.cn/g' /etc/apk/repositories
RUN apk update
RUN apk add git

RUN python3 -m pip install -i https://pypi.org/simple/ GitHacker

ENTRYPOINT ["githacker"]