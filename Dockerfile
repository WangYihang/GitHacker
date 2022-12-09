# syntax=docker/dockerfile:1

FROM python:3.11-alpine AS builder
LABEL org.opencontainers.image.authors="wangyihanger@gmail.com"
RUN sed -i 's/dl-cdn.alpinelinux.org/mirrors.ustc.edu.cn/g' /etc/apk/repositories
RUN apk update
RUN apk add git
WORKDIR /app
RUN git clone https://github.com/WangYihang/GitHacker.git
RUN cd GitHacker && pip install -r requirements.txt && python setup.py sdist bdist_wheel

FROM python:3.11-alpine 
COPY --from=builder /app/GitHacker/dist/ /app/
RUN pip install /app/*.whl
ENV GIT_PYTHON_REFRESH=quiet

ENTRYPOINT ["githacker"]