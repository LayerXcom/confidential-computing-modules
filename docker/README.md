# Anonify docker files

In the project root directory, you can build docker files by following commands.
`server.Dockerfile` can be built in a SGX-enabled environment because it builds in HW mode.
Before building `cached.Dockerfile`, make sure you ran `./scripts/build_server.sh`.

```
$ docker build -t anonify -f docker/dev.Dockerfile ./
$ docker build -t osuketh/anonify-server:latest -f docker/server.Dockerfile ./
$ docker build -t osuketh/anonify-server:latest -f docker/cached.server.Dockerfile ./
```
