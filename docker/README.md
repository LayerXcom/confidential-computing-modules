# Anonify docker files

In the project root directory, you can build docker files by following commands.
`server.Dockerfile` can be built in a SGX-enabled environment because it builds in HW mode.
```
$ docker build -t anonify -f docker/dev.Dockerfile ./
$ docker build -t anonify-server -f docker/server.Dockerfile ./
$ docker build -t anonify-server -f docker/cached.Dockerfile ./
```
