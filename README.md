### Web Application

#### Create `hello` directory, cd `hello` directory

    mkdir hello
    cd hello

#### Init module

    go mod init

#### Download and install

    go get gitee.com/rachel_os/rungo@latest

#### Create file `hello.go`

```go
package main

import "gitee.com/rachel_os/rungo/server/web"

func main() {
	web.Run()
}
```

#### Download required dependencies

    go mod tidy

#### Build and run

    go build hello.go
    ./hello

#### Go to [http://localhost:8080](http://localhost:8080)

