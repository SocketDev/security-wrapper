


  
<!--Socket External Tool Runner: Gosec -->  
  
**Detection**  
**Severity**: `MEDIUM`  
**Filename:** [code/golang-web-server/pkg/mhttp/server.go](https://github.com/socketdev-demo/sast-testing/blob/61f7609dab5de1ff0214338e8a52b2c376a20258/code/golang-web-server/pkg/mhttp/server.go#L49)

```go
48: 	fmt.Printf("Listening on %s...\n", serverUrl)
49: 	log.Fatal(http.ListenAndServe(serverUrl, nil))
50: }

```  
