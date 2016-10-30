package main

import (
	"log"
	"net"
	"fmt"
	 "bufio"
	"os"
	"time"
)

func main() {

	if len(os.Args[1:]) < 3 {
	 	fmt.Println("Invalid Parameters. Syntax: spfblquery ip email helo recipient")
		os.Exit(-1)

		}  

	 query := os.Args[1] + " " + os.Args[2] + " " + os.Args[3]
	 if len(os.Args[1:]) == 4 {
	 	query = query + " " + os.Args[4]
	 }

         hostName := "matrix.spfbl.net"
         portNum := "9877"
         seconds := 10
         timeOut := time.Duration(seconds) * time.Second


    conn, err := net.DialTimeout("tcp", hostName+":"+portNum, timeOut)
	fmt.Fprintf(conn, query + "\n")

	if err != nil {
	// handle error
	}

	status, err := bufio.NewReader(conn).ReadString('\n')
	if err != nil {
			log.Fatal(err)
		}

	
        fmt.Printf(string(status + "/n"))


}
