package main

import (
	"bufio"
	"fmt"
	"os"
	"os/exec"
	"regexp"
	"strings"
)

func main() {
	target, option := getUserInput()
	nmapOutput := runNmap(target, option)
	fmt.Println("Nmap Scan Output:\n", nmapOutput)

	detectOS(nmapOutput)
	addToHostList(target)

	if isWebServerRunning(nmapOutput) {
		fmt.Println("[+] Web server detected!")
		runFfufDirFuzz(target)
		runFfufSubdomainFuzz(target)
	} else {
		fmt.Println("[-] No web server detected.")
	}
}

func getUserInput() (string, string) {
	reader := bufio.NewReader(os.Stdin)
	fmt.Print("Enter target IP or hostname: ")
	ip, _ := reader.ReadString('\n')
	ip = strings.TrimSpace(ip)

	fmt.Print("Choose scan option (1 = custom, 2 = default): ")
	option, _ := reader.ReadString('\n')
	option = strings.TrimSpace(option)

	return ip, option
}

func runNmap(ip, option string) string {
	var cmd *exec.Cmd

	if option == "1" {
		fmt.Print("Enter custom Nmap options (e.g., -sS -p 80,443): ")
		reader := bufio.NewReader(os.Stdin)
		optsStr, _ := reader.ReadString('\n')
		opts := strings.Fields(optsStr)
		opts = append(opts, ip)
		cmd = exec.Command("nmap", opts...)
	} else {
		cmd = exec.Command("nmap", "-sV", "-sC", "-p-", "-O", "-v", ip)
	}

	out, err := cmd.CombinedOutput()
	if err != nil {
		fmt.Println("Error running Nmap:", err)
	}
	return string(out)
}

func detectOS(output string) {
	re := regexp.MustCompile(`OS details: (.+)`)
	matches := re.FindStringSubmatch(output)
	if len(matches) > 1 {
		fmt.Println("[+] Detected OS:", matches[1])
	} else {
		fmt.Println("[-] OS not detected.")
	}
}

func addToHostList(ip string) {
	file, err := os.OpenFile("hosts.txt", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		fmt.Println("Error writing to host list:", err)
		return
	}
	defer file.Close()
	file.WriteString(ip + "\n")
	fmt.Println("[+] Added to hosts.txt")
}

func isWebServerRunning(output string) bool {
	webPattern := regexp.MustCompile(`(?i)http|https|apache|nginx`)
	return webPattern.MatchString(output)
}

func runFfufDirFuzz(ip string) {
	fmt.Println("[*] Running FFUF for directory fuzzing...")
	cmd := exec.Command("ffuf",
		"-u", fmt.Sprintf("http://%s/FUZZ", ip),
		"-w", "/usr/share/wordlists/dirb/common.txt",
		"-t", "50",
	)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.Run()
}

func runFfufSubdomainFuzz(ip string) {
	fmt.Println("[*] Running FFUF for subdomain fuzzing...")
	cmd := exec.Command("ffuf",
		"-u", fmt.Sprintf("http://FUZZ.%s", ip),
		"-w", "/usr/share/wordlists/amass/subdomains.txt",
		"-H", "Host: FUZZ."+ip,
		"-t", "50",
	)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.Run()
}
