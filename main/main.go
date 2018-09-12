package main

import (
	"crypto/tls"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"strings"
	"sync"
	"time"
)

const (
	expExpiring            = "%s: :::: '%s' (Serial Number: %X) expired in %d days."
	expExpiringWithWarning = "Alert :: %s: :::: '%s' (Serial Number: %X) expired in %d days."
	defaultConcurreny      = 16
)

var (
	warnMonths  = flag.Int("months", 0, "Warn if the certificate will expire within this many years.")
	warnDays    = flag.Int("days", 0, "Warn if the certificate will expire within this many years.")
	hostsFile   = flag.String("hostsFile", "", "Path of the file containing the list of hosts.")
	concurrency = flag.Int("concurrency", defaultConcurreny, "Maximum number of hosts to check at once.")
)

type certErrors struct {
	commonName string
	errs       []error
}

type hostResult struct {
	host  string
	err   error
	certs []certErrors
}

func main() {

	flag.Parse()

	if *warnMonths < 0 {
		*warnMonths = 0
	}

	if *warnDays < 0 {
		*warnDays = 30
	}

	if *warnMonths == 0 && *warnDays == 0 {
		*warnMonths = 1
	}

	if len(*hostsFile) == 0 {
		flag.Usage()
		return
	}

	//log.Printf("Starting to process host file %s", *hostsFile)
	processHostFile()
	log.Printf("Completed processing host file")

}

func processHostFile() {
	//log.Printf("func processHostFile :: Starting to process hostsFile %s", *hostsFile)
	done := make(chan struct{})
	defer close(done)
	hosts := readHostFile(done)
	results := make(chan hostResult)

	var wg sync.WaitGroup
	wg.Add(*concurrency)
	//log.Printf("func processHostFile :: Processing to check certs")

	for i := 0; i < *concurrency; i++ {
		//		log.Printf("func processHostFile :: Inside for loop")
		go func() {
			//log.Printf("func processHostFile :: Inside go function")
			/*for host := range hosts {
				log.Printf("Log queued host names :: %s", host)
			}*/
			processHosts(done, hosts, results)
			wg.Done()
		}()
	}

	go func() {
		wg.Wait()
		close(results)
	}()

	for r := range results {
		if r.err != nil {
			log.Printf("%s: %v\n", r.host, r.err)
			continue
		}

		for _, cert := range r.certs {
			for _, err := range cert.errs {
				log.Println(err)
			}
		}
	}
}

func processHosts(done <-chan struct{}, hosts <-chan string, results chan<- hostResult) {

	for host := range hosts {
		//log.Printf("func processHosts :: Processing to check certs for host %s", host)
		select {
		case results <- checkHost(host):
		case <-done:
			return
		}
	}
}

func readHostFile(done <-chan struct{}) <-chan string {
	hosts := make(chan string)
	//log.Printf("func readHostFile :: Starting to process hostsFile %s", *hostsFile)
	go func() {
		defer close(hosts)
		log.Printf("Starting to read hostFile :: %s", *hostsFile)
		fileContent, err := ioutil.ReadFile(*hostsFile)
		if err != nil {
			log.Printf("Error reading host file %s", *hostsFile)
			return
		}

		lines := strings.Split(string(fileContent), "\n")

		for _, line := range lines {

			host := strings.TrimSpace(line)
			//log.Printf("Starting to %d read hostFile :: %s", i, host)
			if len(host) == 0 || host[0] == '#' {
				continue
			}

			select {
			case hosts <- host:
			case <-done:
				return
			}

		}
	}()

	return hosts
}

func checkHost(host string) (result hostResult) {

	//log.Printf("func checkHost:: checking for host %s", host)
	results := hostResult{
		host:  host,
		certs: []certErrors{},
	}
	conn, err := tls.Dial("tcp", host, nil)

	if err != nil {
		results.err = err
		return
	}

	defer conn.Close()

	timeNow := time.Now()
	//verifiedCerts := make(map[string]struct{})

	for _, chain := range conn.ConnectionState().VerifiedChains {
		for _, cert := range chain {
			cErrs := []error{}

			if timeNow.AddDate(0, *warnMonths, *warnDays).After(cert.NotAfter) {
				expiresIn := int64(cert.NotAfter.Sub(timeNow).Hours())
				expiresInDays := expiresIn / 24

				if expiresInDays <= int64(*warnDays) {

					cErrs = append(cErrs, fmt.Errorf(expExpiringWithWarning, host, cert.Subject.CommonName, cert.SerialNumber, expiresInDays))

				} else {
					cErrs = append(cErrs, fmt.Errorf(expExpiring, host, cert.Subject.CommonName, cert.SerialNumber, expiresInDays))
				}

			}

			results.certs = append(results.certs, certErrors{
				commonName: cert.Subject.CommonName,
				errs:       cErrs,
			})
		}
	}

	for _, cert := range results.certs {
		for _, err := range cert.errs {
			log.Println(err)
		}
	}

	return
}
