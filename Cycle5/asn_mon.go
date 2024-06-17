package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"time"

	"github.com/ns3777k/go-shodan/v4/shodan" // with go modules enabled (GO111MODULE=on or outside GOPATH)
)

type SQuery struct {
	Name string
	str  string
}

var queryTable = []SQuery{
	{"Unsafe protocols", "telnet"},
	{"Unsafe OS's", "os:raspbian"},
	{"Non standard ssh ports", "ssh -port:22"},
	{"Insecure mongo db instance", "mongodb port 27017"},
	{"Unsafe file listings", "http.title:\"Index of /\""},
	{"Unsafe file listings", "port:80 title:\"Index of /\""},
	{"Insecure FTP", "\"220\" \"230 Login successful.\" port:21"},
	{"Insecure filezilla", "filezilla port:\"21\""},
	{"Insecure SMB share", "\"Authentication: disabled\" port:445 product:\"Samba\""},
	{"Insecure vstftp", "Vsftpd 2.3.4"},
	{"anonymous FTP", "\"Anonymous+access+allowed\" port:\"21\""},
	{"Insecure FTP", "230 'anonymous@' login ok"},
}

func main() {
	ctx := context.TODO()
	client := shodan.NewEnvClient(nil)
	asnVar := flag.String("asn", "AS23122", "Enter organization ASN")
	cveVar := flag.String("cve", "", "A specific CVE to look for")
	flag.Parse()
	log.Printf("asn:%s", *asnVar)

	// check for cert expiry and flag any certs that are already
	// expired
	query := shodan.HostQueryOptions{
		Query: "asn:" + *asnVar,
	}
	s, err := client.GetHostsForQuery(ctx, &query)
	if err != nil {
		log.Panic(err)
	}
	log.Printf("----------- Certficate verification ------------\n")
	for _, item := range s.Matches {
		if item.SSL != nil {
			log.Printf("item IP:%s Cert expires:%s",
				item.IP.String(), item.SSL.Certificate.Expires)
			if item.SSL.Certificate.IsExpired {
				log.Printf("**** IP:%s certificate expired!!", item.IP.String())
			}
		}
	}

	// check for any devices with identified CVEs
	log.Printf("\n----------- Vulnerabilities ------------\n")
	<-time.After(1 * time.Second)
	for _, item := range s.Matches {
		host, err := client.GetServicesForHost(ctx, item.IP.String(), nil)
		if err != nil {
			log.Panic(err)
		}
		if len(host.Vulnerabilities) > 0 {
			log.Printf("IP:%s Vulnerabilities :%+v",
				item.IP.String(), host.Vulnerabilities)
		}
		<-time.After(1 * time.Second)
	}

	// check for devices with given CVE
	// for eg: CVE-2014-0160 - heartbleed
	if *cveVar != "" {
		log.Printf("----------- CVE: " + *cveVar + "------------\n")
		<-time.After(1 * time.Second)
		query = shodan.HostQueryOptions{
			Query: "asn:" + *asnVar + " vuln:" + *cveVar,
		}
		s, err = client.GetHostsForQuery(ctx, &query)
		if err != nil {
			log.Panic(err)
		}
		for _, item := range s.Matches {
			log.Printf("item IP:%s", item.IP.String())
		}
	}

	// check for a bunch of vulnerabilities which can be extended
	// any time by adding to the table queryTable

	for _, q := range queryTable {

		log.Printf(fmt.Sprintf("----------- %s ------------\n",
			q.Name))
		query = shodan.HostQueryOptions{
			Query: fmt.Sprintf("asn:%s %s", *asnVar, q.str),
		}

		s, err = client.GetHostsForQuery(ctx, &query)
		if err != nil {
			log.Panic(err)
		}

		for _, item := range s.Matches {
			log.Printf("IP:%s", item.IP.String())
		}
	}

}
