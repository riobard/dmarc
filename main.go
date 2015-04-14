/*
A tiny command-line utility to parse DMARC aggregate reports.
*/
package main

import (
	"encoding/xml"
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"
)

var (
	DATEFMT = "2006-01-02 03:04:05"
)

type AggregateReport struct {
	Organization    string                  `xml:"report_metadata>org_name"`
	Email           string                  `xml:"report_metadata>email"`
	ReportID        string                  `xml:"report_metadata>report_id"`
	DateRangeBegin  string                  `xml:"report_metadata>date_range>begin"`
	DateRangeEnd    string                  `xml:"report_metadata>date_range>end"`
	Domain          string                  `xml:"policy_published>domain"`
	AlignDKIM       string                  `xml:"policy_published>adkism"`
	AlignSPF        string                  `xml:"policy_published>aspf"`
	Policy          string                  `xml:"policy_published>p"`
	SubdomainPolicy string                  `xml:"policy_published>sp"`
	Percentage      int                     `xml:"policy_published>pct"`
	Records         []AggregateReportRecord `xml:"record"`
}

func (r *AggregateReport) DateBegin() time.Time {
	timestamp, _ := strconv.Atoi(strings.TrimSpace(r.DateRangeBegin))
	return time.Unix(int64(timestamp), 0)
}

func (r *AggregateReport) DateEnd() time.Time {
	timestamp, _ := strconv.Atoi(strings.TrimSpace(r.DateRangeEnd))
	return time.Unix(int64(timestamp), 0)
}

type AggregateReportRecord struct {
	SourceIP    string `xml:"row>source_ip"`
	HeaderFrom  string `xml:"identifiers>header_from"`
	Count       int    `xml:"row>count"`
	Disposition string `xml:"row>policy_evaluated>disposition"`
	EvalDKIM    string `xml:"row>policy_evaluated>dkim"`
	EvalSPF     string `xml:"row>policy_evaluated>spf"`
}

var wg sync.WaitGroup
var printfLock sync.Mutex

func init() {
	runtime.GOMAXPROCS(runtime.NumCPU())
}

func main() {
	var H = flag.Bool("H", false, "Set 24-hour time format")
	flag.Parse()
	if *H {
		DATEFMT = "2006-01-02 15:04:05"
	}

	fmt.Printf("Date Begin,Date End,Organization,Domain,Passed,Quarantined,Rejected\n")
	for _, file := range flag.Args() {
		f, err := os.Open(file)
		if err != nil {
			log.Printf("failed to open file %s: %s", file, err)
		}
		wg.Add(1)
		go parse(f)
	}
	wg.Wait()
}

func parse(r io.Reader) {
	defer wg.Done()
	fb := &AggregateReport{}
	err := xml.NewDecoder(r).Decode(fb)
	if err != nil {
		log.Fatal(err)
	}

	dispos_none, dispos_quarantine, dispos_reject := 0, 0, 0
	for _, rec := range fb.Records {
		switch rec.Disposition {
		case "none":
			dispos_none += rec.Count
		case "quarantine":
			dispos_quarantine += rec.Count
		case "reject":
			dispos_reject += rec.Count
		default:
			log.Fatalf("unexpected disposition: %s", rec.Disposition)
		}
	}

	printfLock.Lock()
	defer printfLock.Unlock()
	fmt.Printf("%s,%s,%s,%s,%d,%d,%d\n", fb.DateBegin().UTC().Format(DATEFMT), fb.DateEnd().UTC().Format(DATEFMT),
		fb.Organization, fb.Domain, dispos_none, dispos_quarantine, dispos_reject)
}
