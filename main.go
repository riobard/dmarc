/*
A tiny command-line utility to parse DMARC aggregate reports.
*/
package main

import (
	"archive/zip"
	"compress/gzip"
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
	Count       int64  `xml:"row>count"`
	Disposition string `xml:"row>policy_evaluated>disposition"`
	EvalDKIM    string `xml:"row>policy_evaluated>dkim"`
	EvalSPF     string `xml:"row>policy_evaluated>spf"`
}

type ReportRow struct {
	HeaderFrom       string
	DKIMPass         int64
	DKIMFail         int64
	SPFPass          int64
	SPFFail          int64
	PolicyNone       int64
	PolicyQuarantine int64
	PolicyReject     int64
}

type Report struct {
	Domains map[string]*ReportRow
}

func (r Report) Add(rec AggregateReportRecord) {
	rr, ok := r.Domains[rec.HeaderFrom]
	if !ok {
		rr = &ReportRow{HeaderFrom: rec.HeaderFrom}
		r.Domains[rec.HeaderFrom] = rr
	}
	switch rec.Disposition {
	case "none":
		rr.PolicyNone += rec.Count
	case "quarantine":
		rr.PolicyQuarantine += rec.Count
	case "reject":
		rr.PolicyReject += rec.Count
	default:
		log.Fatalf("unexpected disposition: %s", rec.Disposition)
	}

	switch rec.EvalDKIM {
	case "pass":
		rr.DKIMPass += rec.Count
	case "fail":
		rr.DKIMFail += rec.Count
	default:
		log.Fatalf("unexpected DKIM status: %s", rec.EvalDKIM)
	}

	switch rec.EvalSPF {
	case "pass":
		rr.SPFPass += rec.Count
	case "fail":
		rr.SPFFail += rec.Count
	default:
		log.Fatalf("unexpected SPF status: %s", rec.EvalSPF)
	}
}

var wg sync.WaitGroup
var printfLock sync.Mutex

func init() {
	runtime.GOMAXPROCS(runtime.NumCPU())
}

func main() {
	flag.Parse()

	fmt.Printf("%19s,%19s,%22s,%12s,%20s,%9s,%11s,%9s,%9s,%9s,%9s,%9s\n",
		"Date Begin",
		"Date End",
		"Organization",
		"Domain",
		"HeaderFrom",
		"Passed",
		"Quarantined",
		"Rejected",
		"SPF Pass",
		"DKIM Pass",
		"SPF Fail",
		"DKIM Fail")

	for _, file := range flag.Args() {
		if strings.HasSuffix(file, ".gz") {
			f, err := os.Open(file)
			if err != nil {
				log.Printf("failed to open file %s: %s", file, err)
				continue
			}
			g, err := gzip.NewReader(f)
			if err != nil {
				log.Printf("failed to read gzip stream %s: %s", file, err)
				continue
			}
			wg.Add(1)
			go func() {
				parse(g)
				f.Close()
			}()

		} else if strings.HasSuffix(file, ".zip") {
			r, err := zip.OpenReader(file)
			if err != nil {
				log.Fatal(err)
			}

			for _, zf := range r.File {
				// log.Printf("%s has file %s", file, zf.Name)
				f, err := zf.Open()
				if err != nil {
					log.Fatal(err)
				}
				wg.Add(1)
				go func() {
					parse(f)
					f.Close()
				}()
			}
			defer r.Close()
		} else {
			f, err := os.Open(file)
			if err != nil {
				log.Printf("failed to open file %s: %s", file, err)
				continue
			}
			wg.Add(1)
			go parse(f)
		}
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

	report := Report{Domains: make(map[string]*ReportRow)}

	for _, rec := range fb.Records {
		report.Add(rec)
	}

	const DATEFMT = "2006-01-02 03:04:05"
	printfLock.Lock()
	defer printfLock.Unlock()
	for _, row := range report.Domains {
		fmt.Printf("%19s,%19s,%22s,%12s,%20s,%9d,%11d,%9d,%9d,%9d,%9d,%9d\n",
			fb.DateBegin().UTC().Format(DATEFMT),
			fb.DateEnd().UTC().Format(DATEFMT),
			fb.Organization,
			fb.Domain,
			row.HeaderFrom,
			row.PolicyNone,
			row.PolicyQuarantine,
			row.PolicyReject,
			row.SPFPass,
			row.DKIMPass,
			row.SPFFail,
			row.DKIMFail,
		)

	}

}
