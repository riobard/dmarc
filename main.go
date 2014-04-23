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
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

var (
	sortOrder = flag.String("sort", "date", "sort by date|organization|domain")
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
	DateBegin    time.Time
	DateEnd      time.Time
	Domains      map[string]*ReportRow
	Organization string
	Domain       string
}

type Reports []*Report

func (s Reports) Len() int      { return len(s) }
func (s Reports) Swap(i, j int) { s[i], s[j] = s[j], s[i] }

type ByOrganization struct{ Reports }

func (s ByOrganization) Less(i, j int) bool {
	if s.Reports[i].Organization == s.Reports[j].Organization {
		return s.Reports[i].DateBegin.Before(s.Reports[j].DateBegin)
	}
	return s.Reports[i].Organization < s.Reports[j].Organization
}

type ByDomain struct{ Reports }

func (s ByDomain) Less(i, j int) bool {
	if s.Reports[i].Domain == s.Reports[j].Domain {
		return s.Reports[i].DateBegin.Before(s.Reports[j].DateBegin)
	}
	return s.Reports[i].Domain < s.Reports[j].Domain
}

type ByDate struct{ Reports }

func (s ByDate) Less(i, j int) bool {
	if s.Reports[i].DateBegin.Equal(s.Reports[j].DateBegin) {
		return s.Reports[i].Organization < s.Reports[j].Organization
	}
	return s.Reports[i].DateBegin.Before(s.Reports[j].DateBegin)
}

func (r *Report) Add(rec AggregateReportRecord) {
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

func (r *Report) Format() {
	const DATEFMT = "2006-01-02 03:04:05"
	for _, row := range r.Domains {
		fmt.Printf("%19s,%19s,%22s,%12s,%20s,%7d,%7d,%7d,%7d,%7d,%7d,%7d\n",
			r.DateBegin.UTC().Format(DATEFMT),
			r.DateEnd.UTC().Format(DATEFMT),
			r.Organization,
			r.Domain,
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

func init() {
	runtime.GOMAXPROCS(runtime.NumCPU())
}

func main() {
	flag.Parse()

	fmt.Printf("%19s,%19s,%22s,%12s,%20s,%7s,%7s,%7s,%7s,%7s,%7s,%7s\n",
		"Date Begin",
		"Date End",
		"Organization",
		"Domain",
		"HeaderFrom",
		"Passed",
		"Quaran",
		"Reject",
		"SPF P",
		"DKIM P",
		"SPF F",
		"DKIM F")

	out := make(chan *Report, 100)
	exit := make(chan int)
	var wg sync.WaitGroup

	go func() {
		var reports Reports
		for r := range out {
			reports = append(reports, r)
		}

		switch *sortOrder {
		case "date":
			sort.Sort(ByDate{reports})
		case "domain":
			sort.Sort(ByDomain{reports})
		case "organization":
			sort.Sort(ByOrganization{reports})
		default:
			log.Fatalf("unknown sort option %q", *sortOrder)
		}

		for _, r := range reports {
			r.Format()
		}
		exit <- 1
	}()

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
				parse(g, out)
				f.Close()
				wg.Done()
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
					parse(f, out)
					f.Close()
					wg.Done()
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
			go func() {
				parse(f, out)
				f.Close()
				wg.Done()
			}()
		}
	}
	wg.Wait()
	close(out)
	<-exit

}

func parse(r io.Reader, response chan *Report) {
	fb := &AggregateReport{}
	err := xml.NewDecoder(r).Decode(fb)
	if err != nil {
		log.Fatal(err)
	}

	report := &Report{
		Domains:      make(map[string]*ReportRow),
		DateBegin:    fb.DateBegin(),
		DateEnd:      fb.DateEnd(),
		Organization: fb.Organization,
		Domain:       fb.Domain,
	}

	for _, rec := range fb.Records {
		report.Add(rec)
	}
	response <- report
}
