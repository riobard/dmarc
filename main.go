package main

import (
	"encoding/xml"
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"strconv"
	"strings"
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
	Count       int    `xml:"row>count"`
	Disposition string `xml:"row>policy_evaluated>disposition"`
	EvalDKIM    string `xml:"row>policy_evaluated>dkim"`
	EvalSPF     string `xml:"row>policy_evaluated>spf"`
}

func main() {
	flag.Parse()

	fmt.Printf("Date Begin, Date End, Organization, Domain, Passed, Quarantined, Rejected\n")
	for _, file := range flag.Args() {
		f, err := os.Open(file)
		if err != nil {
			log.Printf("failed to open file %s: %s", file, err)
		}
		parse(f)
	}
}

func parse(r io.Reader) {
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

	const DATEFMT = "2006-01-02 03:04:05"
	fmt.Printf("%s, %s, %s, %s, %d, %d, %d\n", fb.DateBegin().UTC().Format(DATEFMT), fb.DateEnd().UTC().Format(DATEFMT),
		fb.Organization, fb.Domain, dispos_none, dispos_quarantine, dispos_reject)
}
