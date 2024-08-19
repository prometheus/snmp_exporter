// Package enricher is responsible for processing the collected data, and enriching it with IAA specific labels.
package enricher

import (
	bytes2 "bytes"
	"fmt"
	"net/http"
	"regexp"
	"sync"

	"github.com/iaa-inc/gosdk"
	"github.com/iaa-inc/gosdk/admin"
	ioprometheusclient "github.com/prometheus/client_model/go"
	"github.com/prometheus/common/expfmt"
)

var parser expfmt.TextParser

// port_a1b2c3d
var portParser = regexp.MustCompile(`port_([a-zA-Z0-9]{7})`)

type Enricher struct {
	api    *gosdk.AdminClient
	w      http.ResponseWriter
	target string
	cache  *Cache
}

func (e *Enricher) Header() http.Header {
	return e.w.Header()
}

func (e *Enricher) Write(bytes []byte) (int, error) {
	// push bytes to a reader and parse the metrics

	r := bytes2.NewReader(bytes)

	metricFamilies, err := parser.TextToMetricFamilies(r)
	if err != nil {
		// Probably no metrics here, just return the bytes
		return e.w.Write(bytes)
	}

	// iterate over the metrics and add the IAA specific labels
	var wg sync.WaitGroup
	for _, mf := range metricFamilies {
		for _, metric := range mf.GetMetric() {
			wg.Add(1)
			go func() {
				defer wg.Done()
				e.processMetric(metric)
			}()
			// metric.Label = append(metric.Label, &io_prometheus_client.LabelPair{Name: &name, Value: &val})
		}
	}
	wg.Wait()

	// encode the metrics back to bytes
	var buf bytes2.Buffer
	encoder := expfmt.NewEncoder(&buf, expfmt.NewFormat(expfmt.TypeTextPlain))

	for _, mf := range metricFamilies {
		err := encoder.Encode(mf)
		if err != nil {
			fmt.Printf("Error encoding metrics: %v\n", err)
		}
	}

	return e.w.Write(buf.Bytes())
}

func (e *Enricher) WriteHeader(statusCode int) {
	e.w.WriteHeader(statusCode)
}

func NewEnricher(
	api *gosdk.AdminClient,
	cache *Cache,
) *Enricher {
	return &Enricher{
		api:   api,
		cache: cache,
	}
}

// SetTarget sets the target of the enricher
func (e *Enricher) SetTarget(target string) {
	e.target = target
}

func (e *Enricher) SetWriter(w http.ResponseWriter) {
	e.w = w
}

func (e *Enricher) processMetric(metric *ioprometheusclient.Metric) {
	ifDescr := ""
	portId := ""
	for _, label := range metric.Label {
		if *label.Name == "ifAlias" {
			matches := portParser.FindStringSubmatch(label.GetValue())

			if len(matches) > 1 {
				portId = matches[0]
			}
		}

		// Store the ifDescr for later use, if we don't find a port ID.
		if *label.Name == "ifDescr" {
			ifDescr = *label.Value
		}
	}

	var port *admin.Port

	if portId != "" {
		port = e.cache.GetPort(portId)
	}

	if port == nil {
		port = e.cache.GetPortByIfDescr(ifDescr, e.target)
	}

	if port != nil {
		name := "member"
		metric.Label = append(metric.Label, &ioprometheusclient.LabelPair{Name: &name, Value: &port.Account.Name})

		exchange := "exchange"
		metric.Label = append(metric.Label, &ioprometheusclient.LabelPair{Name: &exchange, Value: &port.Exchange.Name})

		facility := "facility"
		metric.Label = append(metric.Label, &ioprometheusclient.LabelPair{Name: &facility, Value: &port.Facility.Name})
	}
}
