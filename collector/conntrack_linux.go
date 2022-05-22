// Copyright 2015 The Prometheus Authors
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//go:build !noconntrack
// +build !noconntrack

package collector

import (
	"errors"
	"fmt"
	"os"

	"github.com/go-kit/log"
	"github.com/go-kit/log/level"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/procfs"
	"github.com/vishvananda/netns"
)

type conntrackCollector struct {
	current       *prometheus.Desc
	limit         *prometheus.Desc
	found         *prometheus.Desc
	invalid       *prometheus.Desc
	ignore        *prometheus.Desc
	insert        *prometheus.Desc
	insertFailed  *prometheus.Desc
	drop          *prometheus.Desc
	earlyDrop     *prometheus.Desc
	searchRestart *prometheus.Desc
	logger        log.Logger
}

type conntrackStatistics struct {
	found         uint64 // Number of searched entries which were successful
	invalid       uint64 // Number of packets seen which can not be tracked
	ignore        uint64 // Number of packets seen which are already connected to a conntrack entry
	insert        uint64 // Number of entries inserted into the list
	insertFailed  uint64 // Number of entries for which list insertion was attempted but failed (happens if the same entry is already present)
	drop          uint64 // Number of packets dropped due to conntrack failure. Either new conntrack entry allocation failed, or protocol helper dropped the packet
	earlyDrop     uint64 // Number of dropped conntrack entries to make room for new ones, if maximum table size was reached
	searchRestart uint64 // Number of conntrack table lookups which had to be restarted due to hashtable resizes
}

func init() {
	registerCollector("conntrack", defaultEnabled, NewConntrackCollector)
}

// NewConntrackCollector returns a new Collector exposing conntrack stats.
func NewConntrackCollector(logger log.Logger) (Collector, error) {
	return &conntrackCollector{
		current: prometheus.NewDesc(
			prometheus.BuildFQName(namespace, "", "nf_conntrack_entries"),
			"Number of currently allocated flow entries for connection tracking.",
			[]string{"nework_namespace"}, nil,
		),
		limit: prometheus.NewDesc(
			prometheus.BuildFQName(namespace, "", "nf_conntrack_entries_limit"),
			"Maximum size of connection tracking table.",
			[]string{"nework_namespace"}, nil,
		),
		found: prometheus.NewDesc(
			prometheus.BuildFQName(namespace, "", "nf_conntrack_stat_found"),
			"Number of searched entries which were successful.",
			[]string{"nework_namespace"}, nil,
		),
		invalid: prometheus.NewDesc(
			prometheus.BuildFQName(namespace, "", "nf_conntrack_stat_invalid"),
			"Number of packets seen which can not be tracked.",
			[]string{"nework_namespace"}, nil,
		),
		ignore: prometheus.NewDesc(
			prometheus.BuildFQName(namespace, "", "nf_conntrack_stat_ignore"),
			"Number of packets seen which are already connected to a conntrack entry.",
			[]string{"nework_namespace"}, nil,
		),
		insert: prometheus.NewDesc(
			prometheus.BuildFQName(namespace, "", "nf_conntrack_stat_insert"),
			"Number of entries inserted into the list.",
			[]string{"nework_namespace"}, nil,
		),
		insertFailed: prometheus.NewDesc(
			prometheus.BuildFQName(namespace, "", "nf_conntrack_stat_insert_failed"),
			"Number of entries for which list insertion was attempted but failed.",
			[]string{"nework_namespace"}, nil,
		),
		drop: prometheus.NewDesc(
			prometheus.BuildFQName(namespace, "", "nf_conntrack_stat_drop"),
			"Number of packets dropped due to conntrack failure.",
			[]string{"nework_namespace"}, nil,
		),
		earlyDrop: prometheus.NewDesc(
			prometheus.BuildFQName(namespace, "", "nf_conntrack_stat_early_drop"),
			"Number of dropped conntrack entries to make room for new ones, if maximum table size was reached.",
			[]string{"nework_namespace"}, nil,
		),
		searchRestart: prometheus.NewDesc(
			prometheus.BuildFQName(namespace, "", "nf_conntrack_stat_search_restart"),
			"Number of conntrack table lookups which had to be restarted due to hashtable resizes.",
			[]string{"nework_namespace"}, nil,
		),
		logger: logger,
	}, nil
}

func (c *conntrackCollector) Update(ch chan<- prometheus.Metric) error {
	value, err := readUintFromFile(procFilePath("sys/net/netfilter/nf_conntrack_count"))
	if err != nil {
		return c.handleErr(err)
	}
	ch <- prometheus.MustNewConstMetric(
		c.current, prometheus.GaugeValue, float64(value), "default")

	value, err = readUintFromFile(procFilePath("sys/net/netfilter/nf_conntrack_max"))
	if err != nil {
		return c.handleErr(err)
	}
	ch <- prometheus.MustNewConstMetric(
		c.limit, prometheus.GaugeValue, float64(value), "default")

	conntrackStats, err := getConntrackStatistics()
	if err != nil {
		return c.handleErr(err)
	}

	ch <- prometheus.MustNewConstMetric(
		c.found, prometheus.GaugeValue, float64(conntrackStats.found), "default")
	ch <- prometheus.MustNewConstMetric(
		c.invalid, prometheus.GaugeValue, float64(conntrackStats.invalid), "default")
	ch <- prometheus.MustNewConstMetric(
		c.ignore, prometheus.GaugeValue, float64(conntrackStats.ignore), "default")
	ch <- prometheus.MustNewConstMetric(
		c.insert, prometheus.GaugeValue, float64(conntrackStats.insert), "default")
	ch <- prometheus.MustNewConstMetric(
		c.insertFailed, prometheus.GaugeValue, float64(conntrackStats.insertFailed), "default")
	ch <- prometheus.MustNewConstMetric(
		c.drop, prometheus.GaugeValue, float64(conntrackStats.drop), "default")
	ch <- prometheus.MustNewConstMetric(
		c.earlyDrop, prometheus.GaugeValue, float64(conntrackStats.earlyDrop), "default")
	ch <- prometheus.MustNewConstMetric(
		c.searchRestart, prometheus.GaugeValue, float64(conntrackStats.searchRestart), "default")

	// Gather metrics for named namespaces
	dir, err := os.Open("/var/run/netns/")
	if err != nil {
		return c.handleErr(err)
	}
	files, err := dir.Readdir(0)
	if err != nil {
		return c.handleErr(err)
	}

	for _, netNamespace := range files {
		ns, err := netns.GetFromName(netNamespace.Name())
		if err != nil {
			return c.handleErr(err)
		}
		err = netns.Set(ns)
		if err != nil {
			return c.handleErr(err)
		}

		value, err := readUintFromFile(procFilePath("sys/net/netfilter/nf_conntrack_count"))
		if err != nil {
			return c.handleErr(err)
		}
		ch <- prometheus.MustNewConstMetric(
			c.current, prometheus.GaugeValue, float64(value), netNamespace.Name())

		value, err = readUintFromFile(procFilePath("sys/net/netfilter/nf_conntrack_max"))
		if err != nil {
			return c.handleErr(err)
		}
		ch <- prometheus.MustNewConstMetric(
			c.limit, prometheus.GaugeValue, float64(value), netNamespace.Name())

		conntrackStats, err := getConntrackStatistics()
		if err != nil {
			return c.handleErr(err)
		}

		ch <- prometheus.MustNewConstMetric(
			c.found, prometheus.GaugeValue, float64(conntrackStats.found), netNamespace.Name())
		ch <- prometheus.MustNewConstMetric(
			c.invalid, prometheus.GaugeValue, float64(conntrackStats.invalid), netNamespace.Name())
		ch <- prometheus.MustNewConstMetric(
			c.ignore, prometheus.GaugeValue, float64(conntrackStats.ignore), netNamespace.Name())
		ch <- prometheus.MustNewConstMetric(
			c.insert, prometheus.GaugeValue, float64(conntrackStats.insert), netNamespace.Name())
		ch <- prometheus.MustNewConstMetric(
			c.insertFailed, prometheus.GaugeValue, float64(conntrackStats.insertFailed), netNamespace.Name())
		ch <- prometheus.MustNewConstMetric(
			c.drop, prometheus.GaugeValue, float64(conntrackStats.drop), netNamespace.Name())
		ch <- prometheus.MustNewConstMetric(
			c.earlyDrop, prometheus.GaugeValue, float64(conntrackStats.earlyDrop), netNamespace.Name())
		ch <- prometheus.MustNewConstMetric(
			c.searchRestart, prometheus.GaugeValue, float64(conntrackStats.searchRestart), netNamespace.Name())
	}

	return nil
}

func (c *conntrackCollector) handleErr(err error) error {
	if errors.Is(err, os.ErrNotExist) {
		level.Debug(c.logger).Log("msg", "conntrack probably not loaded")
		return ErrNoData
	}
	return fmt.Errorf("failed to retrieve conntrack stats: %w", err)
}

func getConntrackStatistics() (*conntrackStatistics, error) {
	c := conntrackStatistics{}

	fs, err := procfs.NewFS(*procPath)
	if err != nil {
		return nil, fmt.Errorf("failed to open procfs: %w", err)
	}

	connStats, err := fs.ConntrackStat()
	if err != nil {
		return nil, err
	}

	for _, connStat := range connStats {
		c.found += connStat.Found
		c.invalid += connStat.Invalid
		c.ignore += connStat.Ignore
		c.insert += connStat.Insert
		c.insertFailed += connStat.InsertFailed
		c.drop += connStat.Drop
		c.earlyDrop += connStat.EarlyDrop
		c.searchRestart += connStat.SearchRestart
	}

	return &c, nil
}
