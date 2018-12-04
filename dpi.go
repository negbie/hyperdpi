// Copyright 2018 Intel Corporation.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

import (
	"flag"
	"fmt"
	"time"

	"github.com/flier/gohs/hyperscan"
	"github.com/intel-go/nff-go/examples/dpi/pattern"
	"github.com/intel-go/nff-go/flow"
	"github.com/intel-go/nff-go/packet"
)

var (
	infile  string
	outfile string
	pfile   string
	nreads  int
	timeout time.Duration

	// Number of allowed packets for each flow
	allowedPktsCount [pattern.NumFlows]uint64
	// Number of read packets for each flow
	readPktsCount [pattern.NumFlows]uint64
	// Number of packets blocked by signature for each flow
	blockedPktsCount [pattern.NumFlows]uint64

	// Global Hyperscan database can be uses by several handlers
	hsdb     pattern.HSdb
	patterns []pattern.Pattern

	packetFilter    func(*packet.Packet, flow.UserContext) bool
	onMatchCallback hyperscan.MatchHandler = onMatch
)

func main() {
	flag.StringVar(&infile, "infile", "", "input pcap file")
	flag.StringVar(&outfile, "outfile", "allowed-packets.pcap", "output pcap file with allowed packets")
	flag.StringVar(&pfile, "patterns", "patterns.json", "input JSON file, specifying patterns")
	flag.IntVar(&nreads, "nreads", 1, "number pcap file reads")
	flag.DurationVar(&timeout, "timeout", 5*time.Second, "time to run, seconds")
	flag.Parse()

	// Initialize NFF-Go library
	flow.CheckFatal(flow.SystemInit(nil))

	var err error
	patterns, err = pattern.GetPatternsFromFile(pfile)
	flow.CheckFatal(err)

	packetFilter = filterByHS
	hsdb.SetupHyperscan(patterns)

	// Receive packets from given PCAP file
	inputFlow := flow.SetReceiverFile(infile, int32(nreads))

	// Split packets into flows by hash of five-tuple
	// Packets without five-tuple are put in last flow and will be dropped
	outputFlows, err := flow.SetSplitter(inputFlow, splitBy5Tuple, pattern.TotalNumFlows, nil)
	flow.CheckFatal(err)

	// Drop last flow
	flow.CheckFatal(flow.SetStopper(outputFlows[pattern.TotalNumFlows-1]))

	for i := uint(0); i < pattern.NumFlows; i++ {
		lc := localCounters{handlerID: i}
		flow.CheckFatal(flow.SetHandlerDrop(outputFlows[i], packetFilter, lc))
	}

	outFlow, err := flow.SetMerger(outputFlows[:pattern.NumFlows]...)
	flow.CheckFatal(err)

	flow.CheckFatal(flow.SetSenderFile(outFlow, outfile))

	go func() {
		flow.CheckFatal(flow.SystemStart())
	}()

	// Finish by timeout, as cannot verify if file reading finished
	time.Sleep(timeout)

	// Compose info about all handlers
	var read uint64
	var allowed uint64
	var blocked uint64
	fmt.Println("\nHandler statistics")
	for i := uint(0); i < pattern.NumFlows; i++ {
		fmt.Printf("Handler %d processed %d packets (allowed=%d, blocked by signature=%d)\n",
			i, readPktsCount[i], allowedPktsCount[i], blockedPktsCount[i])
		read += readPktsCount[i]
		allowed += allowedPktsCount[i]
		blocked += blockedPktsCount[i]
	}
	fmt.Println("Total:")
	fmt.Println("read =", read)
	fmt.Println("allowed =", allowed)
	fmt.Println("dropped (read - allowed) =", read-allowed)

	hsdb.CleanupHyperscan()

}
