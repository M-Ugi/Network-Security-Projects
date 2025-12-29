package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"net"
	"time"

	"github.com/scionproto/scion/pkg/addr"
	"github.com/scionproto/scion/pkg/daemon"
	"github.com/scionproto/scion/pkg/experimental/fabrid"
	"github.com/scionproto/scion/pkg/log"
	"github.com/scionproto/scion/pkg/private/common"
	"github.com/scionproto/scion/pkg/private/serrors"
	"github.com/scionproto/scion/pkg/snet"
	"github.com/scionproto/scion/pkg/snet/path"
	"github.com/scionproto/scion/private/path/fabridquery"

	_ "gitlab.inf.ethz.ch/PRV-PERRIG/netsec-course/project-scion/lib"
)

// Request represents the JSON message sent to the verifier
type Request struct {
	ID      int         `json:"ID"`
	Payload interface{} `json:"Payload,omitempty"`
}

// Response represents the JSON message received from the verifier
type Response struct {
	ID      int         `json:"ID"`
	Payload interface{} `json:"Payload,omitempty"`
	State   string      `json:"State"`
}

// The local IP address of your endhost.
// It matches the IP address of the SCION daemon you should use for this run.
var local string

// The remote SCION address of the verifier application.
var remote snet.UDPAddr

// The port of your SCION daemon.
const daemonPort = 30255

func main() {
	// DO NOT MODIFY THIS FUNCTION
	err := log.Setup(log.Config{
		Console: log.ConsoleConfig{
			Level:           "DEBUG",
			StacktraceLevel: "none",
		},
	})
	if err != nil {
		fmt.Println(serrors.WrapStr("setting up logging", err))
	}
	flag.StringVar(&local, "local", "", "The local IP address which is the same IP as the IP of the local SCION daemon")
	flag.Var(&remote, "remote", "The address of the validator")
	flag.Parse()

	if err := realMain(); err != nil {
		log.Error("Error while running project", "err", err)
	}
}

func realMain() error {
	ctx := context.Background()

	log.Info("Connecting to SCION daemon", "local", local, "daemon_port", daemonPort)

	daemonAddr := net.JoinHostPort(local, fmt.Sprintf("%d", daemonPort))
	daemonConn, err := daemon.NewService(daemonAddr).Connect(ctx)
	if err != nil {
		return serrors.WrapStr("connecting to SCION daemon", err)
	}
	defer daemonConn.Close()

	log.Info("Successfully connected to SCION daemon")

	localIA, err := daemonConn.LocalIA(ctx)
	if err != nil {
		return serrors.WrapStr("retrieving local ISD-AS", err)
	}

	log.Info("Local ISD-AS", "ia", localIA)
	log.Info("Remote address", "remote", remote.String())

	paths, err := daemonConn.Paths(ctx, remote.IA, localIA, daemon.PathReqFlags{})
	if err != nil {
		return serrors.WrapStr("querying paths", err)
	}

	if len(paths) == 0 {
		return serrors.New("no paths available to remote")
	}

	log.Info("Found paths", "count", len(paths))

	network := &snet.SCIONNetwork{
		Topology: daemonConn,
	}

	// Create local address
	localAddr := &net.UDPAddr{
		IP: net.ParseIP(local),
	}

	// ========== TEST ID 01 ==========
	log.Info("=== Starting Test ID 01 ===")

	// Set path for Test 01
	remote.Path = paths[0].Dataplane()
	remote.NextHop = paths[0].UnderlayNextHop()

	// Create connection for Test 01
	conn, err := network.Dial(ctx, "udp", localAddr, &remote)
	if err != nil {
		return serrors.WrapStr("dialing remote", err)
	}

	log.Info("Connection established for Test 01")

	// Send Test ID 01
	err = sendTest01(conn)
	if err != nil {
		log.Error("Test ID 01 failed", "err", err)
	}

	// IMPORTANT: Close connection after Test 01
	conn.Close()

	// TEST ID 02
	log.Info(" Starting Test ID 02")

	// Pass network, localAddr, and paths to Test 02
	// It will manage its own connections
	err = sendTest02(network, localAddr, paths)
	if err != nil {
		log.Error("Test ID 02 failed", "err", err)
	}

	// Test ID 10: Carbon Intensity
	log.Info("Starting Test ID 10")
	err = sendTest10(network, localAddr, paths)
	if err != nil {
		log.Error("Test ID 10 failed", "err", err)
	}

	// Test ID 11: Maximize Bandwidth
	log.Info("Starting Test ID 11")
	err = sendTest11(network, localAddr, paths)
	if err != nil {
		log.Error("Test ID 11 failed", "err", err)
	}

	// Test ID 20: EPIC Hidden Paths
	log.Info("Starting Test ID 20")
	err = sendTest20(daemonConn, network, localAddr, localIA)
	if err != nil {
		log.Error("Test ID 20 failed", "err", err)
	}
	// Test ID 30: FABRID Basic Connectivity
	log.Info("Starting Test ID 30")
	err = sendTest30(daemonConn, network, localAddr, localIA)
	if err != nil {
		log.Error("Test ID 30 failed", "err", err)
	}

	// Test ID 31: FABRID Manufacturer A or B
	log.Info("Starting Test ID 31")
	err = sendTest31(daemonConn, network, localAddr, localIA)
	if err != nil {
		log.Error("Test ID 31 failed", "err", err)
	}
	// Test ID 32: FABRID ISD-specific policies
	log.Info("Starting Test ID 32")
	err = sendTest32(daemonConn, network, localAddr, localIA)
	if err != nil {
		log.Error("Test ID 32 failed", "err", err)
	}

	// Test ID 33: FABRID ISD-specific policies
	log.Info("Starting Test ID 33")
	err = sendTest33(daemonConn, network, localAddr, localIA)
	if err != nil {
		log.Error("Test ID 33 failed", "err", err)
	}

	// Test ID 40: FABRID ISD-specific policies
	log.Info("Starting Test ID 40")
	err = sendTest40(daemonConn, network, localAddr, localIA)
	if err != nil {
		log.Error("Test ID 40 failed", "err", err)
	}

	return nil
}

func sendTest01(conn *snet.Conn) error {

	request := Request{
		ID:      1,
		Payload: map[string]interface{}{},
	}

	requestBytes, err := json.Marshal(request)
	if err != nil {
		return serrors.WrapStr("marshaling request", err)
	}

	log.Info("Sending Test ID 01", "payload", string(requestBytes))

	_, err = conn.Write(requestBytes)
	if err != nil {
		return serrors.WrapStr("writing packet", err)
	}

	conn.SetReadDeadline(time.Now().Add(5 * time.Second))

	buffer := make([]byte, 16000)
	n, err := conn.Read(buffer)
	if err != nil {
		return serrors.WrapStr("reading response", err)
	}

	var response Response
	err = json.Unmarshal(buffer[:n], &response)
	if err != nil {
		return serrors.WrapStr("unmarshaling response", err)
	}

	log.Info("Test ID 01 result", "id", response.ID, "state", response.State)

	return nil
}
func sendTest02(network *snet.SCIONNetwork, localAddr *net.UDPAddr, paths []snet.Path) error {
	ctx := context.Background()
	pathIndex := 0

	log.Info("Test ID 02: Sending initial packet", "path_index", pathIndex)

	remote.Path = paths[pathIndex].Dataplane()
	remote.NextHop = paths[pathIndex].UnderlayNextHop()

	conn, err := network.Dial(ctx, "udp", localAddr, &remote)
	if err != nil {
		return serrors.WrapStr("dialing for test 02", err)
	}
	defer conn.Close()

	request := Request{
		ID:      2,
		Payload: map[string]interface{}{},
	}

	requestBytes, err := json.Marshal(request)
	if err != nil {
		return serrors.WrapStr("marshaling test 02 initial request", err)
	}

	log.Info("Test ID 02: Sending initial request", "payload", string(requestBytes))

	_, err = conn.Write(requestBytes)
	if err != nil {
		return serrors.WrapStr("writing test 02 initial packet", err)
	}

	conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	buffer := make([]byte, 16000)
	n, err := conn.Read(buffer)
	if err != nil {
		return serrors.WrapStr("reading test 02 initial response", err)
	}

	var response Response
	err = json.Unmarshal(buffer[:n], &response)
	if err != nil {
		return serrors.WrapStr("unmarshaling test 02 response", err)
	}

	log.Info("Test ID 02: Initial response", "id", response.ID, "state", response.State, "payload", response.Payload)

	if response.State == "TestPassed" {
		log.Info("Test ID 02: Passed on first try")
		return nil
	}

	additionalPaths, ok := response.Payload.(float64)
	if !ok {
		return serrors.New("unexpected payload type in test 02 response")
	}

	numAdditionalPaths := int(additionalPaths)
	log.Info("Test ID 02: Additional paths needed", "count", numAdditionalPaths)

	if pathIndex+numAdditionalPaths >= len(paths) {
		return serrors.New("not enough paths available for test 02", "needed", numAdditionalPaths+1, "available", len(paths))
	}

	for i := 0; i < numAdditionalPaths; i++ {
		pathIndex++
		log.Info("Test ID 02: Sending packet on different path", "path_index", pathIndex, "iteration", i+1, "of", numAdditionalPaths)

		conn.Close()

		remote.Path = paths[pathIndex].Dataplane()
		remote.NextHop = paths[pathIndex].UnderlayNextHop()

		conn, err = network.Dial(ctx, "udp", localAddr, &remote)
		if err != nil {
			return serrors.WrapStr("dialing for test 02 additional path", err, "path_index", pathIndex)
		}

		requestBytes, err = json.Marshal(request)
		if err != nil {
			return serrors.WrapStr("marshaling test 02 request", err)
		}

		_, err = conn.Write(requestBytes)
		if err != nil {
			return serrors.WrapStr("writing test 02 packet", err, "path_index", pathIndex)
		}

		conn.SetReadDeadline(time.Now().Add(5 * time.Second))
		n, err = conn.Read(buffer)
		if err != nil {
			return serrors.WrapStr("reading test 02 response", err, "path_index", pathIndex)
		}

		err = json.Unmarshal(buffer[:n], &response)
		if err != nil {
			return serrors.WrapStr("unmarshaling test 02 response", err)
		}

		log.Info("Test ID 02: Response received", "path_index", pathIndex, "state", response.State)

		if response.State == "TestPassed" {
			log.Info("Test ID 02: Passed!", "total_paths_used", pathIndex+1)
			conn.Close()
			return nil
		}
	}

	conn.Close()

	if response.State != "TestPassed" {
		return serrors.New("test 02 did not pass after using all required paths", "final_state", response.State)
	}

	return nil
}

// calculateCarbonIntensity uses the actual CarbonIntensity field from path metadata
func calculateCarbonIntensity(path snet.Path) (totalIntensity float64, missingCount int, hasCompleteData bool) {
	metadata := path.Metadata()
	if metadata == nil {
		return 999999.0, 1, false
	}

	if len(metadata.CarbonIntensity) == 0 {

		return 999999.0, 1, false
	}

	totalIntensity = 0
	missingCount = 0

	for i, carbon := range metadata.CarbonIntensity {
		if carbon == snet.CarbonIntensityUnset || carbon < 0 {

			missingCount++
			log.Debug("Missing carbon intensity", "index", i)
		} else {

			totalIntensity += float64(carbon)
			log.Debug("Carbon intensity", "index", i, "value", carbon)
		}
	}

	hasCompleteData = (missingCount == 0)

	log.Debug("Total carbon calculation",
		"total_gCO2_per_TB", totalIntensity,
		"missing_count", missingCount,
		"complete", hasCompleteData)

	return totalIntensity, missingCount, hasCompleteData
}

func findLowestCarbonPath(paths []snet.Path) (snet.Path, error) {
	if len(paths) == 0 {
		return nil, serrors.New("no paths available")
	}

	var bestPath snet.Path
	var bestIntensity float64
	var bestMissingCount int
	hasCompletePath := false

	log.Info("Evaluating paths for carbon intensity", "total_paths", len(paths))

	for i, path := range paths {
		intensity, missing, complete := calculateCarbonIntensity(path)

		log.Info("Path carbon analysis",
			"path_index", i,
			"total_intensity", intensity,
			"missing_interfaces", missing,
			"complete_data", complete)

		if bestPath == nil {

			bestPath = path
			bestIntensity = intensity
			bestMissingCount = missing
			hasCompletePath = complete
			log.Info("Initialized best path", "path_index", i)
		} else {

			shouldReplace := false

			if complete && !hasCompletePath {

				shouldReplace = true
				log.Info("Found path with complete data", "path_index", i)
			} else if complete == hasCompletePath {

				if missing < bestMissingCount {

					shouldReplace = true
					log.Info("Found path with fewer missing interfaces", "path_index", i)
				} else if missing == bestMissingCount {

					if intensity < bestIntensity {
						shouldReplace = true
						log.Info("Found path with lower carbon intensity", "path_index", i)
					}
				}
			}

			if shouldReplace {
				bestPath = path
				bestIntensity = intensity
				bestMissingCount = missing
				hasCompletePath = complete
			}
		}
	}

	log.Info("Selected path with minimum carbon intensity",
		"total_intensity", bestIntensity,
		"missing_interfaces", bestMissingCount,
		"complete_data", hasCompletePath)

	return bestPath, nil
}
func sendTest10(network *snet.SCIONNetwork, localAddr *net.UDPAddr, paths []snet.Path) error {
	ctx := context.Background()

	log.Info("Test ID 10: Finding path with minimum carbon intensity")

	bestPath, err := findLowestCarbonPath(paths)
	if err != nil {
		return serrors.WrapStr("finding lowest carbon path", err)
	}

	remote.Path = bestPath.Dataplane()
	remote.NextHop = bestPath.UnderlayNextHop()

	log.Info("Test ID 10: Using selected low-carbon path")

	conn, err := network.Dial(ctx, "udp", localAddr, &remote)
	if err != nil {
		return serrors.WrapStr("dialing for test 10", err)
	}
	defer conn.Close()

	request := Request{
		ID:      10,
		Payload: map[string]interface{}{},
	}

	requestBytes, err := json.Marshal(request)
	if err != nil {
		return serrors.WrapStr("marshaling test 10 request", err)
	}

	log.Info("Test ID 10: Sending request", "payload", string(requestBytes))

	_, err = conn.Write(requestBytes)
	if err != nil {
		return serrors.WrapStr("writing test 10 packet", err)
	}

	conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	buffer := make([]byte, 16000)
	n, err := conn.Read(buffer)
	if err != nil {
		return serrors.WrapStr("reading test 10 response", err)
	}

	var response Response
	err = json.Unmarshal(buffer[:n], &response)
	if err != nil {
		return serrors.WrapStr("unmarshaling test 10 response", err)
	}

	log.Info("Test ID 10 result", "id", response.ID, "state", response.State)

	if response.State != "TestPassed" {
		return serrors.New("test 10 did not pass", "state", response.State)
	}

	return nil
}

type PathScore struct {
	Path            snet.Path
	TotalLatency    time.Duration
	MinBandwidth    uint64
	MissingCount    int
	HasCompleteData bool
	PathLength      int
}

func calculateLatencyAndBandwidth(path snet.Path) (totalLatency time.Duration, minBandwidth uint64, missingCount int, hasCompleteData bool) {
	metadata := path.Metadata()
	if metadata == nil {
		return time.Duration(999999) * time.Hour, 0, 1, false
	}

	totalLatency = 0
	if len(metadata.Latency) > 0 {
		for _, lat := range metadata.Latency {
			if lat == snet.LatencyUnset || lat < 0 {
				missingCount++
			} else {
				totalLatency += lat
			}
		}
	} else {
		missingCount++
	}

	minBandwidth = ^uint64(0)
	bandwidthFound := false

	if len(metadata.Bandwidth) > 0 {
		for _, bw := range metadata.Bandwidth {
			if bw > 0 {
				bandwidthFound = true
				if bw < minBandwidth {
					minBandwidth = bw
				}
			}
		}
	}

	if !bandwidthFound {
		minBandwidth = ^uint64(0)
	}

	latencyComplete := len(metadata.Latency) > 0 && missingCount == 0
	bandwidthComplete := len(metadata.Bandwidth) > 0
	hasCompleteData = latencyComplete && bandwidthComplete

	log.Debug("Path metrics",
		"latency_ms", totalLatency.Milliseconds(),
		"bandwidth_kbps", minBandwidth,
		"missing", missingCount,
		"complete", hasCompleteData)

	return totalLatency, minBandwidth, missingCount, hasCompleteData
}

func findBestBandwidthPath(paths []snet.Path, maxLatencyMs int64) (snet.Path, error) {
	if len(paths) == 0 {
		return nil, serrors.New("no paths available")
	}

	maxLatency := time.Duration(maxLatencyMs) * time.Millisecond

	log.Info("Finding best bandwidth path",
		"max_latency_ms", maxLatencyMs,
		"total_paths", len(paths))

	var validPaths []PathScore

	for i, path := range paths {
		latency, bandwidth, missing, complete := calculateLatencyAndBandwidth(path)

		log.Info("Evaluating path",
			"path_index", i,
			"latency_ms", latency.Milliseconds(),
			"bandwidth_kbps", bandwidth,
			"missing", missing,
			"complete", complete)

		if latency <= maxLatency {
			score := PathScore{
				Path:            path,
				TotalLatency:    latency,
				MinBandwidth:    bandwidth,
				MissingCount:    missing,
				HasCompleteData: complete,
				PathLength:      len(path.Metadata().Interfaces),
			}
			validPaths = append(validPaths, score)
			log.Info("Path within latency bound", "path_index", i)
		} else {
			log.Info("Path exceeds latency bound", "path_index", i)
		}
	}

	if len(validPaths) == 0 {
		return nil, serrors.New("no paths within latency bound")
	}

	// Sort paths by priority
	// 1. Complete data first
	// 2. Fewer missing interfaces
	// 3. Higher bandwidth
	// 4. Shorter path
	// 5. Lower interface IDs (implicit in path order)

	bestIdx := 0
	for i := 1; i < len(validPaths); i++ {
		shouldReplace := false

		curr := validPaths[i]
		best := validPaths[bestIdx]

		if curr.HasCompleteData && !best.HasCompleteData {
			shouldReplace = true
		} else if curr.HasCompleteData == best.HasCompleteData {

			if curr.MissingCount < best.MissingCount {
				shouldReplace = true
			} else if curr.MissingCount == best.MissingCount {

				if curr.MinBandwidth > best.MinBandwidth {
					shouldReplace = true
				} else if curr.MinBandwidth == best.MinBandwidth {

					if curr.PathLength < best.PathLength {
						shouldReplace = true
					}

				}
			}
		}

		if shouldReplace {
			bestIdx = i
			log.Info("New best path", "path_index", i)
		}
	}

	best := validPaths[bestIdx]
	log.Info("Selected best bandwidth path",
		"latency_ms", best.TotalLatency.Milliseconds(),
		"bandwidth_kbps", best.MinBandwidth,
		"path_length", best.PathLength,
		"complete", best.HasCompleteData)

	return best.Path, nil
}
func sendTest11(network *snet.SCIONNetwork, localAddr *net.UDPAddr, paths []snet.Path) error {
	ctx := context.Background()

	log.Info("Test ID 11: Getting latency bound from verifier")

	remote.Path = paths[0].Dataplane()
	remote.NextHop = paths[0].UnderlayNextHop()

	conn, err := network.Dial(ctx, "udp", localAddr, &remote)
	if err != nil {
		return serrors.WrapStr("dialing for test 11 initial", err)
	}

	request := Request{
		ID:      11,
		Payload: map[string]interface{}{},
	}

	requestBytes, err := json.Marshal(request)
	if err != nil {
		conn.Close()
		return serrors.WrapStr("marshaling test 11 initial request", err)
	}

	log.Info("Test ID 11: Requesting latency bound", "payload", string(requestBytes))

	_, err = conn.Write(requestBytes)
	if err != nil {
		conn.Close()
		return serrors.WrapStr("writing test 11 initial packet", err)
	}

	conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	buffer := make([]byte, 16000)
	n, err := conn.Read(buffer)
	if err != nil {
		conn.Close()
		return serrors.WrapStr("reading test 11 initial response", err)
	}
	conn.Close()

	var response Response
	err = json.Unmarshal(buffer[:n], &response)
	if err != nil {
		return serrors.WrapStr("unmarshaling test 11 response", err)
	}

	log.Info("Test ID 11: Received response", "state", response.State, "payload", response.Payload)

	maxLatencyMs, ok := response.Payload.(float64)
	if !ok {
		return serrors.New("unexpected payload type for latency bound")
	}

	log.Info("Test ID 11: Latency bound", "max_latency_ms", maxLatencyMs)

	bestPath, err := findBestBandwidthPath(paths, int64(maxLatencyMs))
	if err != nil {
		return serrors.WrapStr("finding best bandwidth path", err)
	}

	remote.Path = bestPath.Dataplane()
	remote.NextHop = bestPath.UnderlayNextHop()

	conn, err = network.Dial(ctx, "udp", localAddr, &remote)
	if err != nil {
		return serrors.WrapStr("dialing for test 11 final", err)
	}
	defer conn.Close()

	log.Info("Test ID 11: Sending on best bandwidth path")

	requestBytes, err = json.Marshal(request)
	if err != nil {
		return serrors.WrapStr("marshaling test 11 final request", err)
	}

	_, err = conn.Write(requestBytes)
	if err != nil {
		return serrors.WrapStr("writing test 11 final packet", err)
	}

	conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	n, err = conn.Read(buffer)
	if err != nil {
		return serrors.WrapStr("reading test 11 final response", err)
	}

	err = json.Unmarshal(buffer[:n], &response)
	if err != nil {
		return serrors.WrapStr("unmarshaling test 11 final response", err)
	}

	log.Info("Test ID 11 result", "id", response.ID, "state", response.State)

	if response.State != "TestPassed" {
		return serrors.New("test 11 did not pass", "state", response.State)
	}

	return nil
}

func hasEPICPath(path snet.Path) bool {
	metadata := path.Metadata()
	if metadata == nil {
		return false
	}

	return metadata.EpicAuths.SupportsEpic()
}

func getPathLength(path snet.Path) int {
	metadata := path.Metadata()
	if metadata == nil {
		return 999999
	}
	return len(metadata.Interfaces)
}

// compareInterfaceIDs compares two paths by their interface IDs
// Returns true if path1 should be preferred over path2
func compareInterfaceIDs(path1, path2 snet.Path) bool {
	meta1 := path1.Metadata()
	meta2 := path2.Metadata()

	if meta1 == nil {
		return false
	}
	if meta2 == nil {
		return true
	}

	interfaces1 := meta1.Interfaces
	interfaces2 := meta2.Interfaces

	// Compare interface by interface
	minLen := len(interfaces1)
	if len(interfaces2) < minLen {
		minLen = len(interfaces2)
	}

	for i := 0; i < minLen; i++ {
		id1 := interfaces1[i].ID
		id2 := interfaces2[i].ID

		if id1 < id2 {
			return true
		} else if id1 > id2 {
			return false
		}
	}

	return len(interfaces1) < len(interfaces2)
}

func findEPICPath(paths []snet.Path) (snet.Path, error) {
	if len(paths) == 0 {
		return nil, serrors.New("no paths available")
	}

	log.Info("Finding EPIC hidden path", "total_paths", len(paths))

	var hiddenPaths []snet.Path
	var normalPaths []snet.Path

	for i, path := range paths {
		hasEPIC := hasEPICPath(path)
		pathLen := getPathLength(path)

		log.Info("Analyzing path for EPIC",
			"path_index", i,
			"has_epic", hasEPIC,
			"length", pathLen)

		if hasEPIC {
			hiddenPaths = append(hiddenPaths, path)
		} else {
			normalPaths = append(normalPaths, path)
		}
	}

	var candidatePaths []snet.Path
	if len(hiddenPaths) > 0 {
		log.Info("Found EPIC hidden paths", "count", len(hiddenPaths))
		candidatePaths = hiddenPaths
	} else {
		log.Info("No EPIC hidden paths found, using normal paths", "count", len(normalPaths))
		candidatePaths = normalPaths
	}

	if len(candidatePaths) == 0 {
		return nil, serrors.New("no candidate paths available")
	}

	bestPath := candidatePaths[0]
	bestLength := getPathLength(bestPath)

	for i := 1; i < len(candidatePaths); i++ {
		currPath := candidatePaths[i]
		currLength := getPathLength(currPath)

		if currLength < bestLength {

			bestPath = currPath
			bestLength = currLength
			log.Info("Found shorter path", "path_index", i, "length", currLength)
		} else if currLength == bestLength {

			if compareInterfaceIDs(currPath, bestPath) {
				bestPath = currPath
				log.Info("Found path with lower interface IDs", "path_index", i)
			}
		}
	}

	log.Info("Selected EPIC path",
		"has_epic", hasEPICPath(bestPath),
		"length", bestLength)

	return bestPath, nil
}
func sendTest20(daemonConn daemon.Connector, network *snet.SCIONNetwork, localAddr *net.UDPAddr, localIA addr.IA) error {
	ctx := context.Background()

	log.Info("Test ID 20: Fetching EPIC-enabled paths")

	epicPaths, err := daemonConn.Paths(ctx, remote.IA, localIA, daemon.PathReqFlags{
		Hidden: true,
	})
	if err != nil {
		return serrors.WrapStr("querying EPIC paths", err)
	}

	log.Info("Test ID 20: Finding EPIC hidden path", "total_paths", len(epicPaths))

	bestPath, err := findEPICPath(epicPaths)
	if err != nil {
		return serrors.WrapStr("finding EPIC path", err)
	}

	var finalPath snet.Path = bestPath
	hasEPIC := hasEPICPath(bestPath)

	if hasEPIC {
		log.Info("Setting up EPIC dataplane path")

		metadata := bestPath.Metadata()

		scionPath, ok := bestPath.Dataplane().(path.SCION)
		if !ok {
			log.Error("Failed to cast to SCION path for EPIC")
		} else {

			epicDataplane, err := path.NewEPICDataplanePath(
				scionPath,
				metadata.EpicAuths,
			)

			if err != nil {
				log.Error("Failed to create EPIC dataplane", "err", err)
			} else {
				log.Info("EPIC dataplane path created successfully")

				finalPath = &epicPathWrapper{
					originalPath:  bestPath,
					epicDataplane: epicDataplane,
				}
			}
		}
	}

	remote.Path = finalPath.Dataplane()
	remote.NextHop = finalPath.UnderlayNextHop()

	log.Info("Test ID 20: Using selected EPIC path", "has_epic", hasEPIC)

	// Create connection
	conn, err := network.Dial(ctx, "udp", localAddr, &remote)
	if err != nil {
		return serrors.WrapStr("dialing for test 20", err)
	}
	defer conn.Close()

	// Create request
	request := Request{
		ID:      20,
		Payload: map[string]interface{}{},
	}

	requestBytes, err := json.Marshal(request)
	if err != nil {
		return serrors.WrapStr("marshaling test 20 request", err)
	}

	log.Info("Test ID 20: Sending request", "payload", string(requestBytes))

	// Send packet
	_, err = conn.Write(requestBytes)
	if err != nil {
		return serrors.WrapStr("writing test 20 packet", err)
	}

	// Read response
	conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	buffer := make([]byte, 16000)
	n, err := conn.Read(buffer)
	if err != nil {
		return serrors.WrapStr("reading test 20 response", err)
	}

	var response Response
	err = json.Unmarshal(buffer[:n], &response)
	if err != nil {
		return serrors.WrapStr("unmarshaling test 20 response", err)
	}

	log.Info("Test ID 20 result", "id", response.ID, "state", response.State)

	if response.State != "TestPassed" {
		return serrors.New("test 20 did not pass", "state", response.State)
	}

	return nil
}

// epicPathWrapper wraps a path with EPIC dataplane
type epicPathWrapper struct {
	originalPath  snet.Path
	epicDataplane snet.DataplanePath
}

func (e *epicPathWrapper) UnderlayNextHop() *net.UDPAddr {
	return e.originalPath.UnderlayNextHop()
}

func (e *epicPathWrapper) Dataplane() snet.DataplanePath {
	return e.epicDataplane
}

func (e *epicPathWrapper) Metadata() *snet.PathMetadata {
	return e.originalPath.Metadata()
}

func (e *epicPathWrapper) Destination() addr.IA {
	return e.originalPath.Destination()
}

func (e *epicPathWrapper) Source() addr.IA {
	return e.originalPath.Source()
}

func sendTest30(daemonConn daemon.Connector, network *snet.SCIONNetwork, localAddr *net.UDPAddr, localIA addr.IA) error {
	ctx := context.Background()

	log.Info("Test ID 30: FABRID Basic Connectivity")

	fabridPaths, err := daemonConn.Paths(ctx, remote.IA, localIA, daemon.PathReqFlags{
		FetchFabridDetachedMaps: true,
	})
	if err != nil {
		return serrors.WrapStr("querying FABRID paths", err)
	}

	if len(fabridPaths) == 0 {
		return serrors.New("no paths available")
	}

	log.Info("Test ID 30: Found paths", "count", len(fabridPaths))

	var selectedPath snet.Path
	var hasFabrid bool

	for i, path := range fabridPaths {
		metadata := path.Metadata()
		if metadata == nil || len(metadata.FabridInfo) == 0 {
			continue
		}

		for _, info := range metadata.FabridInfo {
			if info.Enabled {
				selectedPath = path
				hasFabrid = true
				log.Info("Selected FABRID-enabled path", "path_index", i)
				break
			}
		}
		if hasFabrid {
			break
		}
	}

	if selectedPath == nil {
		selectedPath = fabridPaths[0]
		log.Info("No FABRID-enabled paths, using first path")
	}

	if hasFabrid {
		log.Info("Setting up FABRID dataplane path")

		metadata := selectedPath.Metadata()
		scionPath, ok := selectedPath.Dataplane().(path.SCION)
		if !ok {
			log.Error("Failed to cast to path.SCION")
			hasFabrid = false
		} else {
			interfaces := metadata.Interfaces

			hopInterfaces := make([]snet.HopInterface, 0)

			i := 0
			for i < len(interfaces) {
				var igIf, egIf common.IFIDType
				var ia addr.IA

				if i == 0 {

					igIf = 0
					egIf = interfaces[i].ID
					ia = interfaces[i].IA
					i++
				} else if i == len(interfaces)-1 {

					igIf = interfaces[i].ID
					egIf = 0
					ia = interfaces[i].IA
					i++
				} else {

					if interfaces[i].IA == interfaces[i+1].IA {

						igIf = interfaces[i].ID
						egIf = interfaces[i+1].ID
						ia = interfaces[i].IA
						i += 2
					} else {

						igIf = interfaces[i].ID
						egIf = 0
						ia = interfaces[i].IA
						i++
					}
				}

				// Get FABRID info for this hop
				hopIdx := len(hopInterfaces)
				var fabridEnabled bool
				var policies []*fabrid.Policy

				if hopIdx < len(metadata.FabridInfo) {
					fabridEnabled = metadata.FabridInfo[hopIdx].Enabled
					policies = metadata.FabridInfo[hopIdx].Policies
				}

				hopInterfaces = append(hopInterfaces, snet.HopInterface{
					IgIf:          igIf,
					EgIf:          egIf,
					IA:            ia,
					FabridEnabled: fabridEnabled,
					Policies:      policies,
				})
			}

			log.Info("Constructed hop interfaces", "count", len(hopInterfaces))

			fabridQuery, err := fabridquery.ParseFabridQuery("0-0#0,0@0")
			if err != nil {
				log.Error("Failed to parse FABRID query", "err", err)
				hasFabrid = false
			} else {
				matchList := fabridquery.MatchList{
					SelectedPolicies: make([]*fabridquery.Policy, len(hopInterfaces)),
				}

				matched, resultMatchList := fabridQuery.Evaluate(hopInterfaces, &matchList)
				log.Info("FABRID query evaluation", "matched", matched)

				policyIDs := resultMatchList.Policies()
				log.Info("Extracted policy IDs", "count", len(policyIDs))

				if len(policyIDs) == 0 {
					log.Error("No policy IDs from MatchList")
					hasFabrid = false
				} else {
					fabridConfig := &path.FabridConfig{
						LocalIA:         localIA,
						LocalAddr:       localAddr.IP.String(),
						DestinationIA:   remote.IA,
						DestinationAddr: remote.Host.IP.String(),
					}

					fabridDataplane, err := path.NewFABRIDDataplanePath(
						scionPath,
						hopInterfaces,
						policyIDs,
						fabridConfig,
						daemonConn.FabridKeys,
					)

					if err != nil {
						log.Error("Failed to create FABRID dataplane", "err", err)
						hasFabrid = false
					} else {
						log.Info("FABRID dataplane created successfully")
						remote.Path = fabridDataplane
						remote.NextHop = selectedPath.UnderlayNextHop()
					}
				}
			}
		}
	}

	if !hasFabrid {
		remote.Path = selectedPath.Dataplane()
		remote.NextHop = selectedPath.UnderlayNextHop()
	}

	log.Info("Test ID 30: Using path", "has_fabrid", hasFabrid)

	conn, err := network.Dial(ctx, "udp", localAddr, &remote)
	if err != nil {
		return serrors.WrapStr("dialing for test 30", err)
	}
	defer conn.Close()

	request := Request{
		ID:      30,
		Payload: hasFabrid,
	}

	requestBytes, err := json.Marshal(request)
	if err != nil {
		return serrors.WrapStr("marshaling test 30 request", err)
	}

	log.Info("Test ID 30: Sending request", "payload", string(requestBytes))

	_, err = conn.Write(requestBytes)
	if err != nil {
		return serrors.WrapStr("writing test 30 packet", err)
	}

	conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	buffer := make([]byte, 16000)
	n, err := conn.Read(buffer)
	if err != nil {
		return serrors.WrapStr("reading test 30 response", err)
	}

	var response Response
	err = json.Unmarshal(buffer[:n], &response)
	if err != nil {
		return serrors.WrapStr("unmarshaling test 30 response", err)
	}

	log.Info("Test ID 30 result", "id", response.ID, "state", response.State)

	if response.State != "TestPassed" {
		return serrors.New("test 30 did not pass", "state", response.State)
	}

	return nil
}
func sendTest31(daemonConn daemon.Connector, network *snet.SCIONNetwork, localAddr *net.UDPAddr, localIA addr.IA) error {
	ctx := context.Background()

	log.Info("Test ID 31: FABRID Manufacturer A or B")

	fabridPaths, err := daemonConn.Paths(ctx, remote.IA, localIA, daemon.PathReqFlags{
		FetchFabridDetachedMaps: true,
	})
	if err != nil {
		return serrors.WrapStr("querying FABRID paths", err)
	}

	if len(fabridPaths) == 0 {
		return serrors.New("no paths available")
	}

	log.Info("Test ID 31: Found paths", "count", len(fabridPaths))

	fabridQuery, err := fabridquery.ParseFabridQuery("0-0#0,0@L1000#0-0#0,0@L1001#0-0#0,0@REJECT")
	if err != nil {
		return serrors.WrapStr("parsing FABRID query", err)
	}

	type pathCandidate struct {
		path          snet.Path
		matchList     *fabridquery.MatchList
		numHops       int
		hopInterfaces []snet.HopInterface
	}

	var candidates []pathCandidate

	for _, p := range fabridPaths {
		metadata := p.Metadata()
		if metadata == nil || len(metadata.FabridInfo) == 0 {
			continue
		}

		interfaces := metadata.Interfaces
		hopInterfaces := make([]snet.HopInterface, 0)

		i := 0
		for i < len(interfaces) {
			var igIf, egIf common.IFIDType
			var ia addr.IA

			if i == 0 {
				igIf = 0
				egIf = interfaces[i].ID
				ia = interfaces[i].IA
				i++
			} else if i == len(interfaces)-1 {
				igIf = interfaces[i].ID
				egIf = 0
				ia = interfaces[i].IA
				i++
			} else {
				if interfaces[i].IA == interfaces[i+1].IA {
					igIf = interfaces[i].ID
					egIf = interfaces[i+1].ID
					ia = interfaces[i].IA
					i += 2
				} else {
					igIf = interfaces[i].ID
					egIf = 0
					ia = interfaces[i].IA
					i++
				}
			}

			hopIdx := len(hopInterfaces)
			var fabridEnabled bool
			var policies []*fabrid.Policy

			if hopIdx < len(metadata.FabridInfo) {
				fabridEnabled = metadata.FabridInfo[hopIdx].Enabled
				policies = metadata.FabridInfo[hopIdx].Policies
			}

			hopInterfaces = append(hopInterfaces, snet.HopInterface{
				IgIf:          igIf,
				EgIf:          egIf,
				IA:            ia,
				FabridEnabled: fabridEnabled,
				Policies:      policies,
			})
		}

		matchList := fabridquery.MatchList{
			SelectedPolicies: make([]*fabridquery.Policy, len(hopInterfaces)),
		}

		matched, resultMatchList := fabridQuery.Evaluate(hopInterfaces, &matchList)

		if matched {
			candidates = append(candidates, pathCandidate{
				path:          p,
				matchList:     resultMatchList,
				numHops:       len(hopInterfaces),
				hopInterfaces: hopInterfaces,
			})
			log.Info("Found matching path", "num_hops", len(hopInterfaces))
		}
	}

	var selectedPath snet.Path
	var selectedMatchList *fabridquery.MatchList
	var policyFulfilled bool

	if len(candidates) == 0 {
		log.Info("No paths match policy, using fallback")
		policyFulfilled = false

		for _, p := range fabridPaths {
			metadata := p.Metadata()
			if metadata != nil && len(metadata.FabridInfo) > 0 {
				selectedPath = p
				break
			}
		}

		if selectedPath == nil {
			selectedPath = fabridPaths[0]
		}

		metadata := selectedPath.Metadata()
		interfaces := metadata.Interfaces
		hopInterfaces := make([]snet.HopInterface, 0)

		i := 0
		for i < len(interfaces) {
			var igIf, egIf common.IFIDType
			var ia addr.IA

			if i == 0 {
				igIf = 0
				egIf = interfaces[i].ID
				ia = interfaces[i].IA
				i++
			} else if i == len(interfaces)-1 {
				igIf = interfaces[i].ID
				egIf = 0
				ia = interfaces[i].IA
				i++
			} else {
				if interfaces[i].IA == interfaces[i+1].IA {
					igIf = interfaces[i].ID
					egIf = interfaces[i+1].ID
					ia = interfaces[i].IA
					i += 2
				} else {
					igIf = interfaces[i].ID
					egIf = 0
					ia = interfaces[i].IA
					i++
				}
			}

			hopIdx := len(hopInterfaces)
			var fabridEnabled bool
			var policies []*fabrid.Policy

			if hopIdx < len(metadata.FabridInfo) {
				fabridEnabled = metadata.FabridInfo[hopIdx].Enabled
				policies = metadata.FabridInfo[hopIdx].Policies
			}

			hopInterfaces = append(hopInterfaces, snet.HopInterface{
				IgIf:          igIf,
				EgIf:          egIf,
				IA:            ia,
				FabridEnabled: fabridEnabled,
				Policies:      policies,
			})
		}

		wildcardQuery, _ := fabridquery.ParseFabridQuery("0-0#0,0@0")
		matchList := fabridquery.MatchList{
			SelectedPolicies: make([]*fabridquery.Policy, len(hopInterfaces)),
		}
		_, resultMatchList := wildcardQuery.Evaluate(hopInterfaces, &matchList)
		selectedMatchList = resultMatchList

	} else {
		policyFulfilled = true

		minHops := candidates[0].numHops
		for _, candidate := range candidates[1:] {
			if candidate.numHops < minHops {
				minHops = candidate.numHops
			}
		}

		var shortestPaths []pathCandidate
		for _, candidate := range candidates {
			if candidate.numHops == minHops {
				shortestPaths = append(shortestPaths, candidate)
			}
		}

		log.Info("Found shortest paths", "count", len(shortestPaths), "hop_count", minHops)

		if len(shortestPaths) == 1 {

			selectedPath = shortestPaths[0].path
			selectedMatchList = shortestPaths[0].matchList
			log.Info("Selected unique shortest path")
		} else {

			selectedCandidate := shortestPaths[0]

			for _, candidate := range shortestPaths[1:] {

				if len(selectedCandidate.hopInterfaces) > 1 && len(candidate.hopInterfaces) > 1 {
					hop1Selected := selectedCandidate.hopInterfaces[1]
					hop1Candidate := candidate.hopInterfaces[1]

					if hop1Candidate.IgIf < hop1Selected.IgIf {
						selectedCandidate = candidate
					}

				}
			}

			selectedPath = selectedCandidate.path
			selectedMatchList = selectedCandidate.matchList
			log.Info("Selected path after comparing first hop ingress", "first_hop_ingress",
				selectedCandidate.hopInterfaces[1].IgIf)
		}
	}

	metadata := selectedPath.Metadata()
	scionPath, ok := selectedPath.Dataplane().(path.SCION)
	if !ok {
		return serrors.New("failed to cast to path.SCION")
	}

	interfaces := metadata.Interfaces
	hopInterfaces := make([]snet.HopInterface, 0)

	i := 0
	for i < len(interfaces) {
		var igIf, egIf common.IFIDType
		var ia addr.IA

		if i == 0 {
			igIf = 0
			egIf = interfaces[i].ID
			ia = interfaces[i].IA
			i++
		} else if i == len(interfaces)-1 {
			igIf = interfaces[i].ID
			egIf = 0
			ia = interfaces[i].IA
			i++
		} else {
			if interfaces[i].IA == interfaces[i+1].IA {
				igIf = interfaces[i].ID
				egIf = interfaces[i+1].ID
				ia = interfaces[i].IA
				i += 2
			} else {
				igIf = interfaces[i].ID
				egIf = 0
				ia = interfaces[i].IA
				i++
			}
		}

		hopIdx := len(hopInterfaces)
		var fabridEnabled bool
		var policies []*fabrid.Policy

		if hopIdx < len(metadata.FabridInfo) {
			fabridEnabled = metadata.FabridInfo[hopIdx].Enabled
			policies = metadata.FabridInfo[hopIdx].Policies
		}

		hopInterfaces = append(hopInterfaces, snet.HopInterface{
			IgIf:          igIf,
			EgIf:          egIf,
			IA:            ia,
			FabridEnabled: fabridEnabled,
			Policies:      policies,
		})
	}

	policyIDs := selectedMatchList.Policies()

	fabridConfig := &path.FabridConfig{
		LocalIA:         localIA,
		LocalAddr:       localAddr.IP.String(),
		DestinationIA:   remote.IA,
		DestinationAddr: remote.Host.IP.String(),
	}

	fabridDataplane, err := path.NewFABRIDDataplanePath(
		scionPath,
		hopInterfaces,
		policyIDs,
		fabridConfig,
		daemonConn.FabridKeys,
	)

	if err != nil {
		return serrors.WrapStr("creating FABRID dataplane", err)
	}

	remote.Path = fabridDataplane
	remote.NextHop = selectedPath.UnderlayNextHop()

	log.Info("Test ID 31: Using FABRID path", "policy_fulfilled", policyFulfilled)

	conn, err := network.Dial(ctx, "udp", localAddr, &remote)
	if err != nil {
		return serrors.WrapStr("dialing for test 31", err)
	}
	defer conn.Close()

	request := Request{
		ID:      31,
		Payload: policyFulfilled,
	}

	requestBytes, err := json.Marshal(request)
	if err != nil {
		return serrors.WrapStr("marshaling test 31 request", err)
	}

	log.Info("Test ID 31: Sending request", "payload", string(requestBytes))

	_, err = conn.Write(requestBytes)
	if err != nil {
		return serrors.WrapStr("writing test 31 packet", err)
	}

	conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	buffer := make([]byte, 16000)
	n, err := conn.Read(buffer)
	if err != nil {
		return serrors.WrapStr("reading test 31 response", err)
	}

	var response Response
	err = json.Unmarshal(buffer[:n], &response)
	if err != nil {
		return serrors.WrapStr("unmarshaling test 31 response", err)
	}

	log.Info("Test ID 31 result", "id", response.ID, "state", response.State)

	if response.State != "TestPassed" {
		return serrors.New("test 31 did not pass", "state", response.State)
	}

	return nil
}
func sendTest32(daemonConn daemon.Connector, network *snet.SCIONNetwork, localAddr *net.UDPAddr, localIA addr.IA) error {
	ctx := context.Background()

	log.Info("Test ID 32: FABRID ISD-specific policies")

	fabridPaths, err := daemonConn.Paths(ctx, remote.IA, localIA, daemon.PathReqFlags{
		FetchFabridDetachedMaps: true,
	})
	if err != nil {
		return serrors.WrapStr("querying FABRID paths", err)
	}

	if len(fabridPaths) == 0 {
		return serrors.New("no paths available")
	}

	log.Info("Test ID 32: Found paths", "count", len(fabridPaths))

	// ISD 1: manufacturer A (L1000), ISD 2: manufacturer B or C (L1001 or L1002)
	fabridQuery, err := fabridquery.ParseFabridQuery(
		"{1-0#0,0@0 ? 1-0#0,0@L1000 + 1-0#0,0@REJECT : 1-0#0,0@0} + " +
			"{2-0#0,0@0 ? 2-0#0,0@L1001 + 2-0#0,0@L1002 + 2-0#0,0@REJECT : 2-0#0,0@0}",
	)

	if err != nil {
		return serrors.WrapStr("parsing FABRID query", err)
	}

	type pathCandidate struct {
		path          snet.Path
		matchList     *fabridquery.MatchList
		numHops       int
		hopInterfaces []snet.HopInterface
	}

	var candidates []pathCandidate

	for _, p := range fabridPaths {
		metadata := p.Metadata()
		if metadata == nil || len(metadata.FabridInfo) == 0 {
			continue
		}

		interfaces := metadata.Interfaces
		hopInterfaces := make([]snet.HopInterface, 0)

		i := 0
		for i < len(interfaces) {
			var igIf, egIf common.IFIDType
			var ia addr.IA

			if i == 0 {
				igIf = 0
				egIf = interfaces[i].ID
				ia = interfaces[i].IA
				i++
			} else if i == len(interfaces)-1 {
				igIf = interfaces[i].ID
				egIf = 0
				ia = interfaces[i].IA
				i++
			} else {
				if interfaces[i].IA == interfaces[i+1].IA {
					igIf = interfaces[i].ID
					egIf = interfaces[i+1].ID
					ia = interfaces[i].IA
					i += 2
				} else {
					igIf = interfaces[i].ID
					egIf = 0
					ia = interfaces[i].IA
					i++
				}
			}

			hopIdx := len(hopInterfaces)
			var fabridEnabled bool
			var policies []*fabrid.Policy

			if hopIdx < len(metadata.FabridInfo) {
				fabridEnabled = metadata.FabridInfo[hopIdx].Enabled
				policies = metadata.FabridInfo[hopIdx].Policies
			}

			hopInterfaces = append(hopInterfaces, snet.HopInterface{
				IgIf:          igIf,
				EgIf:          egIf,
				IA:            ia,
				FabridEnabled: fabridEnabled,
				Policies:      policies,
			})
		}

		matchList := fabridquery.MatchList{
			SelectedPolicies: make([]*fabridquery.Policy, len(hopInterfaces)),
		}

		matched, resultMatchList := fabridQuery.Evaluate(hopInterfaces, &matchList)
		if matched {
			policyInfo := make([]string, len(resultMatchList.SelectedPolicies))
			for j, selectedPolicy := range resultMatchList.SelectedPolicies {
				if selectedPolicy != nil {
					policyInfo[j] = fmt.Sprintf("Hop%d:%v", j, selectedPolicy)
				} else {
					policyInfo[j] = fmt.Sprintf("Hop%d:nil", j)
				}
			}
			log.Info("Path policies", "policies", policyInfo)
			candidates = append(candidates, pathCandidate{
				path:          p,
				matchList:     resultMatchList,
				numHops:       len(hopInterfaces),
				hopInterfaces: hopInterfaces,
			})
			log.Info("Found matching path", "num_hops", len(hopInterfaces))
		}
	}

	var selectedPath snet.Path
	var selectedMatchList *fabridquery.MatchList
	var policyFulfilled bool

	if len(candidates) == 0 {
		log.Info("No paths match policy, using fallback")
		policyFulfilled = false

		for _, p := range fabridPaths {
			metadata := p.Metadata()
			if metadata != nil && len(metadata.FabridInfo) > 0 {
				selectedPath = p
				break
			}
		}

		if selectedPath == nil {
			selectedPath = fabridPaths[0]
		}

		metadata := selectedPath.Metadata()
		interfaces := metadata.Interfaces
		hopInterfaces := make([]snet.HopInterface, 0)

		i := 0
		for i < len(interfaces) {
			var igIf, egIf common.IFIDType
			var ia addr.IA

			if i == 0 {
				igIf = 0
				egIf = interfaces[i].ID
				ia = interfaces[i].IA
				i++
			} else if i == len(interfaces)-1 {
				igIf = interfaces[i].ID
				egIf = 0
				ia = interfaces[i].IA
				i++
			} else {
				if interfaces[i].IA == interfaces[i+1].IA {
					igIf = interfaces[i].ID
					egIf = interfaces[i+1].ID
					ia = interfaces[i].IA
					i += 2
				} else {
					igIf = interfaces[i].ID
					egIf = 0
					ia = interfaces[i].IA
					i++
				}
			}

			hopIdx := len(hopInterfaces)
			var fabridEnabled bool
			var policies []*fabrid.Policy

			if hopIdx < len(metadata.FabridInfo) {
				fabridEnabled = metadata.FabridInfo[hopIdx].Enabled
				policies = metadata.FabridInfo[hopIdx].Policies
			}

			hopInterfaces = append(hopInterfaces, snet.HopInterface{
				IgIf:          igIf,
				EgIf:          egIf,
				IA:            ia,
				FabridEnabled: fabridEnabled,
				Policies:      policies,
			})
		}

		wildcardQuery, _ := fabridquery.ParseFabridQuery("0-0#0,0@0")
		matchList := fabridquery.MatchList{
			SelectedPolicies: make([]*fabridquery.Policy, len(hopInterfaces)),
		}
		_, resultMatchList := wildcardQuery.Evaluate(hopInterfaces, &matchList)
		selectedMatchList = resultMatchList

	} else {
		policyFulfilled = true

		// Find minimum hop count
		minHops := candidates[0].numHops
		for _, candidate := range candidates[1:] {
			if candidate.numHops < minHops {
				minHops = candidate.numHops
			}
		}

		// Filter to only shortest paths
		var shortestPaths []pathCandidate
		for _, candidate := range candidates {
			if candidate.numHops == minHops {
				shortestPaths = append(shortestPaths, candidate)
			}
		}

		log.Info("Found shortest paths", "count", len(shortestPaths), "hop_count", minHops)

		if len(shortestPaths) == 1 {
			selectedPath = shortestPaths[0].path
			selectedMatchList = shortestPaths[0].matchList
			log.Info("Selected unique shortest path")
		} else {

			selectedCandidate := shortestPaths[0]

			for _, candidate := range shortestPaths[1:] {
				if len(selectedCandidate.hopInterfaces) > 1 && len(candidate.hopInterfaces) > 1 {
					hop1Selected := selectedCandidate.hopInterfaces[1]
					hop1Candidate := candidate.hopInterfaces[1]

					if hop1Candidate.IgIf < hop1Selected.IgIf {
						selectedCandidate = candidate
					}
				}
			}

			selectedPath = selectedCandidate.path
			selectedMatchList = selectedCandidate.matchList
			log.Info("Selected path after comparing first hop ingress",
				"first_hop_ingress", selectedCandidate.hopInterfaces[1].IgIf)
		}
	}

	metadata := selectedPath.Metadata()
	scionPath, ok := selectedPath.Dataplane().(path.SCION)
	if !ok {
		return serrors.New("failed to cast to path.SCION")
	}

	interfaces := metadata.Interfaces
	hopInterfaces := make([]snet.HopInterface, 0)

	i := 0
	for i < len(interfaces) {
		var igIf, egIf common.IFIDType
		var ia addr.IA

		if i == 0 {
			igIf = 0
			egIf = interfaces[i].ID
			ia = interfaces[i].IA
			i++
		} else if i == len(interfaces)-1 {
			igIf = interfaces[i].ID
			egIf = 0
			ia = interfaces[i].IA
			i++
		} else {
			if interfaces[i].IA == interfaces[i+1].IA {
				igIf = interfaces[i].ID
				egIf = interfaces[i+1].ID
				ia = interfaces[i].IA
				i += 2
			} else {
				igIf = interfaces[i].ID
				egIf = 0
				ia = interfaces[i].IA
				i++
			}
		}

		hopIdx := len(hopInterfaces)
		var fabridEnabled bool
		var policies []*fabrid.Policy

		if hopIdx < len(metadata.FabridInfo) {
			fabridEnabled = metadata.FabridInfo[hopIdx].Enabled
			policies = metadata.FabridInfo[hopIdx].Policies
		}

		hopInterfaces = append(hopInterfaces, snet.HopInterface{
			IgIf:          igIf,
			EgIf:          egIf,
			IA:            ia,
			FabridEnabled: fabridEnabled,
			Policies:      policies,
		})
	}

	policyIDs := selectedMatchList.Policies()

	fabridConfig := &path.FabridConfig{
		LocalIA:         localIA,
		LocalAddr:       localAddr.IP.String(),
		DestinationIA:   remote.IA,
		DestinationAddr: remote.Host.IP.String(),
	}

	fabridDataplane, err := path.NewFABRIDDataplanePath(
		scionPath,
		hopInterfaces,
		policyIDs,
		fabridConfig,
		daemonConn.FabridKeys,
	)

	if err != nil {
		return serrors.WrapStr("creating FABRID dataplane", err)
	}

	remote.Path = fabridDataplane
	remote.NextHop = selectedPath.UnderlayNextHop()

	log.Info("Test ID 32: Using FABRID path", "policy_fulfilled", policyFulfilled)

	conn, err := network.Dial(ctx, "udp", localAddr, &remote)
	if err != nil {
		return serrors.WrapStr("dialing for test 32", err)
	}
	defer conn.Close()

	request := Request{
		ID:      32,
		Payload: policyFulfilled,
	}

	requestBytes, err := json.Marshal(request)
	if err != nil {
		return serrors.WrapStr("marshaling test 32 request", err)
	}

	log.Info("Test ID 32: Sending request", "payload", string(requestBytes))

	_, err = conn.Write(requestBytes)
	if err != nil {
		return serrors.WrapStr("writing test 32 packet", err)
	}

	conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	buffer := make([]byte, 16000)
	n, err := conn.Read(buffer)
	if err != nil {
		return serrors.WrapStr("reading test 32 response", err)
	}

	var response Response
	err = json.Unmarshal(buffer[:n], &response)
	if err != nil {
		return serrors.WrapStr("unmarshaling test 32 response", err)
	}

	log.Info("Test ID 32 result", "id", response.ID, "state", response.State)

	if response.State != "TestPassed" {
		return serrors.New("test 32 did not pass", "state", response.State)
	}

	return nil
}
func sendTest33(daemonConn daemon.Connector, network *snet.SCIONNetwork, localAddr *net.UDPAddr, localIA addr.IA) error {
	ctx := context.Background()

	log.Info("Test ID 33: FABRID Remote Attestation")

	fabridPaths, err := daemonConn.Paths(ctx, remote.IA, localIA, daemon.PathReqFlags{
		FetchFabridDetachedMaps: true,
	})
	if err != nil {
		return serrors.WrapStr("querying FABRID paths", err)
	}

	if len(fabridPaths) == 0 {
		return serrors.New("no paths available")
	}

	log.Info("Test ID 33: Found paths", "count", len(fabridPaths))

	fabridQuery, err := fabridquery.ParseFabridQuery("0-0#0,0@L2000#0-0#0,0@L1002#0-0#0,0@REJECT")
	if err != nil {
		return serrors.WrapStr("parsing FABRID query", err)
	}

	type pathCandidate struct {
		path          snet.Path
		matchList     *fabridquery.MatchList
		numHops       int
		hopInterfaces []snet.HopInterface
	}

	var candidates []pathCandidate

	for _, p := range fabridPaths {
		metadata := p.Metadata()
		if metadata == nil || len(metadata.FabridInfo) == 0 {
			continue
		}

		interfaces := metadata.Interfaces
		hopInterfaces := make([]snet.HopInterface, 0)

		i := 0
		for i < len(interfaces) {
			var igIf, egIf common.IFIDType
			var ia addr.IA

			if i == 0 {
				igIf = 0
				egIf = interfaces[i].ID
				ia = interfaces[i].IA
				i++
			} else if i == len(interfaces)-1 {
				igIf = interfaces[i].ID
				egIf = 0
				ia = interfaces[i].IA
				i++
			} else {
				if interfaces[i].IA == interfaces[i+1].IA {
					igIf = interfaces[i].ID
					egIf = interfaces[i+1].ID
					ia = interfaces[i].IA
					i += 2
				} else {
					igIf = interfaces[i].ID
					egIf = 0
					ia = interfaces[i].IA
					i++
				}
			}

			hopIdx := len(hopInterfaces)
			var fabridEnabled bool
			var policies []*fabrid.Policy

			if hopIdx < len(metadata.FabridInfo) {
				fabridEnabled = metadata.FabridInfo[hopIdx].Enabled
				policies = metadata.FabridInfo[hopIdx].Policies
			}

			hopInterfaces = append(hopInterfaces, snet.HopInterface{
				IgIf:          igIf,
				EgIf:          egIf,
				IA:            ia,
				FabridEnabled: fabridEnabled,
				Policies:      policies,
			})
		}

		matchList := fabridquery.MatchList{
			SelectedPolicies: make([]*fabridquery.Policy, len(hopInterfaces)),
		}

		matched, resultMatchList := fabridQuery.Evaluate(hopInterfaces, &matchList)

		if matched {

			lastHopIdx := len(hopInterfaces) - 2
			if lastHopIdx >= 1 {
				lastHopValid := false

				if lastHopIdx < len(resultMatchList.SelectedPolicies) {
					policy := resultMatchList.SelectedPolicies[lastHopIdx]
					if policy != nil && fmt.Sprintf("%v", policy) == "L2000" {
						lastHopValid = true
					}
				}

				if !lastHopValid {
					log.Info("Path rejected - last hop lacks L2000", "num_hops", len(hopInterfaces))
					continue
				}
			}

			candidates = append(candidates, pathCandidate{
				path:          p,
				matchList:     resultMatchList,
				numHops:       len(hopInterfaces),
				hopInterfaces: hopInterfaces,
			})
			log.Info("Found matching path", "num_hops", len(hopInterfaces))
		}
	}

	var selectedPath snet.Path
	var selectedMatchList *fabridquery.MatchList
	var policyFulfilled bool

	if len(candidates) == 0 {
		log.Info("No paths match policy, using fallback")
		policyFulfilled = false

		for _, p := range fabridPaths {
			metadata := p.Metadata()
			if metadata != nil && len(metadata.FabridInfo) > 0 {
				selectedPath = p
				break
			}
		}

		if selectedPath == nil {
			selectedPath = fabridPaths[0]
		}

		metadata := selectedPath.Metadata()
		interfaces := metadata.Interfaces
		hopInterfaces := make([]snet.HopInterface, 0)

		i := 0
		for i < len(interfaces) {
			var igIf, egIf common.IFIDType
			var ia addr.IA

			if i == 0 {
				igIf = 0
				egIf = interfaces[i].ID
				ia = interfaces[i].IA
				i++
			} else if i == len(interfaces)-1 {
				igIf = interfaces[i].ID
				egIf = 0
				ia = interfaces[i].IA
				i++
			} else {
				if interfaces[i].IA == interfaces[i+1].IA {
					igIf = interfaces[i].ID
					egIf = interfaces[i+1].ID
					ia = interfaces[i].IA
					i += 2
				} else {
					igIf = interfaces[i].ID
					egIf = 0
					ia = interfaces[i].IA
					i++
				}
			}

			hopIdx := len(hopInterfaces)
			var fabridEnabled bool
			var policies []*fabrid.Policy

			if hopIdx < len(metadata.FabridInfo) {
				fabridEnabled = metadata.FabridInfo[hopIdx].Enabled
				policies = metadata.FabridInfo[hopIdx].Policies
			}

			hopInterfaces = append(hopInterfaces, snet.HopInterface{
				IgIf:          igIf,
				EgIf:          egIf,
				IA:            ia,
				FabridEnabled: fabridEnabled,
				Policies:      policies,
			})
		}

		wildcardQuery, _ := fabridquery.ParseFabridQuery("0-0#0,0@0")
		matchList := fabridquery.MatchList{
			SelectedPolicies: make([]*fabridquery.Policy, len(hopInterfaces)),
		}
		_, resultMatchList := wildcardQuery.Evaluate(hopInterfaces, &matchList)
		selectedMatchList = resultMatchList

	} else {
		policyFulfilled = true

		minHops := candidates[0].numHops
		for _, candidate := range candidates[1:] {
			if candidate.numHops < minHops {
				minHops = candidate.numHops
			}
		}

		var shortestPaths []pathCandidate
		for _, candidate := range candidates {
			if candidate.numHops == minHops {
				shortestPaths = append(shortestPaths, candidate)
			}
		}

		log.Info("Found shortest paths", "count", len(shortestPaths), "hop_count", minHops)

		if len(shortestPaths) == 1 {
			selectedPath = shortestPaths[0].path
			selectedMatchList = shortestPaths[0].matchList
			log.Info("Selected unique shortest path")
		} else {

			selectedCandidate := shortestPaths[0]

			for _, candidate := range shortestPaths[1:] {
				if len(selectedCandidate.hopInterfaces) > 1 && len(candidate.hopInterfaces) > 1 {
					hop1Selected := selectedCandidate.hopInterfaces[1]
					hop1Candidate := candidate.hopInterfaces[1]

					if hop1Candidate.IgIf < hop1Selected.IgIf {
						selectedCandidate = candidate
					}
				}
			}

			selectedPath = selectedCandidate.path
			selectedMatchList = selectedCandidate.matchList
			log.Info("Selected path after comparing first hop ingress",
				"first_hop_ingress", selectedCandidate.hopInterfaces[1].IgIf)
		}
	}

	metadata := selectedPath.Metadata()
	scionPath, ok := selectedPath.Dataplane().(path.SCION)
	if !ok {
		return serrors.New("failed to cast to path.SCION")
	}

	interfaces := metadata.Interfaces
	hopInterfaces := make([]snet.HopInterface, 0)

	i := 0
	for i < len(interfaces) {
		var igIf, egIf common.IFIDType
		var ia addr.IA

		if i == 0 {
			igIf = 0
			egIf = interfaces[i].ID
			ia = interfaces[i].IA
			i++
		} else if i == len(interfaces)-1 {
			igIf = interfaces[i].ID
			egIf = 0
			ia = interfaces[i].IA
			i++
		} else {
			if interfaces[i].IA == interfaces[i+1].IA {
				igIf = interfaces[i].ID
				egIf = interfaces[i+1].ID
				ia = interfaces[i].IA
				i += 2
			} else {
				igIf = interfaces[i].ID
				egIf = 0
				ia = interfaces[i].IA
				i++
			}
		}

		hopIdx := len(hopInterfaces)
		var fabridEnabled bool
		var policies []*fabrid.Policy

		if hopIdx < len(metadata.FabridInfo) {
			fabridEnabled = metadata.FabridInfo[hopIdx].Enabled
			policies = metadata.FabridInfo[hopIdx].Policies
		}

		hopInterfaces = append(hopInterfaces, snet.HopInterface{
			IgIf:          igIf,
			EgIf:          egIf,
			IA:            ia,
			FabridEnabled: fabridEnabled,
			Policies:      policies,
		})
	}

	policyIDs := selectedMatchList.Policies()

	fabridConfig := &path.FabridConfig{
		LocalIA:         localIA,
		LocalAddr:       localAddr.IP.String(),
		DestinationIA:   remote.IA,
		DestinationAddr: remote.Host.IP.String(),
	}

	fabridDataplane, err := path.NewFABRIDDataplanePath(
		scionPath,
		hopInterfaces,
		policyIDs,
		fabridConfig,
		daemonConn.FabridKeys,
	)

	if err != nil {
		return serrors.WrapStr("creating FABRID dataplane", err)
	}

	remote.Path = fabridDataplane
	remote.NextHop = selectedPath.UnderlayNextHop()

	log.Info("Test ID 33: Using FABRID path", "policy_fulfilled", policyFulfilled)

	conn, err := network.Dial(ctx, "udp", localAddr, &remote)
	if err != nil {
		return serrors.WrapStr("dialing for test 33", err)
	}
	defer conn.Close()

	request := Request{
		ID:      33,
		Payload: policyFulfilled,
	}

	requestBytes, err := json.Marshal(request)
	if err != nil {
		return serrors.WrapStr("marshaling test 33 request", err)
	}

	log.Info("Test ID 33: Sending request", "payload", string(requestBytes))

	_, err = conn.Write(requestBytes)
	if err != nil {
		return serrors.WrapStr("writing test 33 packet", err)
	}

	conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	buffer := make([]byte, 16000)
	n, err := conn.Read(buffer)
	if err != nil {
		return serrors.WrapStr("reading test 33 response", err)
	}

	var response Response
	err = json.Unmarshal(buffer[:n], &response)
	if err != nil {
		return serrors.WrapStr("unmarshaling test 33 response", err)
	}

	log.Info("Test ID 33 result", "id", response.ID, "state", response.State)

	if response.State != "TestPassed" {
		return serrors.New("test 33 did not pass", "state", response.State)
	}

	return nil
}
func sendTest40(daemonConn daemon.Connector, network *snet.SCIONNetwork, localAddr *net.UDPAddr, localIA addr.IA) error {
	ctx := context.Background()

	log.Info("Test ID 40: AS Finder Test")

	paths, err := daemonConn.Paths(ctx, remote.IA, localIA, daemon.PathReqFlags{})
	if err != nil {
		return serrors.WrapStr("querying paths", err)
	}

	if len(paths) == 0 {
		return serrors.New("no paths available")
	}

	selectedPath := paths[0]
	remote.Path = selectedPath.Dataplane()
	remote.NextHop = selectedPath.UnderlayNextHop()

	conn, err := network.Dial(ctx, "udp", localAddr, &remote)
	if err != nil {
		return serrors.WrapStr("dialing for test 40", err)
	}
	defer conn.Close()

	initialRequest := Request{
		ID:      40,
		Payload: nil,
	}

	requestBytes, err := json.Marshal(initialRequest)
	if err != nil {
		return serrors.WrapStr("marshaling initial request", err)
	}

	log.Info("Test ID 40: Sending initial request")

	_, err = conn.Write(requestBytes)
	if err != nil {
		return serrors.WrapStr("writing initial packet", err)
	}

	maxIterations := 10
	for iteration := 0; iteration < maxIterations; iteration++ {
		log.Info("Test ID 40: Waiting for response", "iteration", iteration)

		conn.SetReadDeadline(time.Now().Add(5 * time.Second))
		buffer := make([]byte, 16000)

		n, err := conn.Read(buffer)
		if err != nil {
			return serrors.WrapStr("reading response", err)
		}

		var response Response
		err = json.Unmarshal(buffer[:n], &response)
		if err != nil {
			return serrors.WrapStr("unmarshaling response", err)
		}

		log.Info("Test ID 40: Received response", "state", response.State)

		if response.State == "TestPassed" {
			log.Info("Test ID 40: Test passed")
			return nil
		}

		if response.State != "TestRunning" {
			return serrors.New("unexpected test state", "state", response.State)
		}

		asList, err := extractASListReversePath(localIA, daemonConn, ctx)
		if err != nil {
			return serrors.WrapStr("extracting AS list", err)
		}

		log.Info("Test ID 40: Extracted AS list", "ases", asList)

		replyRequest := struct {
			ID      int      `json:"ID"`
			Payload []string `json:"Payload"`
		}{
			ID:      40,
			Payload: asList,
		}

		replyBytes, err := json.Marshal(replyRequest)
		if err != nil {
			return serrors.WrapStr("marshaling reply", err)
		}

		log.Info("Test ID 40: Sending AS list reply", "list", asList)

		_, err = conn.Write(replyBytes)
		if err != nil {
			return serrors.WrapStr("writing reply packet", err)
		}
	}

	return serrors.New("test did not complete within max iterations")
}

func extractASListReversePath(localIA addr.IA, daemonConn daemon.Connector, ctx context.Context) ([]string, error) {

	allPaths, err := daemonConn.Paths(ctx, remote.IA, localIA, daemon.PathReqFlags{})
	if err != nil {
		return nil, serrors.WrapStr("querying paths", err)
	}

	if len(allPaths) == 0 {
		return nil, serrors.New("no paths available")
	}

	metadata := allPaths[0].Metadata()
	if metadata == nil {
		return nil, serrors.New("no metadata available")
	}

	asSet := make(map[string]bool)
	var asList []string

	if !asSet[remote.IA.String()] {
		asSet[remote.IA.String()] = true
		asList = append(asList, remote.IA.String())
	}

	for i := len(metadata.Interfaces) - 1; i >= 0; i-- {
		iface := metadata.Interfaces[i]
		asStr := iface.IA.String()
		if !asSet[asStr] {
			asSet[asStr] = true
			asList = append(asList, asStr)
		}
	}

	if !asSet[localIA.String()] {
		asList = append(asList, localIA.String())
	}

	return asList, nil
}
