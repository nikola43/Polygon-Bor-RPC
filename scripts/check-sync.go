package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"os"
	"time"
)

const (
	publicRPC = "https://polygon-bor-rpc.publicnode.com"
	localRPC  = "http://127.0.0.1:8545"
	interval  = 5 * time.Second
	timeout   = 10 * time.Second

	// ANSI colors
	green  = "\033[0;32m"
	red    = "\033[0;31m"
	yellow = "\033[1;33m"
	blue   = "\033[0;34m"
	reset  = "\033[0m"
)

type jsonRPCRequest struct {
	JSONRPC string        `json:"jsonrpc"`
	Method  string        `json:"method"`
	Params  []interface{} `json:"params"`
	ID      int           `json:"id"`
}

type jsonRPCResponse struct {
	JSONRPC string          `json:"jsonrpc"`
	Result  json.RawMessage `json:"result"`
	Error   *rpcError       `json:"error,omitempty"`
	ID      int             `json:"id"`
}

type rpcError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

type syncStatus struct {
	CurrentBlock  string `json:"currentBlock"`
	HighestBlock  string `json:"highestBlock"`
	StartingBlock string `json:"startingBlock"`
	KnownStates   string `json:"knownStates"`
	PulledStates  string `json:"pulledStates"`
}

var client = &http.Client{Timeout: timeout}

func rpcCall(url, method string) (*jsonRPCResponse, error) {
	req := jsonRPCRequest{
		JSONRPC: "2.0",
		Method:  method,
		Params:  []interface{}{},
		ID:      1,
	}
	body, err := json.Marshal(req)
	if err != nil {
		return nil, err
	}

	resp, err := client.Post(url, "application/json", bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	var rpcResp jsonRPCResponse
	if err := json.Unmarshal(data, &rpcResp); err != nil {
		return nil, fmt.Errorf("invalid JSON response: %w", err)
	}
	if rpcResp.Error != nil {
		return nil, fmt.Errorf("RPC error %d: %s", rpcResp.Error.Code, rpcResp.Error.Message)
	}
	return &rpcResp, nil
}

func getBlockNumber(url string) (*big.Int, error) {
	resp, err := rpcCall(url, "eth_blockNumber")
	if err != nil {
		return nil, err
	}

	var hexStr string
	if err := json.Unmarshal(resp.Result, &hexStr); err != nil {
		return nil, fmt.Errorf("unexpected result format: %w", err)
	}

	block := new(big.Int)
	if _, ok := block.SetString(hexStr, 0); !ok {
		return nil, fmt.Errorf("cannot parse block number: %s", hexStr)
	}
	return block, nil
}

func getSyncStatus(url string) (*syncStatus, bool, error) {
	resp, err := rpcCall(url, "eth_syncing")
	if err != nil {
		return nil, false, err
	}

	// eth_syncing returns false when not syncing, or an object when syncing
	var falseResult bool
	if err := json.Unmarshal(resp.Result, &falseResult); err == nil {
		return nil, false, nil // not syncing
	}

	var status syncStatus
	if err := json.Unmarshal(resp.Result, &status); err != nil {
		return nil, false, fmt.Errorf("cannot parse sync status: %w", err)
	}
	return &status, true, nil
}

func getPeerCount(url string) (int64, error) {
	resp, err := rpcCall(url, "net_peerCount")
	if err != nil {
		return 0, err
	}

	var hexStr string
	if err := json.Unmarshal(resp.Result, &hexStr); err != nil {
		return 0, err
	}

	n := new(big.Int)
	if _, ok := n.SetString(hexStr, 0); !ok {
		return 0, fmt.Errorf("cannot parse peer count: %s", hexStr)
	}
	return n.Int64(), nil
}

func formatDuration(secs int64) string {
	if secs < 0 {
		return "N/A"
	}
	d := secs / 86400
	h := (secs % 86400) / 3600
	m := (secs % 3600) / 60
	s := secs % 60
	return fmt.Sprintf("%02dd %02dh %02dm %02ds", d, h, m, s)
}

func clearScreen() {
	fmt.Print("\033[H\033[2J")
}

func main() {
	localURL := localRPC
	publicURL := publicRPC

	if len(os.Args) > 1 {
		localURL = os.Args[1]
	}
	if len(os.Args) > 2 {
		publicURL = os.Args[2]
	}

	var prevLocal *big.Int
	var prevTime time.Time

	for {
		now := time.Now()

		publicBlock, pubErr := getBlockNumber(publicURL)
		localBlock, locErr := getBlockNumber(localURL)

		clearScreen()
		fmt.Printf("%s======================================%s\n", blue, reset)
		fmt.Printf("%s      Polygon Sync Monitor (Go)%s\n", blue, reset)
		fmt.Printf("%s======================================%s\n", blue, reset)
		fmt.Printf("  Time          : %s\n", now.Format("2006-01-02 15:04:05"))

		if pubErr != nil {
			fmt.Printf("  Public RPC    : %sERROR%s (%s)\n", red, reset, pubErr)
		} else {
			fmt.Printf("  Public Block  : %s%s%s\n", yellow, publicBlock, reset)
		}

		if locErr != nil {
			fmt.Printf("  Local RPC     : %sERROR%s (%s)\n", red, reset, locErr)
			fmt.Printf("%s--------------------------------------%s\n", blue, reset)
			fmt.Printf("  Waiting for local node...\n")
			prevLocal = nil
			time.Sleep(interval)
			continue
		}

		fmt.Printf("  Local Block   : %s%s%s\n", yellow, localBlock, reset)

		// Blocks behind
		diff := new(big.Int)
		if pubErr == nil {
			diff.Sub(publicBlock, localBlock)
			if diff.Sign() < 0 {
				diff.SetInt64(0)
			}
			fmt.Printf("  Blocks Behind : %s%s%s\n", red, diff, reset)

			// Progress percentage: (local / public) * 100
			if publicBlock.Sign() > 0 {
				// Use float64 for percentage display
				localF := new(big.Float).SetInt(localBlock)
				publicF := new(big.Float).SetInt(publicBlock)
				ratio := new(big.Float).Quo(localF, publicF)
				pct, _ := ratio.Mul(ratio, big.NewFloat(100)).Float64()
				fmt.Printf("  Sync Progress : %s%.4f %%%s\n", green, pct, reset)
			}
		}

		// Sync speed & ETA
		var speed float64
		if prevLocal != nil {
			blockDiff := new(big.Int).Sub(localBlock, prevLocal)
			elapsed := now.Sub(prevTime).Seconds()
			if elapsed > 0 {
				diffF, _ := new(big.Float).SetInt(blockDiff).Float64()
				speed = diffF / elapsed
			}
		}
		fmt.Printf("  Sync Speed    : %s%.2f blocks/sec%s\n", green, speed, reset)

		if speed > 0 && pubErr == nil && diff.Sign() > 0 {
			remaining, _ := new(big.Float).SetInt(diff).Float64()
			etaSecs := int64(remaining / speed)
			fmt.Printf("  ETA           : %s%s%s\n", green, formatDuration(etaSecs), reset)
		} else {
			fmt.Printf("  ETA           : %sN/A%s\n", green, reset)
		}

		// eth_syncing status
		syncObj, isSyncing, syncErr := getSyncStatus(localURL)
		if syncErr == nil {
			if !isSyncing {
				if pubErr == nil && diff.Sign() == 0 {
					fmt.Printf("  Status        : %sFULLY SYNCED%s\n", green, reset)
				} else {
					fmt.Printf("  Status        : %sSYNCING (eth_syncing=false, blocks behind)%s\n", yellow, reset)
				}
			} else if syncObj != nil {
				current := new(big.Int)
				highest := new(big.Int)
				current.SetString(syncObj.CurrentBlock, 0)
				highest.SetString(syncObj.HighestBlock, 0)
				fmt.Printf("  Status        : %sSYNCING%s (current=%s highest=%s)\n", yellow, reset, current, highest)
			}
		}

		// Peer count
		peers, peerErr := getPeerCount(localURL)
		if peerErr == nil {
			fmt.Printf("  Peers         : %s%d%s\n", yellow, peers, reset)
		}

		fmt.Printf("%s======================================%s\n", blue, reset)

		prevLocal = new(big.Int).Set(localBlock)
		prevTime = now

		time.Sleep(interval)
	}
}
