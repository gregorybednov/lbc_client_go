package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/spf13/pflag"
)

// ===== RPC plumbing =====

type rpcResp struct {
	JSONRPC string `json:"jsonrpc"`
	ID      any    `json:"id"`
	Error   *struct {
		Code    int    `json:"code"`
		Message string `json:"message"`
		Data    string `json:"data"`
	} `json:"error"`
	Result *struct {
		CheckTx struct {
			Code uint32 `json:"code"`
			Log  string `json:"log"`
		} `json:"check_tx"`
		DeliverTx struct {
			Code uint32 `json:"code"`
			Log  string `json:"log"`
		} `json:"deliver_tx"`
	} `json:"result"`
}

func parseRPCResult(data []byte) error {
	var r rpcResp
	_ = json.Unmarshal(data, &r)
	if r.Error != nil {
		return fmt.Errorf("RPC error: %d %s (%s)", r.Error.Code, r.Error.Message, r.Error.Data)
	}
	if r.Result == nil {
		return fmt.Errorf("empty result")
	}
	if r.Result.CheckTx.Code != 0 {
		return fmt.Errorf("CheckTx failed: %s", r.Result.CheckTx.Log)
	}
	if r.Result.DeliverTx.Code != 0 {
		return fmt.Errorf("DeliverTx failed: %s", r.Result.DeliverTx.Log)
	}
	return nil
}

func postRPC(txB64, rpcURL string) error {
	final := map[string]any{
		"jsonrpc": "2.0",
		"id":      uuid.NewString(),
		"method":  "broadcast_tx_commit",
		"params": map[string]string{
			"tx": txB64,
		},
	}
	finalBytes, _ := json.Marshal(final)
	resp, err := http.Post(rpcURL, "application/json", bytes.NewReader(finalBytes))
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	data, _ := io.ReadAll(resp.Body)
	return parseRPCResult(data)
}

// ===== Keys =====

const configDir = "./config"
const privKeyPath = configDir + "/ed25519.key"
const pubKeyPath = configDir + "/ed25519.pub"

func ensureKeypair() (ed25519.PublicKey, ed25519.PrivateKey, error) {
	if _, err := os.Stat(privKeyPath); os.IsNotExist(err) {
		fmt.Println("🔐 Generating new ed25519 keypair...")
		pub, priv, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			return nil, nil, err
		}
		_ = os.MkdirAll(configDir, 0700)
		_ = os.WriteFile(privKeyPath, priv, 0600)
		_ = os.WriteFile(pubKeyPath, pub, 0644)
		return pub, priv, nil
	}
	priv, err := os.ReadFile(privKeyPath)
	if err != nil {
		return nil, nil, err
	}
	pub, err := os.ReadFile(pubKeyPath)
	if err != nil {
		return nil, nil, err
	}
	return ed25519.PublicKey(pub), ed25519.PrivateKey(priv), nil
}

// ===== Tx bodies per ER =====

type CommiterTxBody struct {
	Type           string `json:"type"` // "commiter"
	ID             string `json:"id"`
	Name           string `json:"name"`
	CommiterPubKey string `json:"commiter_pubkey"`
}

type BeneficiaryTxBody struct {
	Type string `json:"type"` // "beneficiary"
	ID   string `json:"id"`
	Name string `json:"name"`
}

type PromiseTxBody struct {
	Type            string  `json:"type"` // "promise"
	ID              string  `json:"id"`
	Text            string  `json:"text"`
	Due             int64   `json:"due"`
	BeneficiaryID   string  `json:"beneficiary_id"`
	ParentPromiseID *string `json:"parent_promise_id"`
}

type CommitmentTxBody struct {
	Type       string `json:"type"` // "commitment"
	ID         string `json:"id"`
	PromiseID  string `json:"promise_id"`
	CommiterID string `json:"commiter_id"`
	Due        int64  `json:"due"`
}

type SignedTx struct {
	Body      any    `json:"body"`
	Signature string `json:"signature"`
}

type CompositeSignedTx struct {
	Body struct {
		Promise    *PromiseTxBody    `json:"promise"`
		Commitment *CommitmentTxBody `json:"commitment"`
	} `json:"body"`
	Signature string `json:"signature"`
}

// ===== Helpers =====

func mustUUID(prefix string) string { return prefix + ":" + uuid.NewString() }

func parseWhen(s string) (int64, error) {
	if s == "" {
		return 0, errors.New("missing datetime")
	}
	if t, err := time.Parse(time.RFC3339, s); err == nil {
		return t.Unix(), nil
	}
	if t, err := time.Parse("2006-01-02", s); err == nil {
		return time.Date(t.Year(), t.Month(), t.Day(), 0, 0, 0, 0, time.UTC).Unix(), nil
	}
	return 0, fmt.Errorf("cannot parse time: %q (use 2006-01-02 or RFC3339)", s)
}

func sign(priv ed25519.PrivateKey, body any) (sigB64 string, raw []byte, err error) {
	raw, err = json.Marshal(body)
	if err != nil {
		return "", nil, err
	}
	sig := ed25519.Sign(priv, raw)
	return base64.StdEncoding.EncodeToString(sig), raw, nil
}

// ===== High-level ops: send =====

func registerCommiter(name, rpcURL string) error {
	pub, priv, err := ensureKeypair()
	if err != nil {
		return err
	}
	pubB64 := base64.StdEncoding.EncodeToString(pub)
	id := "commiter:" + pubB64
	body := CommiterTxBody{
		Type:           "commiter",
		ID:             id,
		Name:           name,
		CommiterPubKey: pubB64,
	}
	sigB64, _, err := sign(priv, body)
	if err != nil {
		return err
	}
	tx := SignedTx{Body: body, Signature: sigB64}
	txBytes, _ := json.Marshal(tx)
	return postRPC(base64.StdEncoding.EncodeToString(txBytes), rpcURL)
}

func createBeneficiary(name, rpcURL string) (string, error) {
	_, priv, err := ensureKeypair()
	if err != nil {
		return "", err
	}
	id := mustUUID("beneficiary")
	body := BeneficiaryTxBody{
		Type: "beneficiary",
		ID:   id,
		Name: name,
	}
	sigB64, _, err := sign(priv, body)
	if err != nil {
		return "", err
	}
	tx := SignedTx{Body: body, Signature: sigB64}
	txBytes, _ := json.Marshal(tx)
	if err := postRPC(base64.StdEncoding.EncodeToString(txBytes), rpcURL); err != nil {
		return "", err
	}
	return id, nil
}

type CreatePromiseArgs struct {
	Text             string
	DueISO           string
	BeneficiaryID    string
	ParentPromiseID  string
	CommitmentDueISO string
}

func createPromiseAndCommit(args CreatePromiseArgs, rpcURL string) error {
	if args.Text == "" {
		return errors.New("--text is required")
	}
	if args.BeneficiaryID == "" {
		return errors.New("--beneficiary-id is required")
	}
	promiseDue, err := parseWhen(args.DueISO)
	if err != nil {
		return fmt.Errorf("promise --due: %w", err)
	}
	commitDue, err := parseWhen(args.CommitmentDueISO)
	if err != nil {
		return fmt.Errorf("commitment --commitment-due: %w", err)
	}

	pub, priv, err := ensureKeypair()
	if err != nil {
		return err
	}
	pubB64 := base64.StdEncoding.EncodeToString(pub)
	commiterID := "commiter:" + pubB64

	promiseID := mustUUID("promise")
	commitmentID := mustUUID("commitment")

	var parentPtr *string
	if args.ParentPromiseID != "" {
		p := args.ParentPromiseID
		parentPtr = &p
	}

	promise := &PromiseTxBody{
		Type:            "promise",
		ID:              promiseID,
		Text:            args.Text,
		Due:             promiseDue,
		BeneficiaryID:   args.BeneficiaryID,
		ParentPromiseID: parentPtr,
	}
	commitment := &CommitmentTxBody{
		Type:       "commitment",
		ID:         commitmentID,
		PromiseID:  promiseID,
		CommiterID: commiterID,
		Due:        commitDue,
	}

	var compound CompositeSignedTx
	compound.Body.Promise = promise
	compound.Body.Commitment = commitment

	sigB64, _, err := sign(priv, compound.Body)
	if err != nil {
		return err
	}
	compound.Signature = sigB64

	txBytes, err := json.Marshal(compound)
	if err != nil {
		return err
	}
	return postRPC(base64.StdEncoding.EncodeToString(txBytes), rpcURL)
}

// ===== High-level ops: get (abci_query) =====

type abciQueryResp struct {
	JSONRPC string `json:"jsonrpc"`
	ID      any    `json:"id"`
	Result  struct {
		Response struct {
			Code      int    `json:"code"`
			Log       string `json:"log"`
			Info      string `json:"info"`
			Index     string `json:"index"`
			Key       string `json:"key"`
			Value     string `json:"value"` // base64
			ProofOps  any    `json:"proofOps"`
			Height    string `json:"height"`
			Codespace string `json:"codespace"`
		} `json:"response"`
	} `json:"result"`
	Error *struct {
		Code    int    `json:"code"`
		Message string `json:"message"`
		Data    string `json:"data"`
	} `json:"error"`
}

func abciQuery(rpcURL, path, dataB64 string, height string) (*abciQueryResp, error) {
	v := url.Values{}
	// Tendermint любит path в кавычках, как в твоём примере
	v.Set("path", fmt.Sprintf("%q", path))
	if dataB64 != "" {
		v.Set("data", dataB64)
	}
	if height != "" {
		v.Set("height", height)
	}
	u := strings.TrimRight(rpcURL, "/") + "/abci_query?" + v.Encode()
	resp, err := http.Get(u)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	var q abciQueryResp
	if err := json.Unmarshal(b, &q); err != nil {
		return nil, fmt.Errorf("decode json: %w", err)
	}
	if q.Error != nil {
		return nil, fmt.Errorf("RPC error: %d %s (%s)", q.Error.Code, q.Error.Message, q.Error.Data)
	}
	return &q, nil
}

func printRawJSON(obj any) {
	out, _ := json.MarshalIndent(obj, "", "  ")
	fmt.Println(string(out))
}

func tryPrintValueAsJSONOrText(b []byte) {
	// попытка как JSON
	var anyJSON any
	if json.Unmarshal(b, &anyJSON) == nil {
		printRawJSON(anyJSON)
		return
	}
	// если выглядит как текст — печатаем строкой
	s := string(b)
	// грубая эвристика: если есть нулевые байты — покажем как base64
	if strings.IndexByte(s, 0x00) >= 0 {
		fmt.Println(base64.StdEncoding.EncodeToString(b))
		return
	}
	fmt.Println(s)
}

// ===== CLI =====

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(1)
	}
	cmd := os.Args[1]
	switch cmd {
	case "send":
		sendMain(os.Args[2:])
	case "get":
		getMain(os.Args[2:])
	default:
		usage()
		os.Exit(1)
	}
}

func usage() {
	fmt.Println("Usage:")
	fmt.Println("  lbc_client send [--rpc URL] (--name NAME | --beneficiary-name NAME | --text TXT --due DATE --beneficiary-id ID [--parent-id ID] --commitment-due DATE)")
	fmt.Println("  lbc_client get  [--rpc URL] --path PATH [--data BYTES] [--height H] [--raw-json | --value]")
}

func sendMain(args []string) {
	fs := pflag.NewFlagSet("send", pflag.ExitOnError)
	var rpc string
	var name string
	var beneficiaryName string
	var text, due, beneficiaryID, parentID, commitmentDue string

	fs.StringVar(&rpc, "rpc", "http://localhost:26657", "Tendermint RPC URL")
	fs.StringVar(&name, "name", "", "register commiter name")
	fs.StringVar(&beneficiaryName, "beneficiary-name", "", "create beneficiary with a given name")
	fs.StringVar(&text, "text", "", "promise text (required for promise)")
	fs.StringVar(&due, "due", "", "promise due (YYYY-MM-DD or RFC3339)")
	fs.StringVar(&beneficiaryID, "beneficiary-id", "", "beneficiary ID (required for promise)")
	fs.StringVar(&parentID, "parent-id", "", "optional parent promise ID")
	fs.StringVar(&commitmentDue, "commitment-due", "", "commitment due (YYYY-MM-DD or RFC3339)")

	_ = fs.Parse(args)

	switch {
	case name != "":
		if err := registerCommiter(name, rpc); err != nil {
			fmt.Fprintf(os.Stderr, "❌ Error: %v\n", err)
			os.Exit(1)
		}
		fmt.Println("✅ Commiter registered")
	case beneficiaryName != "":
		id, err := createBeneficiary(beneficiaryName, rpc)
		if err != nil {
			fmt.Fprintf(os.Stderr, "❌ Error: %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("✅ Beneficiary created: %s\n", id)
	default:
		// promise+commitment
		if text == "" || due == "" || beneficiaryID == "" || commitmentDue == "" {
			fmt.Fprintln(os.Stderr, "⛔ For promise+commitment you must pass --text, --due, --beneficiary-id, --commitment-due")
			os.Exit(1)
		}
		args := CreatePromiseArgs{
			Text:             text,
			DueISO:           due,
			BeneficiaryID:    beneficiaryID,
			ParentPromiseID:  parentID,
			CommitmentDueISO: commitmentDue,
		}
		if err := createPromiseAndCommit(args, rpc); err != nil {
			fmt.Fprintf(os.Stderr, "❌ Error: %v\n", err)
			os.Exit(1)
		}
		fmt.Println("✅ Promise+Commitment created atomically")
	}
}

func getMain(args []string) {
	fs := pflag.NewFlagSet("get", pflag.ExitOnError)
	var rpc string
	var path string
	var listAlias string
	var dataArg string
	var height string
	var rawJSON bool
	var value bool

	fs.StringVar(&rpc, "rpc", "http://localhost:26657", "Tendermint RPC URL")
	fs.StringVar(&path, "path", "", "ABCI path (e.g. /list/promise)")
	fs.StringVar(&listAlias, "list", "", "entity alias: promise | commitment | commiter | beneficiary")
	fs.StringVar(&dataArg, "data", "", "optional key/arg (sent as base64)")
	fs.StringVar(&height, "height", "", "block height")
	fs.BoolVar(&rawJSON, "raw-json", false, "print raw abci_query JSON")
	fs.BoolVar(&value, "value", false, "decode response.value (base64) and try to parse JSON")

	_ = fs.Parse(args)

	// алиасы -> path
	if path == "" && listAlias != "" {
		switch listAlias {
		case "promise", "commitment", "commiter", "beneficiary":
			path = "/list/" + listAlias
		default:
			fmt.Fprintf(os.Stderr, "⛔ unknown alias for --list: %q\n", listAlias)
			os.Exit(1)
		}
	}

	if path == "" {
		fmt.Fprintln(os.Stderr, "⛔ Either --path or --list is required")
		os.Exit(1)
	}

	// поведение по умолчанию:
	// - при --list, если ни --raw-json, ни --value не заданы → включаем --value
	// - при --path — остаётся прежняя логика (тоже включает --value по умолчанию)
	if !rawJSON && !value {
		value = true
	}

	// data → base64
	var dataB64 string
	if dataArg != "" {
		dataB64 = base64.StdEncoding.EncodeToString([]byte(dataArg))
	}

	q, err := abciQuery(rpc, path, dataB64, height)
	if err != nil {
		fmt.Fprintf(os.Stderr, "❌ Error: %v\n", err)
		os.Exit(1)
	}

	if rawJSON {
		printRawJSON(q)
		return
	}

	// value mode
	valB64 := q.Result.Response.Value
	if valB64 == "" {
		fmt.Println("")
		return
	}
	raw, err := base64.StdEncoding.DecodeString(valB64)
	if err != nil {
		fmt.Fprintf(os.Stderr, "⚠️ cannot base64-decode value: %v\n", err)
		fmt.Println(valB64)
		return
	}
	tryPrintValueAsJSONOrText(raw)
}
