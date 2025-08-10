package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"time"

	"github.com/google/uuid"

	types "github.com/gregorybednov/lbc_sdk"
	"github.com/spf13/pflag"
)

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

const configDir = "./config"
const privKeyPath = configDir + "/ed25519.key"
const pubKeyPath = configDir + "/ed25519.pub"

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

func ensureKeypair() (ed25519.PublicKey, ed25519.PrivateKey, error) {
	if _, err := os.Stat(privKeyPath); os.IsNotExist(err) {
		fmt.Println("🔐 Generating new ed25519 keypair...")
		pub, priv, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			return nil, nil, err
		}
		os.MkdirAll(configDir, 0700)
		os.WriteFile(privKeyPath, priv, 0600)
		os.WriteFile(pubKeyPath, pub, 0644)
		return pub, priv, nil
	}
	priv, _ := os.ReadFile(privKeyPath)
	pub, _ := os.ReadFile(pubKeyPath)
	return ed25519.PublicKey(pub), ed25519.PrivateKey(priv), nil
}

func sendTx(tx types.SignedTx, rpcURL string) error {
	txBytes, _ := json.Marshal(tx)
	txB64 := base64.StdEncoding.EncodeToString(txBytes)
	final := map[string]any{
		"jsonrpc": "2.0",
		"id":      uuid.NewString(),
		"method":  "broadcast_tx_commit",
		"params": map[string]string{
			"tx": txB64,
		},
	}
	finalBytes, _ := json.Marshal(final)
	fmt.Println("🚧 Raw tx JSON:", string(txBytes))
	fmt.Printf("🚧 Final RPC body:\n%s\n", string(finalBytes))
	resp, err := http.Post(rpcURL, "application/json", bytes.NewReader(finalBytes))
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	data, _ := io.ReadAll(resp.Body)
	fmt.Println("📡 Response:")
	fmt.Println(string(data))
	if err := parseRPCResult(data); err != nil {
		return err
	}
	return nil
}

func registerCommiter(name, rpcURL string) error {
	pub, priv, _ := ensureKeypair()
	pubB64 := base64.StdEncoding.EncodeToString(pub)
	id := "commiter:" + pubB64
	body := types.CommiterTxBody{
		Type:           "commiter",
		ID:             id,
		Name:           name,
		CommiterPubKey: pubB64,
	}
	bodyBytes, _ := json.Marshal(body)
	sig := ed25519.Sign(priv, bodyBytes)
	tx := types.SignedTx{Body: body, Signature: base64.StdEncoding.EncodeToString(sig)}
	return sendTx(tx, rpcURL)
}

func createPromise(desc, rpcURL string) error {
	pub, priv, _ := ensureKeypair()
	pubB64 := base64.StdEncoding.EncodeToString(pub)

	commiterID := "commiter:" + pubB64
	promiseID := "promise:" + uuid.NewString()
	commitmentID := "commitment:" + uuid.NewString()

	// Объекты тела
	promise := &types.PromiseTxBody{
		Type:        "promise",
		ID:          promiseID,
		Description: desc,
		Timestamp:   time.Now().Unix(),
	}
	commitment := &types.CommitmentTxBody{
		Type:       "commitment",
		ID:         commitmentID,
		PromiseID:  promiseID,
		CommiterID: commiterID,
	}

	// Сборка тела для подписи
	bodyStruct := struct {
		Promise    *types.PromiseTxBody    `json:"promise"`
		Commitment *types.CommitmentTxBody `json:"commitment"`
	}{
		Promise:    promise,
		Commitment: commitment,
	}

	// Сериализация и подпись
	bodyBytes, err := json.Marshal(bodyStruct)
	if err != nil {
		return fmt.Errorf("failed to marshal compound body: %w", err)
	}
	sig := ed25519.Sign(priv, bodyBytes)
	sigB64 := base64.StdEncoding.EncodeToString(sig)

	// Формирование транзакции
	compound := types.CompoundTx{
		Body:      bodyStruct,
		Signature: sigB64,
	}

	// Отправка
	txBytes, err := json.Marshal(compound)
	if err != nil {
		return fmt.Errorf("failed to marshal compound tx: %w", err)
	}
	txB64 := base64.StdEncoding.EncodeToString(txBytes)
	final := map[string]any{
		"jsonrpc": "2.0",
		"id":      uuid.NewString(),
		"method":  "broadcast_tx_commit",
		"params": map[string]string{
			"tx": txB64,
		},
	}

	finalBytes, _ := json.Marshal(final)
	fmt.Printf("🚧 Final RPC body:\n%s\n", string(finalBytes))
	resp, err := http.Post(rpcURL, "application/json", bytes.NewReader(finalBytes))
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	data, _ := io.ReadAll(resp.Body)
	fmt.Println("📡 Response:")
	fmt.Println(string(data))
	if err := parseRPCResult(data); err != nil {
		return err
	}
	return nil
}

func main() {
	var name, desc, rpc string
	pflag.StringVar(&name, "name", "", "register commiter name")
	pflag.StringVar(&desc, "desc", "", "create promise description")
	pflag.StringVar(&rpc, "rpc", "http://localhost:26657", "Tendermint RPC URL")
	pflag.Parse()

	if name != "" {
		err := registerCommiter(name, rpc)
		if err != nil {
			fmt.Fprintf(os.Stderr, "❌ Error: %v\n", err)
			os.Exit(1)
		}
		fmt.Println("✅ Commiter registered successfully")
		return
	}

	if desc != "" {
		err := createPromise(desc, rpc)
		if err != nil {
			fmt.Fprintf(os.Stderr, "❌ Error: %v\n", err)
			os.Exit(1)
		}
		fmt.Println("✅ Promise and Commitment created successfully")
		return
	}

	fmt.Println("⛔ Please provide either --name or --desc")
	os.Exit(1)
}
