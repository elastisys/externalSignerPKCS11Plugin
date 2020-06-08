package main

import (
	"crypto"
	"crypto/rsa"
	"errors"
	"fmt"
	"log"
	"net"
	"os"
	"strconv"
	"sync"

	"github.com/ThalesIgnite/crypto11"
	"github.com/adrg/xdg"
	"github.com/spf13/viper"
	"golang.org/x/crypto/ssh/terminal"

	pb "k8s.io/client-go/plugin/pkg/client/auth/externalsigner/v1alpha1"

	"google.golang.org/grpc"
)

const (
	cfgSocketName = "socketName"
	cfgPathLib    = "pathLib"
	cfgSlotID     = "slotId"
	cfgObjectID   = "objectId"
)

type server struct {
	pb.UnimplementedExternalSignerServiceServer
}

type clientCache struct {
	mu sync.RWMutex

	cache map[cacheKey]*cacheValue
}

var cache = newClientCache()
var passwordReader PasswordReader

func newClientCache() *clientCache {
	return &clientCache{cache: make(map[cacheKey]*cacheValue)}
}

type cacheKey struct {
	clusterName string
}

type cacheValue struct {
	crypto11Context *crypto11.Context
	objectID        *int
}

func (c *clientCache) getClient(clusterName string) (*cacheValue, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	client, ok := c.cache[cacheKey{clusterName: clusterName}]
	return client, ok
}

// setClient attempts to put the client in the cache but may return any clients
// with the same keys set before. This is so there's only ever one client for a provider.
func (c *clientCache) setClient(clusterName string, client *cacheValue) *cacheValue {
	c.mu.Lock()
	defer c.mu.Unlock()
	key := cacheKey{clusterName: clusterName}

	// If another client has already initialized a client for the given provider we want
	// to use that client instead of the one we're trying to set. This is so all transports
	// share a client and can coordinate around the same mutex when refreshing and writing
	// to the kubeconfig.
	if oldClient, ok := c.cache[key]; ok {
		return oldClient
	}

	c.cache[key] = client
	return client
}

func (c *clientCache) deleteClient(clusterName string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	key := cacheKey{clusterName: clusterName}

	c.cache[key].crypto11Context.Close()
	delete(c.cache, key)
}

func loadConfigFile() error {
	err := viper.ReadInConfig() // Find and read the config file
	if err != nil {             // Handle errors reading the config file
		log.Printf("Error while reading config file: %s \n", err)
		return err
	}

	socketName := viper.GetString(cfgSocketName)
	pathLib := viper.GetString(cfgPathLib)
	slotID := viper.GetInt(cfgSlotID)
	objectID := viper.GetInt(cfgObjectID)

	fmt.Printf("=== From external plugin config ===\n")
	fmt.Printf("%s: %s\n", cfgSocketName, socketName)
	fmt.Printf("%s: %s\n", cfgPathLib, pathLib)
	fmt.Printf("%s: %v\n", cfgSlotID, slotID)
	fmt.Printf("%s: %v\n", cfgObjectID, objectID)

	return nil
}

func setDefaultConfig() {
	log.Printf("Setting default configuration\n")
	viper.SetDefault(cfgSocketName, "externalsigner.sock")
	viper.SetDefault(cfgPathLib, "/usr/local/lib/libykcs11.so")
	viper.SetDefault(cfgSlotID, "0")
	viper.SetDefault(cfgObjectID, "2")
}

func getConfig(configMap map[string]string) (*string, *int, *int) {
	path := configMap[cfgPathLib]
	if path == "" {
		path = viper.GetString(cfgPathLib)
	}

	slotID, err := strconv.Atoi(configMap[cfgSlotID])
	if err != nil {
		slotID = viper.GetInt(cfgSlotID)
	}

	objectID, err := strconv.Atoi(configMap[cfgObjectID])
	if err != nil {
		objectID = viper.GetInt(cfgObjectID)
	}

	return &path, &slotID, &objectID
}

type PasswordReader interface {
	ReadPassword() (string, error)
}

type StdInPasswordReader struct {
}

func (pr StdInPasswordReader) ReadPassword() (string, error) {
	pwd, error := terminal.ReadPassword(int(os.Stdin.Fd()))
	return string(pwd), error
}

func readPassword() (string, error) {
	pwd, err := passwordReader.ReadPassword()
	if err != nil {
		return "", err
	}
	if len(pwd) == 0 {
		return "", errors.New("empty password provided")
	}
	return pwd, nil
}

func getPin() (*string, error) {
	// pinFromConfig := "123456"
	// pinFromConfig := ""

	var pin string
	// if pinFromConfig != "" {
	// 	pin = pinFromConfig
	// } else {
	fmt.Fprintf(os.Stderr, "Enter pin: ")
	pin, err := readPassword()

	if err != nil {
		return nil, fmt.Errorf("pin error: %v", err)
	}
	fmt.Fprintf(os.Stderr, "\n")
	// }
	return &pin, nil
}

func getCrypto11ContextWithPin(path string, slotID int, pin string) (*crypto11.Context, error) {
	config := &crypto11.Config{
		Path:       path,
		Pin:        pin,
		SlotNumber: &slotID,
		// MaxSessions:     2,
		// PoolWaitTimeout: 0,
	}

	crypto11Ctx, err := crypto11.Configure(config)
	if err != nil {
		return nil, fmt.Errorf("crypto11 configure error: %v", err)
	}

	return crypto11Ctx, err
}

func (s *server) GetCertificate(in *pb.CertificateRequest, stream pb.ExternalSignerService_GetCertificateServer) error {
	configMap := in.GetConfiguration()
	cluster := in.GetCluster()

	log.Printf("Received get certificate request for cluster [%s]", cluster.Server)

	var crypto11Ctx *crypto11.Context
	var objectID *int
	var cv *cacheValue
	var ok bool

	if cv, ok = cache.getClient(cluster.Server); ok {
		fmt.Printf("Using cached context for get certificate\n")
		crypto11Ctx = cv.crypto11Context
		objectID = cv.objectID
	} else {
		fmt.Printf("Creating new context\n")
		path, slotID, objectIDLocal := getConfig(configMap)

		stream.Send(&pb.CertificateResponse{Content: &pb.CertificateResponse_UserPrompt{UserPrompt: "Provide PIN in the external signer console."}})
		pin, err := getPin()
		if err != nil {
			return err
		}

		crypto11Ctx, err = getCrypto11ContextWithPin(*path, *slotID, *pin)
		if err != nil {
			return fmt.Errorf("get crypto11 context error: %v", err)
		}
		objectID = objectIDLocal
		cache.setClient(cluster.Server, &cacheValue{crypto11Context: crypto11Ctx, objectID: objectIDLocal})
	}

	baObjectID := []byte{byte(*objectID)}

	certDat, err := crypto11Ctx.FindCertificate(baObjectID, nil, nil)
	if err != nil || certDat == nil {
		cache.deleteClient(cluster.Server) // do not cache failing settings

		var errorMessage string
		if err != nil {
			errorMessage = fmt.Sprintf("find certificate error: %v", err)
		} else {
			errorMessage = "could not find certificate with the given slotID and objectID"
		}

		return fmt.Errorf(errorMessage)
	}

	stream.Send(&pb.CertificateResponse{Content: &pb.CertificateResponse_Certificate{Certificate: certDat.Raw}})
	return nil
}

func (s *server) Sign(in *pb.SignatureRequest, stream pb.ExternalSignerService_SignServer) error {
	cluster := in.GetCluster()

	log.Printf("Received sign request for cluster [%s]", cluster.Server)

	var crypto11Ctx *crypto11.Context
	var objectID *int
	var ok bool
	var cv *cacheValue

	if cv, ok = cache.getClient(cluster.Server); ok {
		fmt.Printf("Using cached context for signing\n")
		crypto11Ctx = cv.crypto11Context
		objectID = cv.objectID
	} else {
		return fmt.Errorf("Context not available")

		// stream.Send(&pb.SignatureResponse{Content: &pb.SignatureResponse_UserPrompt{UserPrompt: "Provide PIN in the external signer console."}})
	}

	baObjectID := []byte{byte(*objectID)}

	key, err := crypto11Ctx.FindKeyPair(baObjectID, nil)

	if err != nil {
		return fmt.Errorf("find key pair error: %s", err)
	}
	if key == nil {
		return fmt.Errorf("private key with objectID %v not found", *objectID)
	}

	// attr, err := crypto11Ctx.GetAttributes(key, []crypto11.AttributeType{crypto11.CkaAlwaysAuthenticate})

	var dat []byte

	switch x := in.SignerOpts.(type) {
	case *pb.SignatureRequest_SignerOptsRSAPSS:
		pSSOptions := rsa.PSSOptions{
			SaltLength: int(in.GetSignerOptsRSAPSS().GetSaltLenght()),
			Hash:       crypto.Hash(in.GetSignerOptsRSAPSS().GetHash()),
		}

		dat, err = key.Sign(nil, in.GetDigest(), &pSSOptions)
		if err != nil {
			return fmt.Errorf("sign error: %v", err)
		}
	default:
		return fmt.Errorf("SignerOpts has unexpected type %T", x)
	}

	cache.deleteClient(cluster.Server)

	log.Printf("Signature sent")

	stream.Send(&pb.SignatureResponse{Content: &pb.SignatureResponse_Signature{Signature: dat}})
	return nil
}

func main() {
	viper.SetConfigName("config") // name of config file (without extension)
	viper.SetConfigType("yaml")   // REQUIRED if the config file does not have the extension in the name
	viper.AddConfigPath(".")      // optionally look for config in the working directory

	setDefaultConfig()
	loadConfigFile()

	passwordReader = StdInPasswordReader{}

	socketPath, err := xdg.RuntimeFile(viper.GetString(cfgSocketName))
	if err != nil {
		log.Fatal(err)
	}

	if err := os.RemoveAll(socketPath); err != nil {
		log.Fatal(err)
	}

	lis, err := net.Listen("unix", socketPath)

	if err != nil {
		log.Fatalf("failed to listen: %v", err)
	}
	log.Printf("Listening on: %v\n", lis.Addr().String())

	s := grpc.NewServer()
	pb.RegisterExternalSignerServiceServer(s, &server{})
	if err := s.Serve(lis); err != nil {
		log.Fatalf("failed to serve: %v", err)
	}
}
