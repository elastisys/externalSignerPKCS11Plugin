package main

import (
	"crypto"
	"crypto/rsa"
	"fmt"
	"log"
	"net"
	"os"
	"strconv"
	"sync"

	"github.com/ThalesIgnite/crypto11"
	"github.com/adrg/xdg"
	"golang.org/x/crypto/ssh/terminal"

	pb "k8s.io/client-go/plugin/pkg/client/auth/externalsigner/v1alpha1"

	"google.golang.org/grpc"
)

const (
	cfgPathLib  = "pathLib"
	cfgSlotID   = "slotId"
	cfgObjectID = "objectId"
)

type server struct {
	pb.UnimplementedExternalSignerServiceServer
}

type clientCache struct {
	mu sync.RWMutex

	cache map[cacheKey]cacheValue
}

var cache = newClientCache()

func newClientCache() *clientCache {
	return &clientCache{cache: make(map[cacheKey]cacheValue)}
}

type cacheKey struct {
	clusterName string
}

type cacheValue struct {
	crypto11Context *crypto11.Context
	objectID        *int
}

func (c *clientCache) getClient(clusterName string) (cacheValue, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	client, ok := c.cache[cacheKey{clusterName: clusterName}]
	return client, ok
}

// setClient attempts to put the client in the cache but may return any clients
// with the same keys set before. This is so there's only ever one client for a provider.
func (c *clientCache) setClient(clusterName string, client cacheValue) cacheValue {
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

func parseConfigMap(configMap map[string]string) (*string, *int, *int, error) {
	path := configMap[cfgPathLib]
	if path == "" {
		return nil, nil, nil, fmt.Errorf("must provide path %s", cfgPathLib)
	}

	slotID, err := strconv.Atoi(configMap[cfgSlotID])
	if err != nil {
		return nil, nil, nil, fmt.Errorf("must provide integer %s: %v", cfgSlotID, err)
	}
	objectID, err := strconv.Atoi(configMap[cfgObjectID])
	if err != nil {
		return nil, nil, nil, fmt.Errorf("must provide integer %s: %v", cfgObjectID, err)
	}

	return &path, &slotID, &objectID, nil
}

func getPin() (*string, error) {
	// pinFromConfig := "123456"
	// pinFromConfig := ""

	var pin string
	// if pinFromConfig != "" {
	// 	pin = pinFromConfig
	// } else {
	fmt.Fprintf(os.Stderr, "Enter pin: ")
	pinByte, err := terminal.ReadPassword(int(os.Stdin.Fd()))
	if err != nil {
		return nil, fmt.Errorf("pin error: %v", err)
	}
	fmt.Fprintf(os.Stderr, "\n")
	pin = string(pinByte)
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
	clusterName := in.GetClusterName()

	log.Printf("Received get certificate request for cluster [%s]", clusterName)

	var crypto11Ctx *crypto11.Context
	var objectID *int
	var cv cacheValue
	var ok bool

	if cv, ok = cache.getClient(clusterName); ok {
		fmt.Printf("Using cached context for get certificate\n")
		crypto11Ctx = cv.crypto11Context
		objectID = cv.objectID
	} else {
		fmt.Printf("Creating new context\n")
		path, slotID, objectIDLocal, err := parseConfigMap(configMap)
		if err != nil {
			return fmt.Errorf("parse config map error: %v", err)
		}

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
		cache.setClient(clusterName, cacheValue{crypto11Context: crypto11Ctx, objectID: objectIDLocal})
	}

	baObjectID := []byte{byte(*objectID)}

	certDat, err := crypto11Ctx.FindCertificate(baObjectID, nil, nil)
	if err != nil {
		return fmt.Errorf("find certificate error: %v", err)
	}

	if certDat == nil {
		return fmt.Errorf("could not find certificate with the given slotID and objectID")
	}

	stream.Send(&pb.CertificateResponse{Content: &pb.CertificateResponse_Certificate{Certificate: certDat.Raw}})
	return nil
}

func (s *server) Sign(in *pb.SignatureRequest, stream pb.ExternalSignerService_SignServer) error {
	// configMap := in.GetConfiguration()
	clusterName := in.GetClusterName()

	log.Printf("Received sign request for cluster [%s]", clusterName)

	var crypto11Ctx *crypto11.Context
	var objectID *int
	var ok bool
	var cv cacheValue

	if cv, ok = cache.getClient(clusterName); ok {
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

	switch in.GetSignerType() {
	case pb.SignatureRequest_RSAPSS:
		pSSOptions := rsa.PSSOptions{
			SaltLength: int(in.GetSignerOptsRSAPSS().GetSaltLenght()),
			Hash:       crypto.Hash(in.GetSignerOptsRSAPSS().GetHash()),
		}

		dat, err = key.Sign(nil, in.GetDigest(), &pSSOptions)
		if err != nil {
			return fmt.Errorf("sign error: %v", err)
		}
	default:
		return fmt.Errorf("SignerOpts for %s are not implemented", in.GetSignerType())
	}

	cache.deleteClient(clusterName)

	log.Printf("Signature sent")

	stream.Send(&pb.SignatureResponse{Content: &pb.SignatureResponse_Signature{Signature: dat}})
	return nil
}

func main() {
	socketPath, err := xdg.RuntimeFile("externalsigner.sock")
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
