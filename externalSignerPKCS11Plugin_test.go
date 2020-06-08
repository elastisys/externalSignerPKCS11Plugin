package main

import (
	"context"
	"errors"
	"io"
	"log"
	"net"
	"testing"

	"google.golang.org/grpc"
	"google.golang.org/grpc/test/bufconn"

	pb "k8s.io/client-go/plugin/pkg/client/auth/externalsigner/v1alpha1"
)

const bufSize = 1024 * 1024

var lis *bufconn.Listener

func init() {
	lis = bufconn.Listen(bufSize)
	s := grpc.NewServer()
	pb.RegisterExternalSignerServiceServer(s, &server{})
	go func() {
		if err := s.Serve(lis); err != nil {
			log.Fatalf("Server exited with error: %v", err)
		}
	}()
}

func bufDialer(context.Context, string) (net.Conn, error) {
	return lis.Dial()
}

func TestPluginCache(t *testing.T) {
	cache := newClientCache()

	cN1 := "clusterName1"
	cN2 := "clusterName1"
	cN3 := "clusterName3"

	if _, ok := cache.getClient(cN1); ok {
		t.Fatalf("got client before putting one in the cache")
	}
	assertCacheLen(t, cache, 0)

	cli1 := new(cacheValue)
	cli2 := new(cacheValue)
	cli3 := new(cacheValue)

	gotcli := cache.setClient(cN1, cli1)
	if cli1 != gotcli {
		t.Fatalf("set first client and got a different one")
	}
	assertCacheLen(t, cache, 1)

	gotcli = cache.setClient(cN2, cli2)
	if cli1 != gotcli {
		t.Fatalf("set a second client and didn't get the first")
	}
	assertCacheLen(t, cache, 1)

	gotcli = cache.setClient(cN3, cli3)
	if cli1 == gotcli {
		t.Fatalf("set a third client and got the first")
	}
	if cli3 != gotcli {
		t.Fatalf("set third client and got a different one")
	}
	assertCacheLen(t, cache, 2)
}

func assertCacheLen(t *testing.T, cache *clientCache, length int) {
	t.Helper()
	if len(cache.cache) != length {
		t.Errorf("expected cache length %d got %d", length, len(cache.cache))
	}
}

type stubPasswordReader struct {
	Password    string
	ReturnError bool
}

func (pr stubPasswordReader) ReadPassword() (string, error) {
	if pr.ReturnError {
		return "", errors.New("stubbed error")
	}
	return pr.Password, nil
}

func TestGetCertificate(t *testing.T) {
	ctx := context.Background()
	conn, err := grpc.DialContext(ctx, "bufnet", grpc.WithContextDialer(bufDialer), grpc.WithInsecure())
	if err != nil {
		t.Fatalf("Failed to dial bufnet: %v", err)
	}
	defer conn.Close()

	clusterAddress := "clusterAddress"

	cfg := map[string]string{
		"pathLib":  "/usr/local/lib/libykcs11.so",
		"slotId":   "0",
		"objectId": "2",
	}

	passwordReader = stubPasswordReader{Password: "123456"}

	client := pb.NewExternalSignerServiceClient(conn)
	stream, err := client.GetCertificate(ctx, &pb.CertificateRequest{
		Version: pb.Version_v1alpha1,
		Cluster: &pb.Cluster{
			Server: clusterAddress,
		},
		Configuration: cfg,
	})

	// var certRaw []byte

	for {
		cr, err := stream.Recv()
		if err == io.EOF {
			break
		}
		if err != nil {
			log.Printf("received error from external plugin: %v", err)
			return
		}

		switch x := cr.Content.(type) {
		case *pb.CertificateResponse_Certificate:
			log.Printf("Received certificate")
			// certRaw = x.Certificate
		case *pb.CertificateResponse_UserPrompt:
			log.Printf("Received prompt: %s\n", x.UserPrompt)
		case nil:
			// The field is not set.
		default:
			log.Printf("Certificate response has unexpected type %T", x)
			return
		}
	}

	if err != nil {
		t.Fatalf("SayHello failed: %v", err)
	}

	// Test for output here.
}
