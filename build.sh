#!/bin/bash
export PATH=$PATH:/usr/local/go/bin
go build externalSignerPKCS11Plugin.go
cp externalSignerPKCS11Plugin ~/.kube/bin/externalSignerPKCS11Plugin
