# External Signer PKCS#11 Plugin

This plugin is a part of [Kubernetes enhancement], which adds support for
authentication via external TLS certificate signers, what enables usage of
Hardware Security Modules (HSMs), also known as smartcards, cryptographic
processors or, by a popular brand name, YubiKeys(tm), via PKCS#11 standard. This
enhancement allows developers or automation pipelines to authenticate with the
Kubernetes cluster, without requiring access to the client key, hence improving
compliance and security.

## To start using External Signer PKCS#11 Plugin

Since this extension requires some modifications in Kubernetes client-go, which
are not yet included in the upstream repository (we target 1.20 release for the
alpha version), you need to use [the Elastisys version of
Kubernetes](https://github.com/elastisys/kubernetes/tree/feat-external-signer-grpc).

To build the plugin, ensure that you have a working [Go environment] and run:

    ./build.sh

To use this authentication method:

1. Configure kubeconfig to use the External Signer PKCS#11 Plugin for authentication.

    An excerpt from an exemplary kubeconfig file:

    ```yaml
    apiVersion: v1
    kind: Config
    users:
    - name: my-user
      user:
        auth-provider:
          name: externalSigner
          config:
            pathSocket: "unix:///private/hsm.sock"
            objectId: "2"                         # PKCS#11 specific configuration
            slotId: "0"
    ```
2. Start the plugin.

    ```bash
    ./externalSignerPKCS11Plugin
    ```

3. Continue using your Kubernetes cluster as normal, for example, issuing
   kubectl commands.

   ```bash
   kubectl get pods
   ```

## Support

If you need support, reach out to us at: cristian.klein@elastisys.com and jakub@elastisys.com

[Go environment]: https://golang.org/doc/install
[Kubernetes enhancement]: https://github.com/jakubkrzywda/enhancements/tree/master/keps/sig-auth/1750-external-tls-certificate-authenticator