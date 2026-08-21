import re

with open("src/gateway/governance/kms_signer.py", "r") as f:
    content = f.read()

# Add get_public_keys_pem to BaseKMSProvider
base_provider_replace = """    def get_public_key_pem(self) -> bytes:
        \"\"\"Fetch the public key PEM from the cloud provider.\"\"\"
        pass

    def get_public_keys_pem(self) -> dict[str, bytes]:
        \"\"\"Fetch all active public key PEMs. Defaults to returning the single primary key.\"\"\"
        return {"default": self.get_public_key_pem()}
"""
content = re.sub(
    r"    def get_public_key_pem\(self\) -> bytes:\n        \"\"\"Fetch the public key PEM from the cloud provider\.\"\"\"\n        pass\n",
    base_provider_replace,
    content
)

# Add get_public_keys_pem to GCPKMSProvider
gcp_provider_add = """    def get_public_key_pem(self) -> bytes:
        response = self._kms_client.get_public_key(name=self._key_version_name)  # type: ignore[union-attr]
        return response.pem.encode("utf-8")

    def get_public_keys_pem(self) -> dict[str, bytes]:
        \"\"\"Fetch all ENABLED public keys for the CryptoKey to support rotation.\"\"\"
        parts = self._key_version_name.split("/cryptoKeyVersions/")
        if len(parts) != 2:
            return {self._key_version_name: self.get_public_key_pem()}
        
        crypto_key_name = parts[0]
        keys = {}
        try:
            versions = self._kms_client.list_crypto_key_versions(parent=crypto_key_name)  # type: ignore[union-attr]
            for v in versions:
                if v.state.name == "ENABLED":
                    pub = self._kms_client.get_public_key(name=v.name)  # type: ignore[union-attr]
                    keys[v.name] = pub.pem.encode("utf-8")
        except Exception as exc:
            import logging
            logging.getLogger(__name__).warning("Failed to list crypto key versions: %s", exc)
            
        if not keys:
            keys[self._key_version_name] = self.get_public_key_pem()
        return keys
"""
content = re.sub(
    r"    def get_public_key_pem\(self\) -> bytes:\n        response = self._kms_client.get_public_key\(name=self._key_version_name\)  # type: ignore\[union-attr\]\n        return response.pem.encode\(\"utf-8\"\)\n",
    gcp_provider_add,
    content
)

# Add get_jwks to KMSGovernanceSigner
signer_add = """    def get_public_key_pem(self) -> bytes:
        if not self._public_key_pem:
            raise RuntimeError("No public key is loaded.")
        return self._public_key_pem

    def get_jwks(self) -> dict[str, dict]:
        \"\"\"Return a JSON Web Key Set (JWKS) dictionary of all enabled keys.\"\"\"
        from src.gateway.governance.jwks import pem_to_jwk
        
        if not self._provider:
            if self._public_key_pem:
                jwk = pem_to_jwk(self._public_key_pem)
                return {"keys": [jwk]}
            return {"keys": []}
            
        pems = self._provider.get_public_keys_pem()
        keys = []
        for pem in pems.values():
            try:
                keys.append(pem_to_jwk(pem))
            except Exception:
                pass
        return {"keys": keys}
"""
content = re.sub(
    r"    def get_public_key_pem\(self\) -> bytes:\n        if not self._public_key_pem:\n            raise RuntimeError\(\"No public key is loaded.\"\)\n        return self._public_key_pem\n",
    signer_add,
    content
)

with open("src/gateway/governance/kms_signer.py", "w") as f:
    f.write(content)
