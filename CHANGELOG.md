# Changelog

## 0.1.0 (unreleased)

First release.

- LNS front door: token and client-certificate auth per gateway and purpose,
  `/router-info` with a configured URI, frames relayed to ChirpStack Gateway
  Bridge or any muxs, rechecks that drop revoked connections.
- CUPS server: `POST /update-info` delivering URIs, minted credentials
  (recorded before they are sent) and signed firmware.
- Signer process holding the client CA and firmware key, on a private
  address or unix socket.
- Backends: webhook (static bearer or OAuth2 client credentials), YAML file,
  or your own class.
- `basicstation_gate.cups`: the CUPS wire format with no dependencies.
- `basicstation-gate issue` for credential bundles.
- Docker image and a compose example with ChirpStack Gateway Bridge.
- Tested against LoRa Basics Station 2.0.6 and ChirpStack Gateway Bridge 4.1.2.
