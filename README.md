# Antero Wazuh Helm Repository

This is the public Helm repository for deploying [Wazuh](https://wazuh.com/) via Helm charts, maintained by the Antero team.

## Requirements

[Helm](https://helm.sh) must be installed to use the charts.
Please refer to Helm's [documentation](https://helm.sh/docs/) to get started.

## Add the repo

```bash
helm repo add antero-wazuh https://antero.github.io/wazuh-helm-chart
helm repo update
```

You can then run `helm search repo antero-wazuh` to see the charts.
