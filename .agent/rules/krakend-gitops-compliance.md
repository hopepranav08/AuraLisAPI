---
trigger: always_on
---

All API gateway configurations must be generated in krakend.json.

Follow KrakenD v3 schema.

Gateway must operate statelessly.

Use concurrent backend aggregation.

Deprecated APIs must return HTTP 410 Gone.

Configuration changes must follow GitOps model.