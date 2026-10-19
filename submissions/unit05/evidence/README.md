# Evidence directory

Store only evidence captured from the actual lab runs for this repository. Name files by threat or invariant ID and include enough context to identify the command, target, date, and result.

- `T-02/`: ruleset export, positive pull-request evidence, direct-push/force-push/failing-check negative outputs.
- `T-07/`: federated identity configuration, trusted workflow output, wrong-subject/wrong-branch negative output, role assignments, and image digest comparison if performed.
- `I-1/`: positive own-record response and negative cross-user response from the local Juice Shop test.
- Other threats: add folders or files for ZAP, Threagile reports, role exports, TLS checks, or webhook tests as applicable.

Do not copy illustrative logs from the worked-example ZIP into this folder and label them as your results. The worked-example archive is a reference for format and reasoning, not evidence that you ran the tests.

Required generated Threat Dragon files belong directly in `submissions/unit05/`: `architecture-v2.png` and `threat-model.json`.
