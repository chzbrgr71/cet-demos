## Azure Log Analytics - Kusto examples

```bash
# query for cluster-admin clusterrolebinding + extend columns
# detects: kubectl create clusterrolebinding my-svc-acct-admin --clusterrole=cluster-admin --serviceaccount=brianredmond 
AzureDiagnostics
| where Category == "kube-audit"
| where parse_json(log_s).verb == "create"
| where parse_json(tostring(parse_json(tostring(parse_json(log_s).requestObject)).roleRef)).name == "cluster-admin"
| where parse_json(tostring(parse_json(log_s).requestObject)).kind == "ClusterRoleBinding"
| extend k8skind = parse_json(tostring(parse_json(log_s).requestObject)).kind
| extend k8sroleref = parse_json(tostring(parse_json(tostring(parse_json(log_s).requestObject)).roleRef)).name
| extend k8suser = parse_json(tostring(parse_json(log_s).user)).username
| extend k8sipaddress = parse_json(tostring(parse_json(log_s).sourceIPs))[0]

# query for CronJob creation
AzureDiagnostics
| where Category == "kube-audit"
| where parse_json(log_s).verb == "create"
| where parse_json(tostring(parse_json(log_s).requestObject)).kind == "CronJob"

# query for actions from standard user account (az aks get-credentials)
AzureDiagnostics
| where Category == "kube-audit"
| project log_s
| where parse_json(tostring(parse_json(log_s).user)).username == "masterclient"

# query for specific source IP
AzureDiagnostics
| where Category == "kube-audit"
| project log_s
| where parse_json(tostring(parse_json(log_s).sourceIPs))[0] == "192.168.1.1"

# query for RBAC result (allow, deny, etc.)
AzureDiagnostics
| where Category == "kube-audit"
| project log_s
| where parse_json(log_s).verb == "create"
| where parse_json(tostring(parse_json(log_s).annotations)).["authorization.k8s.io/decision"] == "allow"

# query for Azure RBAC AKS role assignment
AzureActivity
| where OperationName == "Create role assignment"
| extend RoleDef = tostring(parse_json(tostring(parse_json(tostring(parse_json(Properties).requestbody)).Properties)).RoleDefinitionId)
| extend  Caller = tostring(parse_json(tostring(parse_json(tostring(parse_json(Properties).requestbody)).Properties)).Caller)
| where RoleDef contains "8e3af657-a8ff-443c-a75c-2fe8c4bcb635" or RoleDef contains "b24988ac-6180-42a0-ab88-20f7382dd24c"
| extend AccountCustomEntity = Caller
| extend IPCustomEntity = CallerIpAddress
| extend URLCustomEntity = HTTPRequest
| extend HostCustomEntity = ResourceId
```


