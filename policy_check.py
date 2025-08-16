import sys, json

with open(sys.argv[1]) as f:
    pol = json.load(f)

issues=[]
for i,stmt in enumerate(pol.get('Statement', []), start=1):
    act = stmt.get('Action', [])
    res = stmt.get('Resource', [])
    act = [act] if isinstance(act,str) else act
    res = [res] if isinstance(res,str) else res
    if any(a == '*' for a in act):
        issues.append((i,'High','Action is * (admin)'))
    if any(r == '*' for r in res):
        issues.append((i,'High','Resource is * (full resource access)'))
    pref = ('iam:*','s3:*','ec2:*')
    if any(str(a).lower().startswith(p.split(':')[0]) and str(a).endsWith('*') for p in pref):
        issues.append((i,'Medium','Broad service-wide permission'))

print('Stmt#\tSeverity\tMessage')
for s,sev,msg in issues: print(f'{s}\t{sev}\t{msg}')
if not issues: print('No high-risk wildcards found.')
