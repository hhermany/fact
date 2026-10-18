import json,sys,collections,datetime as dt
r=sys.argv[1]
ops={}
for l in open(r+'/ops.jsonl'):
    o=json.loads(l); ops[o['op_id']]=o
ev=json.load(open(r+'/agentprov/events.json'))['events']
def ts(s):
    s=s.rstrip('Z'); a,b=(s.split('.')+['0'])[:2]; return dt.datetime.fromisoformat(a).replace(tzinfo=dt.timezone.utc).timestamp()*1e9+int((b+'000000000')[:9])
meth=collections.Counter(); cover=[]; pos=collections.Counter()
for e in ev:
    t=ts(e['created_at']); meth[e['correlation_method']]+=1
    act=[o for o in ops.values() if o['t_start']<=t<=o['t_end']]
    cover.append(len(act))
    tc=e['tool_call_id']
    if tc and act:
        act.sort(key=lambda o:o['t_start'])
        ids=[o['op_id'] for o in act]
        pos['first' if ids[0]==tc else 'last' if ids[-1]==tc else 'mid' if tc in ids else 'outside']+=1
print(meth); print('janelas ativas no connect: media %.1f max %d'%(sum(cover)/len(cover),max(cover))); print(pos)
