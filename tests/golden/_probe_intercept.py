import json, sys

data = json.load(open("_dlp_flows.json", encoding="utf-8"))
flows = data.get("flows", [])
print("total flows:", len(flows))

def keys_of_interest(f):
    return {
        "src": f.get("src"), "dst": f.get("dst"),
        "sni": f.get("sni"), "tunnel_sni": f.get("tunnel_sni"),
        "loopback": f.get("loopback"),
        "intercept_vendor": f.get("intercept_vendor"),
        "chain_loopback_key": f.get("chain_loopback_key"),
        "chain_outbound_key": f.get("chain_outbound_key"),
        "severity": f.get("severity"),
    }

# loopback flows
lb = [f for f in flows if str(f.get("src", "")).startswith("127.") or str(f.get("dst", "")).startswith("127.")]
print("loopback flows:", len(lb))
for f in lb[:15]:
    print(json.dumps(keys_of_interest(f), ensure_ascii=False))

print("--- flows WITH intercept_vendor ---")
iv = [f for f in flows if f.get("intercept_vendor")]
print("count:", len(iv))
for f in iv[:10]:
    print(json.dumps(keys_of_interest(f), ensure_ascii=False))

print("--- flows WITH chain_loopback_key ---")
ck = [f for f in flows if f.get("chain_loopback_key")]
print("count:", len(ck))
for f in ck[:10]:
    print(json.dumps(keys_of_interest(f), ensure_ascii=False))
