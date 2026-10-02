import urllib.request, re, os

H = "brynlee-monogrammatic-nonphenomenally.ngrok-free.dev"
base = "http://localhost:8000/apps/ridecheck-web-15b48db5/_next/static/chunks/"
files = ["0844-_p--k6r-.js", "03k-opl7car0z.js", "03~yq9q893hmn.js"]

os.makedirs("/tmp/chunks", exist_ok=True)
for f in files:
    try:
        req = urllib.request.Request(base + f, headers={"Host": H})
        data = urllib.request.urlopen(req, timeout=10).read().decode("utf-8", "replace")
        open("/tmp/chunks/" + f, "w").write(data)
        print("BAIXOU", f, len(data))
    except Exception as e:
        print("ERRO", f, e)

pats = [r'"/([^"]*api/auth[^"]*)"', r"`/([^`]*api/auth[^`]*)`", r"api/auth/csrf", r"getCsrfToken"]
import glob
for f in glob.glob("/tmp/chunks/*.js"):
    txt = open(f).read()
    print("\n===", f, "===")
    for pat in pats:
        ms = re.findall(pat, txt)
        for m in ms[:8]:
            print(" ", m)