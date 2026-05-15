import json
from main import generate_html_report
class O: pass
with open('recon_output.json','r',encoding='utf-8') as f:
    data = json.load(f)
O.domain = data.get('target','report')
O.results = data.get('results', [])
print('Generating HTML report from recon_output.json...')
fn = generate_html_report(O)
print('Wrote:', fn)
