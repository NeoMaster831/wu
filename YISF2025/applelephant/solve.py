URL = "http://211.229.232.98:20688"

import requests

resp = requests.post(URL, files={'file': open('adv.png', 'rb')})

print(resp.text)