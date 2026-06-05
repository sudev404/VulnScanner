import requests
import time
import json

# Register test user
reg_resp = requests.post('http://localhost:5000/api/auth/register', json={
    'username': 'testuser3',
    'email': 'test3@test.com',
    'password': 'password123'
})

if reg_resp.status_code == 409:
    # User exists, login
    login_resp = requests.post('http://localhost:5000/api/auth/login', json={
        'username': 'testuser3',
        'password': 'password123'
    })
    token = login_resp.json()['token']
else:
    token = reg_resp.json()['token']

headers = {'Authorization': f'Bearer {token}'}

# Start scan
print("Starting scan...")
scan_resp = requests.post('http://localhost:5000/api/scan', 
    json={'target': '8.8.8.8', 'profile': 'quick', 'modules': ['ports'], 'consent_given': True},
    headers=headers)

if scan_resp.status_code != 201:
    print(f"Scan start failed: {scan_resp.status_code}")
    print(scan_resp.json())
    exit(1)

scan_id = scan_resp.json()['scan_id']
print(f'Scan started: {scan_id}')

# Poll status
for i in range(20):
    status_resp = requests.get(f'http://localhost:5000/api/scan/{scan_id}/status', headers=headers)
    status = status_resp.json()
    print(f'[{i}s] Progress: {status["progress"]}% - {status["stage"]}')
    
    if status['db_status'] in ['completed', 'failed']:
        print(f'Scan {status["db_status"]}!')
        
        # Get results
        results_resp = requests.get(f'http://localhost:5000/api/scan/{scan_id}/results', headers=headers)
        results = results_resp.json()
        print(f'Findings: {len(results["findings"])}')
        if results['findings']:
            print(f'Sample finding: {results["findings"][0]["title"]}')
        else:
            print('Scan completed but no findings')
        break
    
    time.sleep(1)
else:
    print("Scan did not complete in 20 seconds")
