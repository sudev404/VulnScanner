import React, { useState, useEffect } from 'react';

const API_URL = 'https://vulnscanner-backend-docker.onrender.com/api';

export default function VulnScannerApp() {
  const [token, setToken] = useState(localStorage.getItem('token'));
  const [user, setUser] = useState(JSON.parse(localStorage.getItem('user') || '{}'));
  const [currentPage, setCurrentPage] = useState('scan');
  const [scans, setScans] = useState([]);

  useEffect(() => {
    if (!token) setCurrentPage('login');
  }, [token]);

  const logout = () => {
    localStorage.removeItem('token');
    localStorage.removeItem('user');
    setToken(null);
    setUser({});
    setCurrentPage('login');
  };

  if (!token) {
    return <LoginPage setToken={setToken} setUser={setUser} />;
  }

  return (
    <div style={{ minHeight: '100vh', background: '#0a0e27', color: '#fff', fontFamily: "'Courier New', monospace" }}>
      {/* Header */}
      <header style={{ background: '#1a1f3a', borderBottom: '2px solid #ff5555', padding: '20px', display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: '20px' }}>
          <h1 style={{ margin: 0, fontSize: '24px', color: '#ff5555' }}>🔍 VULNSCANNER</h1>
          <nav style={{ display: 'flex', gap: '15px' }}>
            <NavButton active={currentPage === 'scan'} onClick={() => setCurrentPage('scan')}>New Scan</NavButton>
            <NavButton active={currentPage === 'results'} onClick={() => setCurrentPage('results')}>Results</NavButton>
            {user.is_admin && <NavButton active={currentPage === 'admin'} onClick={() => setCurrentPage('admin')}>Admin</NavButton>}
          </nav>
        </div>
        <div style={{ display: 'flex', alignItems: 'center', gap: '15px' }}>
          <span>{user.username}</span>
          <button onClick={logout} style={{ padding: '8px 16px', background: '#ff5555', border: 'none', color: '#fff', cursor: 'pointer', borderRadius: '4px' }}>Logout</button>
        </div>
      </header>

      {/* Main Content */}
      <main style={{ padding: '40px' }}>
        {currentPage === 'scan' && <ScanPage token={token} user={user} />}
        {currentPage === 'results' && <ResultsPage token={token} />}
        {currentPage === 'admin' && user.is_admin && <AdminPanel token={token} />}
      </main>
    </div>
  );
}

function NavButton({ active, onClick, children }) {
  return (
    <button onClick={onClick} style={{
      padding: '8px 16px',
      background: active ? '#ff5555' : 'transparent',
      border: `1px solid ${active ? '#ff5555' : '#666'}`,
      color: '#fff',
      cursor: 'pointer',
      borderRadius: '4px'
    }}>
      {children}
    </button>
  );
}

function LoginPage({ setToken, setUser }) {
  const [activeTab, setActiveTab] = useState('login');
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [email, setEmail] = useState('');
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');

  const handleLogin = async () => {
    if (!username.trim() || !password.trim()) {
      setError('Username and password required');
      return;
    }
    setLoading(true);
    setError('');
    try {
      const res = await fetch(`${API_URL}/auth/login`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ username: username.trim(), password })
      });
      const data = await res.json();
      if (!res.ok) throw new Error(data.error);
      localStorage.setItem('token', data.token);
      localStorage.setItem('user', JSON.stringify(data.user));
      setToken(data.token);
      setUser(data.user);
    } catch (err) {
      setError(err.message);
    } finally {
      setLoading(false);
    }
  };

  const handleRegister = async () => {
    if (!username.trim()) {
      setError('Username required');
      return;
    }
    setLoading(true);
    setError('');
    try {
      const res = await fetch(`${API_URL}/auth/register`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ 
          username: username.trim(),
          email: email.trim() || undefined,
          password: password || undefined
        })
      });
      const data = await res.json();
      if (!res.ok) throw new Error(data.error);
      localStorage.setItem('token', data.token);
      localStorage.setItem('user', JSON.stringify(data.user));
      setToken(data.token);
      setUser(data.user);
    } catch (err) {
      setError(err.message);
    } finally {
      setLoading(false);
    }
  };

  const handleKeyPress = (e) => {
    if (e.key === 'Enter') {
      if (activeTab === 'login') handleLogin();
      else handleRegister();
    }
  };

  return (
    <div style={{ minHeight: '100vh', background: 'linear-gradient(135deg, #0a0e27 0%, #1a1f3a 100%)', display: 'flex', alignItems: 'center', justifyContent: 'center', padding: '20px', fontFamily: "'Courier New', monospace", color: '#fff' }}>
      <div style={{ maxWidth: '600px', width: '100%' }}>
        {/* Header */}
        <div style={{ textAlign: 'center', marginBottom: '40px' }}>
          <h1 style={{ fontSize: '48px', marginBottom: '10px', color: '#ff5555', margin: '0 0 10px 0' }}>🔍 VULNSCANNER</h1>
          <p style={{ color: '#999', margin: '0' }}>Vulnerability Assessment Platform</p>
        </div>

        {/* Tab Buttons */}
        <div style={{ display: 'flex', gap: '10px', marginBottom: '30px', background: '#1a1f3a', padding: '10px', borderRadius: '8px' }}>
          <button
            onClick={() => { setActiveTab('login'); setError(''); setPassword(''); }}
            style={{
              flex: 1,
              padding: '12px',
              background: activeTab === 'login' ? '#ff5555' : 'transparent',
              border: 'none',
              color: '#fff',
              cursor: 'pointer',
              borderRadius: '4px',
              fontWeight: 'bold',
              transition: 'all 0.3s',
              fontSize: '16px'
            }}
          >
            LOGIN
          </button>
          <button
            onClick={() => { setActiveTab('register'); setError(''); setPassword(''); }}
            style={{
              flex: 1,
              padding: '12px',
              background: activeTab === 'register' ? '#ff5555' : 'transparent',
              border: 'none',
              color: '#fff',
              cursor: 'pointer',
              borderRadius: '4px',
              fontWeight: 'bold',
              transition: 'all 0.3s',
              fontSize: '16px'
            }}
          >
            REGISTER
          </button>
        </div>

        {/* Login Tab */}
        {activeTab === 'login' && (
          <div style={{ background: '#1a1f3a', padding: '30px', borderRadius: '8px', border: '1px solid #333' }}>
            <h2 style={{ margin: '0 0 20px 0', color: '#ff5555' }}>Login to Your Account</h2>
            
            <label style={{ display: 'block', marginBottom: '15px' }}>
              <div style={{ marginBottom: '8px', color: '#aaa', fontSize: '12px', textTransform: 'uppercase' }}>Username</div>
              <input
                type="text"
                placeholder="Enter your username"
                value={username}
                onChange={(e) => setUsername(e.target.value)}
                onKeyPress={handleKeyPress}
                style={{
                  width: '100%',
                  padding: '12px',
                  background: '#0a0e27',
                  border: '1px solid #444',
                  color: '#fff',
                  borderRadius: '4px',
                  boxSizing: 'border-box',
                  fontSize: '14px'
                }}
              />
            </label>

            <label style={{ display: 'block', marginBottom: '20px' }}>
              <div style={{ marginBottom: '8px', color: '#aaa', fontSize: '12px', textTransform: 'uppercase' }}>Password</div>
              <input
                type="password"
                placeholder="Enter your password"
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                onKeyPress={handleKeyPress}
                style={{
                  width: '100%',
                  padding: '12px',
                  background: '#0a0e27',
                  border: '1px solid #444',
                  color: '#fff',
                  borderRadius: '4px',
                  boxSizing: 'border-box',
                  fontSize: '14px'
                }}
              />
            </label>

            {error && <p style={{ color: '#ff5555', marginBottom: '15px', textAlign: 'center' }}>{error}</p>}

            <button
              onClick={handleLogin}
              disabled={loading}
              style={{
                width: '100%',
                padding: '12px',
                background: loading ? '#666' : '#ff5555',
                border: 'none',
                color: '#fff',
                cursor: loading ? 'not-allowed' : 'pointer',
                borderRadius: '4px',
                fontWeight: 'bold',
                fontSize: '16px',
                opacity: loading ? 0.6 : 1,
                transition: 'all 0.3s'
              }}
            >
              {loading ? 'Logging in...' : '🔓 LOGIN'}
            </button>

            <p style={{ marginTop: '15px', color: '#999', fontSize: '12px', textAlign: 'center' }}>
              Don't have an account? Click the REGISTER tab above
            </p>
          </div>
        )}

        {/* Register Tab */}
        {activeTab === 'register' && (
          <div style={{ background: '#1a1f3a', padding: '30px', borderRadius: '8px', border: '1px solid #333' }}>
            <h2 style={{ margin: '0 0 20px 0', color: '#ff5555' }}>Create New Account</h2>
            
            <label style={{ display: 'block', marginBottom: '15px' }}>
              <div style={{ marginBottom: '8px', color: '#aaa', fontSize: '12px', textTransform: 'uppercase' }}>Username</div>
              <input
                type="text"
                placeholder="Choose a username"
                value={username}
                onChange={(e) => setUsername(e.target.value)}
                onKeyPress={handleKeyPress}
                style={{
                  width: '100%',
                  padding: '12px',
                  background: '#0a0e27',
                  border: '1px solid #444',
                  color: '#fff',
                  borderRadius: '4px',
                  boxSizing: 'border-box',
                  fontSize: '14px'
                }}
              />
            </label>

            <label style={{ display: 'block', marginBottom: '15px' }}>
              <div style={{ marginBottom: '8px', color: '#aaa', fontSize: '12px', textTransform: 'uppercase' }}>Email (Optional)</div>
              <input
                type="email"
                placeholder="your@email.com"
                value={email}
                onChange={(e) => setEmail(e.target.value)}
                onKeyPress={handleKeyPress}
                style={{
                  width: '100%',
                  padding: '12px',
                  background: '#0a0e27',
                  border: '1px solid #444',
                  color: '#fff',
                  borderRadius: '4px',
                  boxSizing: 'border-box',
                  fontSize: '14px'
                }}
              />
            </label>

            <label style={{ display: 'block', marginBottom: '20px' }}>
              <div style={{ marginBottom: '8px', color: '#aaa', fontSize: '12px', textTransform: 'uppercase' }}>Password (Optional)</div>
              <input
                type="password"
                placeholder="Leave blank for auto-generated"
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                onKeyPress={handleKeyPress}
                style={{
                  width: '100%',
                  padding: '12px',
                  background: '#0a0e27',
                  border: '1px solid #444',
                  color: '#fff',
                  borderRadius: '4px',
                  boxSizing: 'border-box',
                  fontSize: '14px'
                }}
              />
            </label>

            {error && <p style={{ color: '#ff5555', marginBottom: '15px', textAlign: 'center' }}>{error}</p>}

            <button
              onClick={handleRegister}
              disabled={loading}
              style={{
                width: '100%',
                padding: '12px',
                background: loading ? '#666' : '#ff5555',
                border: 'none',
                color: '#fff',
                cursor: loading ? 'not-allowed' : 'pointer',
                borderRadius: '4px',
                fontWeight: 'bold',
                fontSize: '16px',
                opacity: loading ? 0.6 : 1,
                transition: 'all 0.3s'
              }}
            >
              {loading ? 'Creating Account...' : '✨ CREATE ACCOUNT'}
            </button>

            <p style={{ marginTop: '15px', color: '#999', fontSize: '12px', textAlign: 'center' }}>
              Already have an account? Click the LOGIN tab above
            </p>
          </div>
        )}
      </div>
    </div>
  );
}

function ScanPage({ token, user }) {
  const [target, setTarget] = useState('127.0.0.1');
  const [profile, setProfile] = useState('quick');
  const [modules, setModules] = useState({ ports: true, services: true, cve: true, web: true, sqli: true, xss: true });
  const [runExploits, setRunExploits] = useState(false);
  const [consent, setConsent] = useState(false);
  const [loading, setLoading] = useState(false);
  const [scanId, setScanId] = useState(null);
  const [progress, setProgress] = useState(0);
  const [stage, setStage] = useState('');
  const [error, setError] = useState('');

  const toggleModule = (mod) => {
    setModules(prev => ({ ...prev, [mod]: !prev[mod] }));
  };

  const startScan = async () => {
    if (!target.trim()) {
      setError('Target required');
      return;
    }
    if (!consent) {
      setError('Must accept consent');
      return;
    }

    setLoading(true);
    setError('');
    try {
      const res = await fetch(`${API_URL}/scan`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${token}`
        },
        body: JSON.stringify({
          target: target.trim(),
          profile,
          modules: Object.keys(modules).filter(m => modules[m]),
          run_exploits: runExploits,
          consent_given: consent
        })
      });

      const data = await res.json();
      if (!res.ok) throw new Error(data.error);

      setScanId(data.scan_id);
      pollScanStatus(data.scan_id, token);
    } catch (err) {
      setError(err.message);
      setLoading(false);
    }
  };

  const pollScanStatus = (id, tok) => {
    const interval = setInterval(async () => {
      try {
        const res = await fetch(`${API_URL}/scan/${id}/status`, {
          headers: { 'Authorization': `Bearer ${tok}` }
        });
        const data = await res.json();
        setProgress(data.progress);
        setStage(data.stage);

        if (!data.is_active) {
          clearInterval(interval);
          setLoading(false);
        }
      } catch (err) {
        console.error(err);
        clearInterval(interval);
      }
    }, 1000);
  };

  if (scanId) {
    return (
      <div style={{ maxWidth: '800px', margin: '0 auto' }}>
        <h2>Scan in Progress</h2>
        <p>Scan ID: {scanId}</p>
        <div style={{ background: '#1a1f3a', padding: '20px', borderRadius: '8px', marginBottom: '20px' }}>
          <div style={{ marginBottom: '10px', color: '#ff5555' }}>{stage || 'Initializing...'}</div>
          <div style={{ background: '#0a0e27', height: '30px', borderRadius: '4px', overflow: 'hidden', border: '1px solid #444' }}>
            <div style={{
              width: `${progress}%`,
              height: '100%',
              background: 'linear-gradient(90deg, #ff5555, #ff8888)',
              transition: 'width 0.3s'
            }} />
          </div>
          <div style={{ marginTop: '10px', textAlign: 'right', color: '#999' }}>{progress}%</div>
          <div style={{ marginTop: '15px', display: 'grid', gridTemplateColumns: 'repeat(4, 1fr)', gap: '8px' }}>
            {['Port Scan', 'CVE Check', 'Nikto', 'SQLi/XSS'].map((ph, i) => (
              <div key={i} style={{
                padding: '6px',
                borderRadius: '4px',
                textAlign: 'center',
                fontSize: '11px',
                background: progress > i * 25 ? '#ff555533' : '#0a0e27',
                border: `1px solid ${progress > i * 25 ? '#ff5555' : '#333'}`,
                color: progress > i * 25 ? '#ff5555' : '#666'
              }}>{ph}</div>
            ))}
          </div>
        </div>
        <button
          onClick={() => { setScanId(null); setProgress(0); setStage(''); }}
          style={{ padding: '10px 20px', background: '#ff5555', border: 'none', color: '#fff', cursor: 'pointer', borderRadius: '4px' }}
        >
          View Results
        </button>
      </div>
    );
  }

  return (
    <div style={{ maxWidth: '800px', margin: '0 auto' }}>
      <h2 style={{ color: '#ff5555', marginBottom: '30px' }}>New Vulnerability Scan</h2>

      <div style={{ background: '#1a1f3a', padding: '30px', borderRadius: '8px', marginBottom: '20px' }}>
        <label style={{ display: 'block', marginBottom: '15px' }}>
          <div style={{ marginBottom: '8px', color: '#ff5555' }}>TARGET (IP or Domain)</div>
          <input
            type="text"
            value={target}
            onChange={(e) => setTarget(e.target.value)}
            placeholder="127.0.0.1"
            style={{
              width: '100%',
              padding: '12px',
              background: '#0a0e27',
              border: '1px solid #444',
              color: '#fff',
              borderRadius: '4px',
              boxSizing: 'border-box'
            }}
          />
        </label>

        <label style={{ display: 'block', marginBottom: '15px' }}>
          <div style={{ marginBottom: '8px', color: '#ff5555' }}>SCAN PROFILE</div>
          <select
            value={profile}
            onChange={(e) => setProfile(e.target.value)}
            style={{
              width: '100%',
              padding: '12px',
              background: '#0a0e27',
              border: '1px solid #444',
              color: '#fff',
              borderRadius: '4px'
            }}
          >
            <option value="quick">Quick (Fast)</option>
            <option value="full">Full (Comprehensive)</option>
            <option value="stealth">Stealth (Slow)</option>
            <option value="web">Web Only</option>
            <option value="vuln">Vuln (CVE + SQLi + XSS)</option>
          </select>
        </label>

        <div style={{ marginBottom: '20px' }}>
          <div style={{ marginBottom: '10px', color: '#ff5555' }}>MODULES</div>
          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(2, 1fr)', gap: '10px' }}>
            {['ports', 'services', 'cve', 'web', 'sqli', 'xss'].map(mod => (
              <label key={mod} style={{ display: 'flex', alignItems: 'center', gap: '8px', cursor: 'pointer' }}>
                <input
                  type="checkbox"
                  checked={modules[mod]}
                  onChange={() => toggleModule(mod)}
                  style={{ cursor: 'pointer' }}
                />
                <span style={{ textTransform: 'capitalize' }}>{mod}</span>
              </label>
            ))}
          </div>
        </div>

        <label style={{ display: 'flex', alignItems: 'center', gap: '10px', marginBottom: '20px', cursor: 'pointer' }}>
          <input
            type="checkbox"
            checked={runExploits}
            onChange={(e) => setRunExploits(e.target.checked)}
            style={{ cursor: 'pointer' }}
          />
          <span>Run Active Exploits</span>
        </label>

        <label style={{ display: 'flex', alignItems: 'center', gap: '10px', marginBottom: '20px', cursor: 'pointer', background: '#0a0e27', padding: '15px', borderRadius: '4px', border: '1px solid #444' }}>
          <input
            type="checkbox"
            checked={consent}
            onChange={(e) => setConsent(e.target.checked)}
            style={{ cursor: 'pointer' }}
          />
          <span>I have permission to scan this target</span>
        </label>

        {error && <p style={{ color: '#ff5555', marginBottom: '15px' }}>{error}</p>}

        <button
          onClick={startScan}
          disabled={loading || !consent}
          style={{
            width: '100%',
            padding: '15px',
            background: loading || !consent ? '#666' : '#ff5555',
            border: 'none',
            color: '#fff',
            cursor: loading || !consent ? 'not-allowed' : 'pointer',
            borderRadius: '4px',
            fontSize: '16px',
            fontWeight: 'bold'
          }}
        >
          {loading ? 'Starting Scan...' : '▶ START SCAN'}
        </button>
      </div>
    </div>
  );
}

function ResultsPage({ token }) {
  const [scans, setScans] = useState([]);
  const [selectedScan, setSelectedScan] = useState(null);
  const [findings, setFindings] = useState([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    fetchScans();
  }, []);

  const fetchScans = async () => {
    try {
      const res = await fetch(`${API_URL}/scans`, {
        headers: { 'Authorization': `Bearer ${token}` }
      });
      const data = await res.json();
      setScans(data.scans || []);
      setLoading(false);
    } catch (err) {
      console.error(err);
      setLoading(false);
    }
  };

  const selectScan = async (scan) => {
    setSelectedScan(scan);
    try {
      const res = await fetch(`${API_URL}/scan/${scan.id}/results`, {
        headers: { 'Authorization': `Bearer ${token}` }
      });
      const data = await res.json();
      setFindings(data.findings || []);
    } catch (err) {
      console.error(err);
    }
  };

  if (loading) return <p>Loading scans...</p>;

  if (selectedScan) {
    return (
      <div style={{ maxWidth: '1000px', margin: '0 auto' }}>
        <button onClick={() => setSelectedScan(null)} style={{ marginBottom: '20px', padding: '8px 16px', background: '#666', border: 'none', color: '#fff', cursor: 'pointer', borderRadius: '4px' }}>← Back</button>
        <h2>Scan Results: {selectedScan.target}</h2>
        <div style={{ background: '#1a1f3a', padding: '20px', borderRadius: '8px', marginBottom: '20px' }}>
          <p><strong>Risk Level:</strong> <span style={{ color: selectedScan.risk_level === 'Critical' ? '#ff5555' : '#ffaa00' }}>{selectedScan.risk_level}</span></p>
          <p><strong>Risk Score:</strong> {selectedScan.risk_score.toFixed(1)}/100</p>
          <p><strong>Status:</strong> {selectedScan.status}</p>
          <p><strong>Findings:</strong> {findings.length}</p>
        </div>

        {findings.length > 0 && (
          <div>
            <h3>Findings</h3>
            {findings.map((f, i) => (
              <div key={i} style={{ background: '#1a1f3a', padding: '15px', marginBottom: '10px', borderRadius: '4px', borderLeft: `4px solid ${f.severity === 'Critical' ? '#ff5555' : f.severity === 'High' ? '#ffaa00' : '#888'}` }}>
                <h4 style={{ margin: '0 0 10px 0' }}>{f.title}</h4>
                <p style={{ margin: '0', color: '#aaa', fontSize: '14px' }}>{f.description}</p>
                <p style={{ margin: '5px 0 0 0', color: '#999', fontSize: '12px' }}>Severity: {f.severity} | Category: {f.category}</p>
              </div>
            ))}
          </div>
        )}
      </div>
    );
  }

  return (
    <div style={{ maxWidth: '1000px', margin: '0 auto' }}>
      <h2 style={{ marginBottom: '20px' }}>Scan Results</h2>
      {scans.length === 0 ? (
        <p style={{ color: '#999' }}>No scans yet. Start a new scan to see results.</p>
      ) : (
        <div>
          {scans.map(scan => (
            <div
              key={scan.id}
              onClick={() => selectScan(scan)}
              style={{
                background: '#1a1f3a',
                padding: '20px',
                marginBottom: '10px',
                borderRadius: '8px',
                cursor: 'pointer',
                border: '1px solid #444',
                display: 'flex',
                justifyContent: 'space-between',
                alignItems: 'center'
              }}
            >
              <div>
                <h3 style={{ margin: '0 0 5px 0' }}>{scan.target}</h3>
                <p style={{ margin: '0', color: '#999', fontSize: '12px' }}>Status: {scan.status}</p>
              </div>
              <div style={{ textAlign: 'right' }}>
                <p style={{ margin: '0', color: scan.risk_level === 'Critical' ? '#ff5555' : '#ffaa00', fontWeight: 'bold' }}>{scan.risk_level}</p>
                <p style={{ margin: '0', color: '#999', fontSize: '12px' }}>{scan.risk_score.toFixed(1)}/100</p>
              </div>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}

function AdminPanel({ token }) {
  const [users, setUsers] = useState([]);
  const [config, setConfig] = useState(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    fetchAdminData();
  }, []);

  const fetchAdminData = async () => {
    try {
      const [usersRes, configRes] = await Promise.all([
        fetch(`${API_URL}/admin/users`, { headers: { 'Authorization': `Bearer ${token}` } }),
        fetch(`${API_URL}/admin/config`, { headers: { 'Authorization': `Bearer ${token}` } })
      ]);
      const usersData = await usersRes.json();
      const configData = await configRes.json();
      setUsers(usersData.users || []);
      setConfig(configData);
      setLoading(false);
    } catch (err) {
      console.error(err);
      setLoading(false);
    }
  };

  if (loading) return <p>Loading admin data...</p>;

  return (
    <div style={{ maxWidth: '1200px', margin: '0 auto' }}>
      <h2 style={{ color: '#ff5555', marginBottom: '30px' }}>Admin Panel</h2>

      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(3, 1fr)', gap: '20px', marginBottom: '40px' }}>
        <AdminCard title="Total Users" value={users.length} />
        <AdminCard title="Active Users" value={users.filter(u => u.is_active).length} />
        <AdminCard title="Max Concurrent Scans" value={config?.max_concurrent_scans || 0} />
      </div>

      <h3 style={{ marginBottom: '15px' }}>Users</h3>
      <div style={{ background: '#1a1f3a', borderRadius: '8px', overflow: 'hidden' }}>
        {users.map((user, i) => (
          <div key={i} style={{
            padding: '15px',
            borderBottom: i < users.length - 1 ? '1px solid #333' : 'none',
            display: 'flex',
            justifyContent: 'space-between',
            alignItems: 'center'
          }}>
            <div>
              <p style={{ margin: '0', fontWeight: 'bold' }}>{user.username}</p>
              <p style={{ margin: '5px 0 0 0', color: '#999', fontSize: '12px' }}>{user.email}</p>
            </div>
            <div style={{ display: 'flex', gap: '10px', alignItems: 'center' }}>
              <span style={{ background: user.is_active ? '#00aa00' : '#aa0000', padding: '4px 8px', borderRadius: '3px', fontSize: '12px' }}>
                {user.is_active ? 'Active' : 'Inactive'}
              </span>
              {user.is_admin && <span style={{ background: '#ff5555', padding: '4px 8px', borderRadius: '3px', fontSize: '12px' }}>Admin</span>}
            </div>
          </div>
        ))}
      </div>
    </div>
  );
}

function AdminCard({ title, value }) {
  return (
    <div style={{ background: '#1a1f3a', padding: '20px', borderRadius: '8px', textAlign: 'center' }}>
      <p style={{ margin: '0', color: '#999', fontSize: '12px', textTransform: 'uppercase' }}>{title}</p>
      <p style={{ margin: '10px 0 0 0', fontSize: '32px', color: '#ff5555', fontWeight: 'bold' }}>{value}</p>
    </div>
  );
}
