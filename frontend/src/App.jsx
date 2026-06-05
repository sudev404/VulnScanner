import React, { useState, useEffect } from 'react';
import AdminPanel from './AdminPanel';

const API_URL = 'https://vulnscanner-backend-tfm3.onrender.com/api';

export default function VulnScannerApp() {
  const [token, setToken] = useState(localStorage.getItem('token'));
  const [user, setUser] = useState(() => {
    try { return JSON.parse(localStorage.getItem('user') || '{}'); }
    catch { return {}; }
  });
  const [currentPage, setCurrentPage] = useState('scan');
  const [needsAdmin, setNeedsAdmin] = useState(null);

  useEffect(() => {
    if (!token) checkAdminExists();
  }, [token]);

  const checkAdminExists = async () => {
    try {
      const res = await fetch(`${API_URL}/admin/users`);
      setNeedsAdmin(res.status === 403);
    } catch {
      setNeedsAdmin(false);
    }
  };

  const logout = () => {
    localStorage.removeItem('token');
    localStorage.removeItem('user');
    setToken(null);
    setUser({});
    setCurrentPage('scan');
  };

  if (!token) {
    if (needsAdmin === null) return (
      <div style={{ minHeight: '100vh', background: '#0a0e27', color: '#fff', display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
        Loading...
      </div>
    );
    if (needsAdmin) return <AdminSetupPage setToken={setToken} setUser={setUser} checkAdminExists={checkAdminExists} />;
    return <LoginPage setToken={setToken} setUser={setUser} />;
  }

  // Support both user.is_admin (bool) and user.role === 'admin' (string)
  const isAdmin = user.is_admin === true || user.role === 'admin';

  return (
    <div style={{ minHeight: '100vh', background: '#0a0e27', color: '#fff', fontFamily: "'Courier New', monospace" }}>
      <header style={{ background: '#1a1f3a', borderBottom: '2px solid #ff5555', padding: '20px', display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: '20px' }}>
          <h1 style={{ margin: 0, fontSize: '24px', color: '#ff5555' }}>🔍 VULNSCANNER</h1>
          <nav style={{ display: 'flex', gap: '15px' }}>
            <NavButton active={currentPage === 'scan'} onClick={() => setCurrentPage('scan')}>New Scan</NavButton>
            <NavButton active={currentPage === 'results'} onClick={() => setCurrentPage('results')}>Results</NavButton>
            {isAdmin && <NavButton active={currentPage === 'admin'} onClick={() => setCurrentPage('admin')}>Admin</NavButton>}
          </nav>
        </div>
        <div style={{ display: 'flex', alignItems: 'center', gap: '15px' }}>
          <span>
            {user.username}
            {isAdmin && <span style={{ background: '#ff5555', padding: '2px 8px', borderRadius: '3px', fontSize: '12px', marginLeft: '10px' }}>ADMIN</span>}
          </span>
          <button onClick={logout} style={{ padding: '8px 16px', background: '#ff5555', border: 'none', color: '#fff', cursor: 'pointer', borderRadius: '4px' }}>Logout</button>
        </div>
      </header>

      <main style={{ padding: '40px' }}>
        {currentPage === 'scan' && <ScanPage token={token} user={user} />}
        {currentPage === 'results' && <ResultsPage token={token} />}
        {currentPage === 'admin' && isAdmin && <AdminPanel token={token} user={user} />}
      </main>
    </div>
  );
}

// ─── Admin Setup Page ────────────────────────────────────────────────────────

function AdminSetupPage({ setToken, setUser }) {
  const [username, setUsername] = useState('');
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');
  const [success, setSuccess] = useState(false);

  const createAdmin = async () => {
    if (!username.trim() || !email.trim() || !password.trim()) { setError('All fields required'); return; }
    if (password.length < 8) { setError('Password must be 8+ characters'); return; }
    setLoading(true); setError('');
    try {
      const res = await fetch(`${API_URL}/auth/create-admin`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ username: username.trim(), email: email.trim(), password })
      });
      const data = await res.json();
      if (!res.ok) throw new Error(data.error);
      setSuccess(true);
      setTimeout(() => {
        localStorage.setItem('token', data.token);
        localStorage.setItem('user', JSON.stringify(data.user));
        setToken(data.token);
        setUser(data.user);
      }, 1500);
    } catch (err) {
      setError(err.message);
    } finally {
      setLoading(false);
    }
  };

  if (success) return (
    <div style={{ minHeight: '100vh', background: 'linear-gradient(135deg, #0a0e27 0%, #1a1f3a 100%)', display: 'flex', alignItems: 'center', justifyContent: 'center', fontFamily: "'Courier New', monospace", color: '#fff' }}>
      <div style={{ textAlign: 'center' }}>
        <h1 style={{ fontSize: '48px', color: '#00aa00', marginBottom: '20px' }}>✅ Admin Created!</h1>
        <p style={{ color: '#aaa', fontSize: '16px' }}>Redirecting to dashboard...</p>
      </div>
    </div>
  );

  return (
    <div style={{ minHeight: '100vh', background: 'linear-gradient(135deg, #0a0e27 0%, #1a1f3a 100%)', display: 'flex', alignItems: 'center', justifyContent: 'center', padding: '20px', fontFamily: "'Courier New', monospace", color: '#fff' }}>
      <div style={{ maxWidth: '600px', width: '100%' }}>
        <div style={{ textAlign: 'center', marginBottom: '40px' }}>
          <h1 style={{ fontSize: '48px', color: '#ff5555', margin: '0 0 10px 0' }}>🔍 VULNSCANNER</h1>
          <p style={{ color: '#999', margin: 0 }}>Initial Setup - Create Admin Account</p>
        </div>
        <div style={{ background: '#1a1f3a', padding: '30px', borderRadius: '8px', border: '2px solid #ff5555' }}>
          <h2 style={{ margin: '0 0 20px 0', color: '#ff5555' }}>⚙ First Time Setup</h2>
          <p style={{ color: '#aaa', marginBottom: '20px' }}>No admin account found. Create the first administrator account to get started.</p>
          {[
            { label: 'Admin Username', type: 'text', val: username, set: setUsername, ph: 'admin' },
            { label: 'Admin Email', type: 'email', val: email, set: setEmail, ph: 'admin@vulnscanner.local' },
            { label: 'Admin Password (8+ chars)', type: 'password', val: password, set: setPassword, ph: 'Strong password' },
          ].map(({ label, type, val, set, ph }) => (
            <label key={label} style={{ display: 'block', marginBottom: '15px' }}>
              <div style={{ marginBottom: '8px', color: '#aaa', fontSize: '12px', textTransform: 'uppercase' }}>{label}</div>
              <input type={type} placeholder={ph} value={val} onChange={e => set(e.target.value)}
                onKeyPress={e => e.key === 'Enter' && createAdmin()}
                style={{ width: '100%', padding: '12px', background: '#0a0e27', border: '1px solid #444', color: '#fff', borderRadius: '4px', boxSizing: 'border-box', fontSize: '14px' }} />
            </label>
          ))}
          {error && <p style={{ color: '#ff5555', marginBottom: '15px', textAlign: 'center' }}>{error}</p>}
          <button onClick={createAdmin} disabled={loading}
            style={{ width: '100%', padding: '12px', background: loading ? '#666' : '#ff5555', border: 'none', color: '#fff', cursor: loading ? 'not-allowed' : 'pointer', borderRadius: '4px', fontWeight: 'bold', fontSize: '16px' }}>
            {loading ? 'Creating Admin...' : '🛡 CREATE ADMIN ACCOUNT'}
          </button>
        </div>
      </div>
    </div>
  );
}

// ─── Nav Button ──────────────────────────────────────────────────────────────

function NavButton({ active, onClick, children }) {
  return (
    <button onClick={onClick} style={{
      padding: '8px 16px',
      background: active ? '#ff5555' : 'transparent',
      border: `1px solid ${active ? '#ff5555' : '#666'}`,
      color: '#fff', cursor: 'pointer', borderRadius: '4px'
    }}>
      {children}
    </button>
  );
}

// ─── Login Page ──────────────────────────────────────────────────────────────

function LoginPage({ setToken, setUser }) {
  const [activeTab, setActiveTab] = useState('login');
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [email, setEmail] = useState('');
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');

  const handleLogin = async () => {
    if (!username.trim() || !password.trim()) { setError('Username and password required'); return; }
    setLoading(true); setError('');
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
    if (!username.trim()) { setError('Username required'); return; }
    setLoading(true); setError('');
    try {
      const res = await fetch(`${API_URL}/auth/register`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ username: username.trim(), email: email.trim() || undefined, password: password || undefined })
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

  const inputStyle = {
    width: '100%', padding: '12px', background: '#0a0e27',
    border: '1px solid #444', color: '#fff', borderRadius: '4px',
    boxSizing: 'border-box', fontSize: '14px'
  };

  const isLogin = activeTab === 'login';

  return (
    <div style={{ minHeight: '100vh', background: 'linear-gradient(135deg, #0a0e27 0%, #1a1f3a 100%)', display: 'flex', alignItems: 'center', justifyContent: 'center', padding: '20px', fontFamily: "'Courier New', monospace", color: '#fff' }}>
      <div style={{ maxWidth: '600px', width: '100%' }}>
        <div style={{ textAlign: 'center', marginBottom: '40px' }}>
          <h1 style={{ fontSize: '48px', color: '#ff5555', margin: '0 0 10px 0' }}>🔍 VULNSCANNER</h1>
          <p style={{ color: '#999', margin: 0 }}>Vulnerability Assessment Platform</p>
        </div>

        <div style={{ display: 'flex', gap: '10px', marginBottom: '30px', background: '#1a1f3a', padding: '10px', borderRadius: '8px' }}>
          {['login', 'register'].map(tab => (
            <button key={tab} onClick={() => { setActiveTab(tab); setError(''); setPassword(''); }}
              style={{ flex: 1, padding: '12px', background: activeTab === tab ? '#ff5555' : 'transparent', border: 'none', color: '#fff', cursor: 'pointer', borderRadius: '4px', fontWeight: 'bold', fontSize: '16px' }}>
              {tab.toUpperCase()}
            </button>
          ))}
        </div>

        <div style={{ background: '#1a1f3a', padding: '30px', borderRadius: '8px', border: '1px solid #333' }}>
          <h2 style={{ margin: '0 0 20px 0', color: '#ff5555' }}>{isLogin ? 'Login to Your Account' : 'Create New Account'}</h2>

          <label style={{ display: 'block', marginBottom: '15px' }}>
            <div style={{ marginBottom: '8px', color: '#aaa', fontSize: '12px', textTransform: 'uppercase' }}>Username</div>
            <input type="text" placeholder={isLogin ? 'Enter your username' : 'Choose a username'}
              value={username} onChange={e => setUsername(e.target.value)}
              onKeyPress={e => e.key === 'Enter' && (isLogin ? handleLogin() : handleRegister())}
              style={inputStyle} />
          </label>

          {!isLogin && (
            <label style={{ display: 'block', marginBottom: '15px' }}>
              <div style={{ marginBottom: '8px', color: '#aaa', fontSize: '12px', textTransform: 'uppercase' }}>Email (Optional)</div>
              <input type="email" placeholder="your@email.com" value={email} onChange={e => setEmail(e.target.value)}
                onKeyPress={e => e.key === 'Enter' && handleRegister()} style={inputStyle} />
            </label>
          )}

          <label style={{ display: 'block', marginBottom: '20px' }}>
            <div style={{ marginBottom: '8px', color: '#aaa', fontSize: '12px', textTransform: 'uppercase' }}>
              {isLogin ? 'Password' : 'Password (Optional)'}
            </div>
            <input type="password" placeholder={isLogin ? 'Enter your password' : 'Leave blank for auto-generated'}
              value={password} onChange={e => setPassword(e.target.value)}
              onKeyPress={e => e.key === 'Enter' && (isLogin ? handleLogin() : handleRegister())}
              style={inputStyle} />
          </label>

          {error && <p style={{ color: '#ff5555', marginBottom: '15px', textAlign: 'center' }}>{error}</p>}

          <button onClick={isLogin ? handleLogin : handleRegister} disabled={loading}
            style={{ width: '100%', padding: '12px', background: loading ? '#666' : '#ff5555', border: 'none', color: '#fff', cursor: loading ? 'not-allowed' : 'pointer', borderRadius: '4px', fontWeight: 'bold', fontSize: '16px' }}>
            {loading ? (isLogin ? 'Logging in...' : 'Creating Account...') : (isLogin ? '🔓 LOGIN' : '✨ CREATE ACCOUNT')}
          </button>

          <p style={{ marginTop: '15px', color: '#999', fontSize: '12px', textAlign: 'center' }}>
            {isLogin ? "Don't have an account? Click the REGISTER tab above" : 'Already have an account? Click the LOGIN tab above'}
          </p>
        </div>
      </div>
    </div>
  );
}

// ─── Scan Page ───────────────────────────────────────────────────────────────

function ScanPage({ token }) {
  const [target, setTarget] = useState('127.0.0.1');
  const [profile, setProfile] = useState('quick');
  const [modules, setModules] = useState({ ports: true, services: true, cve: true, web: true });
  const [runExploits, setRunExploits] = useState(false);
  const [consent, setConsent] = useState(false);
  const [loading, setLoading] = useState(false);
  const [scanId, setScanId] = useState(null);
  const [progress, setProgress] = useState(0);
  const [stage, setStage] = useState('');
  const [error, setError] = useState('');

  const startScan = async () => {
    if (!target.trim()) { setError('Target required'); return; }
    if (!consent) { setError('Must accept consent'); return; }
    setLoading(true); setError('');
    try {
      const res = await fetch(`${API_URL}/scan`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', 'Authorization': `Bearer ${token}` },
        body: JSON.stringify({
          target: target.trim(), profile,
          modules: Object.keys(modules).filter(m => modules[m]),
          run_exploits: runExploits, consent_given: consent
        })
      });
      const data = await res.json();
      if (!res.ok) throw new Error(data.error);
      setScanId(data.scan_id);
      const interval = setInterval(async () => {
        try {
          const r = await fetch(`${API_URL}/scan/${data.scan_id}/status`, { headers: { 'Authorization': `Bearer ${token}` } });
          const d = await r.json();
          setProgress(d.progress);
          setStage(d.stage);
          if (!d.is_active) { clearInterval(interval); setLoading(false); }
        } catch { clearInterval(interval); }
      }, 1000);
    } catch (err) {
      setError(err.message);
      setLoading(false);
    }
  };

  if (scanId) return (
    <div style={{ maxWidth: '800px', margin: '0 auto' }}>
      <h2>Scan in Progress</h2>
      <p>Scan ID: {scanId}</p>
      <div style={{ background: '#1a1f3a', padding: '20px', borderRadius: '8px', marginBottom: '20px' }}>
        <div style={{ marginBottom: '10px' }}>{stage}</div>
        <div style={{ background: '#0a0e27', height: '30px', borderRadius: '4px', overflow: 'hidden', border: '1px solid #444' }}>
          <div style={{ width: `${progress}%`, height: '100%', background: 'linear-gradient(90deg, #ff5555, #ff8888)', transition: 'width 0.3s' }} />
        </div>
        <div style={{ marginTop: '10px', textAlign: 'right', color: '#999' }}>{progress}%</div>
      </div>
      <button onClick={() => { setScanId(null); setProgress(0); setStage(''); }}
        style={{ padding: '10px 20px', background: '#ff5555', border: 'none', color: '#fff', cursor: 'pointer', borderRadius: '4px' }}>
        View Results
      </button>
    </div>
  );

  return (
    <div style={{ maxWidth: '800px', margin: '0 auto' }}>
      <h2 style={{ color: '#ff5555', marginBottom: '30px' }}>New Vulnerability Scan</h2>
      <div style={{ background: '#1a1f3a', padding: '30px', borderRadius: '8px', marginBottom: '20px' }}>

        <label style={{ display: 'block', marginBottom: '15px' }}>
          <div style={{ marginBottom: '8px', color: '#ff5555' }}>TARGET (IP or Domain)</div>
          <input type="text" value={target} onChange={e => setTarget(e.target.value)} placeholder="127.0.0.1"
            style={{ width: '100%', padding: '12px', background: '#0a0e27', border: '1px solid #444', color: '#fff', borderRadius: '4px', boxSizing: 'border-box' }} />
        </label>

        <label style={{ display: 'block', marginBottom: '15px' }}>
          <div style={{ marginBottom: '8px', color: '#ff5555' }}>SCAN PROFILE</div>
          <select value={profile} onChange={e => setProfile(e.target.value)}
            style={{ width: '100%', padding: '12px', background: '#0a0e27', border: '1px solid #444', color: '#fff', borderRadius: '4px' }}>
            <option value="quick">Quick (Fast)</option>
            <option value="full">Full (Comprehensive)</option>
            <option value="stealth">Stealth (Slow)</option>
            <option value="web">Web Only</option>
          </select>
        </label>

        <div style={{ marginBottom: '20px' }}>
          <div style={{ marginBottom: '10px', color: '#ff5555' }}>MODULES</div>
          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(2, 1fr)', gap: '10px' }}>
            {['ports', 'services', 'cve', 'web'].map(mod => (
              <label key={mod} style={{ display: 'flex', alignItems: 'center', gap: '8px', cursor: 'pointer' }}>
                <input type="checkbox" checked={modules[mod]} onChange={() => setModules(prev => ({ ...prev, [mod]: !prev[mod] }))} style={{ cursor: 'pointer' }} />
                <span style={{ textTransform: 'capitalize' }}>{mod}</span>
              </label>
            ))}
          </div>
        </div>

        <label style={{ display: 'flex', alignItems: 'center', gap: '10px', marginBottom: '20px', cursor: 'pointer' }}>
          <input type="checkbox" checked={runExploits} onChange={e => setRunExploits(e.target.checked)} style={{ cursor: 'pointer' }} />
          <span>Run Active Exploits</span>
        </label>

        <label style={{ display: 'flex', alignItems: 'center', gap: '10px', marginBottom: '20px', cursor: 'pointer', background: '#0a0e27', padding: '15px', borderRadius: '4px', border: '1px solid #444' }}>
          <input type="checkbox" checked={consent} onChange={e => setConsent(e.target.checked)} style={{ cursor: 'pointer' }} />
          <span>I have permission to scan this target</span>
        </label>

        {error && <p style={{ color: '#ff5555', marginBottom: '15px' }}>{error}</p>}

        <button onClick={startScan} disabled={loading || !consent}
          style={{ width: '100%', padding: '15px', background: loading || !consent ? '#666' : '#ff5555', border: 'none', color: '#fff', cursor: loading || !consent ? 'not-allowed' : 'pointer', borderRadius: '4px', fontSize: '16px', fontWeight: 'bold' }}>
          {loading ? 'Starting Scan...' : '▶ START SCAN'}
        </button>
      </div>
    </div>
  );
}

// ─── Results Page ────────────────────────────────────────────────────────────

function ResultsPage({ token }) {
  const [scans, setScans] = useState([]);
  const [selectedScan, setSelectedScan] = useState(null);
  const [findings, setFindings] = useState([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => { fetchScans(); }, []);

  const fetchScans = async () => {
    try {
      const res = await fetch(`${API_URL}/scans`, { headers: { 'Authorization': `Bearer ${token}` } });
      const data = await res.json();
      setScans(data.scans || []);
    } catch (err) {
      console.error(err);
    } finally {
      setLoading(false);
    }
  };

  const selectScan = async (scan) => {
    setSelectedScan(scan);
    try {
      const res = await fetch(`${API_URL}/scan/${scan.id}/results`, { headers: { 'Authorization': `Bearer ${token}` } });
      const data = await res.json();
      setFindings(data.findings || []);
    } catch (err) {
      console.error(err);
    }
  };

  if (loading) return <p>Loading scans...</p>;

  if (selectedScan) return (
    <div style={{ maxWidth: '1000px', margin: '0 auto' }}>
      <button onClick={() => setSelectedScan(null)}
        style={{ marginBottom: '20px', padding: '8px 16px', background: '#666', border: 'none', color: '#fff', cursor: 'pointer', borderRadius: '4px' }}>
        ← Back to Scans
      </button>
      <h2 style={{ color: '#ff5555' }}>Scan Results: {selectedScan.target}</h2>
      <div style={{ background: '#1a1f3a', padding: '20px', borderRadius: '8px', marginBottom: '20px' }}>
        <p>Status: {selectedScan.status} | Risk Score: {selectedScan.risk_score}</p>
        <p>Started: {new Date(selectedScan.started_at).toLocaleString()}</p>
      </div>
      <h3>Findings ({findings.length})</h3>
      {findings.length === 0 ? (
        <p style={{ color: '#64748b' }}>No findings for this scan.</p>
      ) : (
        findings.map((f, i) => (
          <div key={i} style={{ background: '#1a1f3a', border: `1px solid ${f.severity === 'critical' ? '#ef4444' : f.severity === 'high' ? '#f97316' : '#334155'}`, borderRadius: '8px', padding: '15px', marginBottom: '10px' }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '8px' }}>
              <strong>{f.title}</strong>
              <span style={{ background: f.severity === 'critical' ? '#ef4444' : f.severity === 'high' ? '#f97316' : '#334155', padding: '2px 8px', borderRadius: '4px', fontSize: '11px', fontWeight: 'bold' }}>
                {f.severity?.toUpperCase()}
              </span>
            </div>
            <p style={{ color: '#94a3b8', fontSize: '13px', margin: 0 }}>{f.description}</p>
          </div>
        ))
      )}
    </div>
  );

  return (
    <div style={{ maxWidth: '1000px', margin: '0 auto' }}>
      <h2 style={{ color: '#ff5555', marginBottom: '30px' }}>Scan Results</h2>
      {scans.length === 0 ? (
        <div style={{ background: '#1a1f3a', padding: '40px', borderRadius: '8px', textAlign: 'center' }}>
          <p style={{ color: '#64748b', fontSize: '16px' }}>No scans yet. Start a new scan!</p>
        </div>
      ) : (
        scans.map((scan, i) => (
          <div key={i} onClick={() => selectScan(scan)}
            style={{ background: '#1a1f3a', border: '1px solid #334155', borderRadius: '8px', padding: '20px', marginBottom: '10px', cursor: 'pointer' }}
            onMouseOver={e => e.currentTarget.style.borderColor = '#ff5555'}
            onMouseOut={e => e.currentTarget.style.borderColor = '#334155'}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
              <div>
                <strong style={{ fontSize: '16px' }}>{scan.target}</strong>
                <p style={{ color: '#94a3b8', fontSize: '12px', margin: '4px 0 0 0' }}>
                  {new Date(scan.started_at).toLocaleString()} | Profile: {scan.profile}
                </p>
              </div>
              <div style={{ textAlign: 'right' }}>
                <span style={{ background: scan.status === 'completed' ? '#166534' : scan.status === 'running' ? '#1e40af' : '#374151', padding: '4px 10px', borderRadius: '4px', fontSize: '12px' }}>
                  {scan.status?.toUpperCase()}
                </span>
                {scan.risk_score != null && (
                  <p style={{ color: scan.risk_score > 70 ? '#ef4444' : scan.risk_score > 40 ? '#f97316' : '#22c55e', fontWeight: 'bold', margin: '4px 0 0 0' }}>
                    Risk: {scan.risk_score}
                  </p>
                )}
              </div>
            </div>
          </div>
        ))
      )}
    </div>
  );
}
