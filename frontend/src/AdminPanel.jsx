import { useState, useEffect } from "react";

const API = "https://vulnscanner-backend-tfm3.onrender.com/api";

export default function AdminPanel({ token, user }) {
  const [adminTab, setAdminTab] = useState("rbac");

  // Helper: get token from prop or localStorage fallback
  const getToken = () => token || localStorage.getItem("token");

  // ════════════════════════════════════════════════════════════════════════════
  // RBAC TAB
  // ════════════════════════════════════════════════════════════════════════════

  const RBACTab = () => {
    const [users, setUsers] = useState([]);
    const [selectedUser, setSelectedUser] = useState(null);
    const [newRole, setNewRole] = useState("");
    const [error, setError] = useState("");
    const [loading, setLoading] = useState(false);

    useEffect(() => {
      fetchUsers();
    }, []);

    const fetchUsers = async () => {
      setLoading(true);
      setError("");
      try {
        const res = await fetch(`${API}/admin/users`, {
          headers: { "Authorization": `Bearer ${getToken()}` }
        });
        if (!res.ok) {
          const data = await res.json().catch(() => ({}));
          setError(data.error || `Failed to fetch users (${res.status})`);
          return;
        }
        const data = await res.json();
        setUsers(data.users || []);
      } catch (e) {
        setError("Failed to fetch users — check backend connection");
      } finally {
        setLoading(false);
      }
    };

    const updateUserRole = async (userId) => {
      if (!newRole) { alert("Please select a role"); return; }
      try {
        const res = await fetch(`${API}/admin/users/${userId}/role`, {
          method: "PATCH",
          headers: {
            "Content-Type": "application/json",
            "Authorization": `Bearer ${getToken()}`
          },
          body: JSON.stringify({ role: newRole })
        });
        const data = await res.json();
        if (res.ok) {
          alert(`✅ User role updated to ${newRole}`);
          fetchUsers();
          setSelectedUser(null);
          setNewRole("");
        } else {
          alert(`❌ Error: ${data.error}`);
        }
      } catch (e) {
        alert("❌ Network error updating role");
      }
    };

    return (
      <div style={{ maxWidth: "900px" }}>
        <h2>👥 Role-Based Access Control</h2>

        {/* Role Legend */}
        <div style={{
          background: "#0f172a",
          border: "1px solid #334155",
          borderRadius: "8px",
          padding: "15px",
          marginBottom: "20px"
        }}>
          <h3>Role Permissions</h3>
          <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: "15px", fontSize: "12px" }}>
            <div>
              <strong style={{ color: "#ef4444" }}>🔴 Admin</strong><br />
              Full access • Manage users • View all scans • Schedule scans
            </div>
            <div>
              <strong style={{ color: "#f97316" }}>🟠 Analyst</strong><br />
              Create scans • Schedule scans • Export reports
            </div>
            <div>
              <strong style={{ color: "#fbbf24" }}>🟡 Auditor</strong><br />
              View-only • Access all scans • Export reports
            </div>
            <div>
              <strong style={{ color: "#64748b" }}>⚪ User</strong><br />
              Create own scans • Export reports
            </div>
          </div>
        </div>

        {/* Error Banner */}
        {error && (
          <div style={{
            background: "#fee2e2",
            border: "1px solid #ef4444",
            color: "#dc2626",
            padding: "12px 16px",
            borderRadius: "6px",
            marginBottom: "16px",
            display: "flex",
            justifyContent: "space-between",
            alignItems: "center"
          }}>
            <span>{error}</span>
            <button
              onClick={fetchUsers}
              style={{
                background: "#ef4444",
                color: "#fff",
                border: "none",
                borderRadius: "4px",
                padding: "4px 10px",
                cursor: "pointer",
                fontSize: "12px"
              }}
            >
              Retry
            </button>
          </div>
        )}

        {/* Users Table */}
        <div style={{
          background: "#1e293b",
          border: "1px solid #334155",
          borderRadius: "8px",
          overflow: "hidden"
        }}>
          <table style={{ width: "100%", borderCollapse: "collapse", fontSize: "13px" }}>
            <thead style={{ background: "#0f172a" }}>
              <tr>
                {["Username", "Email", "Current Role", "Status", "Permissions", "Actions"].map(h => (
                  <th key={h} style={{ padding: "12px", textAlign: "left", borderBottom: "1px solid #334155" }}>{h}</th>
                ))}
              </tr>
            </thead>
            <tbody>
              {loading ? (
                <tr>
                  <td colSpan={6} style={{ padding: "20px", textAlign: "center", color: "#94a3b8" }}>
                    Loading users...
                  </td>
                </tr>
              ) : users.length === 0 && !error ? (
                <tr>
                  <td colSpan={6} style={{ padding: "20px", textAlign: "center", color: "#64748b" }}>
                    No users found
                  </td>
                </tr>
              ) : (
                users.map((u, i) => (
                  <tr key={i} style={{ borderBottom: "1px solid #334155" }}>
                    <td style={{ padding: "12px" }}>{u.username}</td>
                    <td style={{ padding: "12px", fontSize: "11px", color: "#94a3b8" }}>{u.email}</td>
                    <td style={{ padding: "12px" }}>
                      <span style={{
                        background: u.role === "admin" ? "#ef4444" : u.role === "analyst" ? "#f97316" : "#334155",
                        color: "#fff",
                        padding: "4px 8px",
                        borderRadius: "4px",
                        fontSize: "11px",
                        fontWeight: "bold"
                      }}>
                        {u.role?.toUpperCase()}
                      </span>
                    </td>
                    <td style={{ padding: "12px", fontSize: "12px" }}>
                      {u.is_active ? "✅ Active" : "❌ Inactive"}
                    </td>
                    <td style={{ padding: "12px", fontSize: "11px", color: "#94a3b8" }}>
                      {u.role === "admin" ? "Full access" : u.role === "analyst" ? "Scan + Export" : u.role === "auditor" ? "View + Export" : "Own scans"}
                    </td>
                    <td style={{ padding: "12px" }}>
                      <button
                        onClick={() => { setSelectedUser(u.id); setNewRole(u.role); }}
                        style={{
                          padding: "6px 12px",
                          background: "#334155",
                          color: "#f1f5f9",
                          border: "none",
                          borderRadius: "4px",
                          cursor: "pointer",
                          fontSize: "11px"
                        }}
                      >
                        Change Role
                      </button>
                    </td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>

        {/* Change Role Modal */}
        {selectedUser && (
          <div style={{
            position: "fixed", top: 0, left: 0, right: 0, bottom: 0,
            background: "rgba(0,0,0,0.7)",
            display: "flex", alignItems: "center", justifyContent: "center",
            zIndex: 1000
          }}>
            <div style={{
              background: "#1e293b",
              border: "1px solid #334155",
              borderRadius: "8px",
              padding: "30px",
              maxWidth: "400px",
              width: "90%"
            }}>
              <h3>Change User Role</h3>
              <select
                value={newRole}
                onChange={(e) => setNewRole(e.target.value)}
                style={{
                  width: "100%", padding: "10px", marginBottom: "15px",
                  background: "#0f172a", border: "1px solid #334155",
                  color: "#f1f5f9", borderRadius: "4px"
                }}
              >
                <option value="">Select Role</option>
                <option value="admin">Admin</option>
                <option value="analyst">Analyst</option>
                <option value="auditor">Auditor</option>
                <option value="user">User</option>
              </select>
              <div style={{ display: "flex", gap: "10px" }}>
                <button
                  onClick={() => updateUserRole(selectedUser)}
                  style={{
                    flex: 1, padding: "10px", background: "#ef4444",
                    color: "#fff", border: "none", borderRadius: "4px",
                    cursor: "pointer", fontWeight: "bold"
                  }}
                >
                  Update
                </button>
                <button
                  onClick={() => { setSelectedUser(null); setNewRole(""); }}
                  style={{
                    flex: 1, padding: "10px", background: "#334155",
                    color: "#f1f5f9", border: "none", borderRadius: "4px",
                    cursor: "pointer"
                  }}
                >
                  Cancel
                </button>
              </div>
            </div>
          </div>
        )}
      </div>
    );
  };

  // ════════════════════════════════════════════════════════════════════════════
  // SCHEDULING TAB
  // ════════════════════════════════════════════════════════════════════════════

  const SchedulingTab = () => {
    const [scheduleName, setScheduleName] = useState("");
    const [scheduleTarget, setScheduleTarget] = useState("");
    const [scheduleFreq, setScheduleFreq] = useState("weekly");
    const [scheduleProfile, setScheduleProfile] = useState("quick");
    const [scheduledScans, setScheduledScans] = useState([]);
    const [loading, setLoading] = useState(false);
    const [error, setError] = useState("");

    useEffect(() => {
      fetchScheduledScans();
    }, []);

    const fetchScheduledScans = async () => {
      try {
        const res = await fetch(`${API}/scheduled-scans`, {
          headers: { "Authorization": `Bearer ${getToken()}` }
        });
        if (!res.ok) return;
        const data = await res.json();
        setScheduledScans(data.scheduled_scans || []);
      } catch (e) {
        console.error("Error fetching scheduled scans:", e);
      }
    };

    const createScheduledScan = async () => {
      if (!scheduleName || !scheduleTarget) {
        setError("Please fill in all fields");
        return;
      }
      setLoading(true);
      setError("");
      try {
        const res = await fetch(`${API}/scheduled-scans`, {
          method: "POST",
          headers: {
            "Content-Type": "application/json",
            "Authorization": `Bearer ${getToken()}`
          },
          body: JSON.stringify({
            name: scheduleName,
            target: scheduleTarget,
            frequency: scheduleFreq,
            profile: scheduleProfile,
            notify_on_critical: true
          })
        });
        const data = await res.json();
        if (res.ok) {
          setScheduleName("");
          setScheduleTarget("");
          setScheduleFreq("weekly");
          setScheduleProfile("quick");
          fetchScheduledScans();
        } else {
          setError(data.error || "Failed to create schedule");
        }
      } catch (e) {
        setError("Network error creating schedule");
      } finally {
        setLoading(false);
      }
    };

    const deleteScheduledScan = async (scanId, scanName) => {
      if (!window.confirm(`Delete schedule "${scanName}"?`)) return;
      try {
        const res = await fetch(`${API}/scheduled-scans/${scanId}`, {
          method: "DELETE",
          headers: { "Authorization": `Bearer ${getToken()}` }
        });
        if (res.ok) {
          fetchScheduledScans();
        } else {
          alert("Failed to delete schedule");
        }
      } catch (e) {
        alert("Network error deleting schedule");
      }
    };

    const toggleSchedule = async (scanId, currentState) => {
      try {
        const res = await fetch(`${API}/scheduled-scans/${scanId}`, {
          method: "PATCH",
          headers: {
            "Content-Type": "application/json",
            "Authorization": `Bearer ${getToken()}`
          },
          body: JSON.stringify({ is_active: !currentState })
        });
        if (res.ok) fetchScheduledScans();
      } catch (e) {
        console.error("Toggle error:", e);
      }
    };

    return (
      <div style={{ maxWidth: "900px" }}>
        <h2>⏰ Scan Scheduling</h2>

        {/* Create Form */}
        <div style={{
          background: "#1e293b", border: "1px solid #334155",
          borderRadius: "8px", padding: "20px", marginBottom: "20px"
        }}>
          <h3>Create Scheduled Scan</h3>

          {error && (
            <div style={{
              background: "#fee2e2", border: "1px solid #ef4444",
              color: "#dc2626", padding: "10px", borderRadius: "4px", marginBottom: "15px"
            }}>{error}</div>
          )}

          {[
            { label: "Scan Name", value: scheduleName, setter: setScheduleName, placeholder: "e.g., Weekly Server Scan" },
            { label: "Target IP/Domain", value: scheduleTarget, setter: setScheduleTarget, placeholder: "e.g., 192.168.1.1 or scanme.nmap.org" }
          ].map(({ label, value, setter, placeholder }) => (
            <div key={label} style={{ marginBottom: "15px" }}>
              <label style={{ display: "block", fontSize: "12px", color: "#94a3b8", marginBottom: "5px" }}>{label}</label>
              <input
                value={value}
                onChange={(e) => setter(e.target.value)}
                placeholder={placeholder}
                style={{
                  width: "100%", padding: "10px", background: "#0f172a",
                  border: "1px solid #334155", color: "#f1f5f9",
                  borderRadius: "4px", boxSizing: "border-box"
                }}
              />
            </div>
          ))}

          <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: "15px", marginBottom: "15px" }}>
            <div>
              <label style={{ display: "block", fontSize: "12px", color: "#94a3b8", marginBottom: "5px" }}>Frequency</label>
              <select
                value={scheduleFreq}
                onChange={(e) => setScheduleFreq(e.target.value)}
                style={{
                  width: "100%", padding: "10px", background: "#0f172a",
                  border: "1px solid #334155", color: "#f1f5f9", borderRadius: "4px"
                }}
              >
                <option value="daily">Daily</option>
                <option value="weekly">Weekly</option>
                <option value="monthly">Monthly</option>
              </select>
            </div>
            <div>
              <label style={{ display: "block", fontSize: "12px", color: "#94a3b8", marginBottom: "5px" }}>Scan Profile</label>
              <select
                value={scheduleProfile}
                onChange={(e) => setScheduleProfile(e.target.value)}
                style={{
                  width: "100%", padding: "10px", background: "#0f172a",
                  border: "1px solid #334155", color: "#f1f5f9", borderRadius: "4px"
                }}
              >
                <option value="quick">Quick</option>
                <option value="full">Full</option>
                <option value="web">Web Only</option>
                <option value="vuln">Vuln (CVE + SQLi + XSS)</option>
                <option value="stealth">Stealth</option>
              </select>
            </div>
          </div>

          <button
            onClick={createScheduledScan}
            disabled={loading}
            style={{
              width: "100%", padding: "12px",
              background: loading ? "#666" : "#ef4444",
              color: "#fff", border: "none", borderRadius: "4px",
              cursor: loading ? "not-allowed" : "pointer", fontWeight: "bold"
            }}
          >
            {loading ? "Creating..." : "✅ Schedule Scan"}
          </button>
        </div>

        {/* Active Schedules */}
        <h3>Active Schedules ({scheduledScans.length})</h3>
        {scheduledScans.length === 0 ? (
          <p style={{ color: "#64748b" }}>No scheduled scans yet — create one above</p>
        ) : (
          scheduledScans.map((scan, i) => (
            <div key={i} style={{
              background: "#0f172a", border: `1px solid ${scan.is_active ? "#22c55e" : "#334155"}`,
              borderRadius: "8px", padding: "15px", marginBottom: "10px"
            }}>
              <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center" }}>
                <div>
                  <strong style={{ fontSize: "15px" }}>{scan.name}</strong>
                  <span style={{
                    marginLeft: "10px", fontSize: "11px", padding: "2px 8px",
                    borderRadius: "10px", fontWeight: "bold",
                    background: scan.is_active ? "#166534" : "#1e293b",
                    color: scan.is_active ? "#22c55e" : "#64748b"
                  }}>
                    {scan.is_active ? "● ACTIVE" : "○ PAUSED"}
                  </span><br />
                  <span style={{ fontSize: "12px", color: "#94a3b8" }}>
                    🎯 {scan.target} &nbsp;|&nbsp; 🔁 {scan.frequency?.toUpperCase()} &nbsp;|&nbsp; 🛠 {scan.profile?.toUpperCase() || "QUICK"}
                  </span><br />
                  <span style={{ fontSize: "11px", color: "#fbbf24" }}>
                    ⏱ Next run: {scan.next_run ? new Date(scan.next_run).toLocaleString() : "N/A"}
                  </span>
                  {scan.last_run && (
                    <span style={{ fontSize: "11px", color: "#64748b", marginLeft: "15px" }}>
                      Last run: {new Date(scan.last_run).toLocaleString()}
                    </span>
                  )}
                </div>
                <div style={{ display: "flex", gap: "8px" }}>
                  <button
                    onClick={() => toggleSchedule(scan.id, scan.is_active)}
                    style={{
                      padding: "6px 12px",
                      background: scan.is_active ? "#334155" : "#166534",
                      color: "#fff", border: "none", borderRadius: "4px", cursor: "pointer",
                      fontSize: "12px"
                    }}
                  >
                    {scan.is_active ? "⏸ Pause" : "▶ Resume"}
                  </button>
                  <button
                    onClick={() => deleteScheduledScan(scan.id, scan.name)}
                    style={{
                      padding: "6px 12px", background: "#ef4444",
                      color: "#fff", border: "none", borderRadius: "4px",
                      cursor: "pointer", fontSize: "12px"
                    }}
                  >
                    🗑 Delete
                  </button>
                </div>
              </div>
            </div>
          ))
        )}
      </div>
    );
  };

  // ════════════════════════════════════════════════════════════════════════════
  // REPORTING TAB
  // ════════════════════════════════════════════════════════════════════════════

  const ReportingTab = () => {
    const [reportStats, setReportStats] = useState(null);
    const [error, setError] = useState("");

    useEffect(() => {
      fetchReportStats();
    }, []);

    const fetchReportStats = async () => {
      setError("");
      try {
        const res = await fetch(`${API}/reports/dashboard`, {
          headers: { "Authorization": `Bearer ${getToken()}` }
        });
        if (!res.ok) {
          const data = await res.json().catch(() => ({}));
          setError(data.error || `Failed to load report data (${res.status})`);
          return;
        }
        const data = await res.json();
        setReportStats(data);
      } catch (e) {
        setError("Failed to load report data — check backend connection");
      }
    };

    if (error) {
      return (
        <div style={{ maxWidth: "900px" }}>
          <h2>📊 Vulnerability Reports & Analytics</h2>
          <div style={{
            background: "#fee2e2", border: "1px solid #ef4444",
            color: "#dc2626", padding: "12px 16px", borderRadius: "6px"
          }}>
            {error}
          </div>
        </div>
      );
    }

    if (!reportStats) {
      return (
        <div style={{ maxWidth: "900px" }}>
          <h2>📊 Vulnerability Reports & Analytics</h2>
          <p style={{ color: "#94a3b8" }}>Loading...</p>
        </div>
      );
    }

    return (
      <div style={{ maxWidth: "900px" }}>
        <h2>📊 Vulnerability Reports & Analytics</h2>

        <div style={{
          display: "grid", gridTemplateColumns: "1fr 1fr 1fr 1fr",
          gap: "15px", marginBottom: "20px"
        }}>
          {[
            { label: "Critical Issues", value: reportStats.critical_count, color: "#ef4444" },
            { label: "High Severity", value: reportStats.high_count, color: "#f97316" },
            { label: "Medium Issues", value: reportStats.medium_count, color: "#fbbf24" },
            { label: "Total Scans", value: reportStats.total_scans, color: "#388e3c" },
          ].map(({ label, value, color }) => (
            <div key={label} style={{
              background: "#1e293b", border: `1px solid ${color}`,
              borderRadius: "8px", padding: "20px", textAlign: "center"
            }}>
              <div style={{ fontSize: "24px", fontWeight: "bold", color }}>{value}</div>
              <div style={{ fontSize: "12px", color: "#94a3b8", marginTop: "5px" }}>{label}</div>
            </div>
          ))}
        </div>

        <div style={{
          background: "#1e293b", border: "1px solid #334155",
          borderRadius: "8px", padding: "20px"
        }}>
          <h3>Overall Statistics</h3>
          <table style={{ width: "100%", fontSize: "13px" }}>
            <tbody>
              {[
                { label: "Average Risk Score", value: `${reportStats.avg_risk_score?.toFixed(1)}/100`, color: "#ef4444" },
                { label: "Total Findings", value: reportStats.total_findings },
                { label: "Most Common Service", value: reportStats.most_common_service || "N/A" },
              ].map(({ label, value, color }) => (
                <tr key={label} style={{ borderBottom: "1px solid #334155" }}>
                  <td style={{ padding: "10px" }}><strong>{label}</strong></td>
                  <td style={{ padding: "10px", textAlign: "right", color: color || "#f1f5f9", fontWeight: color ? "bold" : "normal" }}>
                    {value}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>

        <div style={{ marginTop: "20px", display: "flex", gap: "10px" }}>
          <button
            onClick={() => alert("📄 PDF report generation in progress...")}
            style={{
              flex: 1, padding: "12px", background: "#ef4444",
              color: "#fff", border: "none", borderRadius: "4px",
              cursor: "pointer", fontWeight: "bold"
            }}
          >
            📄 Export as PDF
          </button>
          <button
            onClick={() => alert("📊 CSV export in progress...")}
            style={{
              flex: 1, padding: "12px", background: "#334155",
              color: "#f1f5f9", border: "none", borderRadius: "4px",
              cursor: "pointer", fontWeight: "bold"
            }}
          >
            📊 Export as CSV
          </button>
        </div>
      </div>
    );
  };

  // ════════════════════════════════════════════════════════════════════════════
  // MAIN ADMIN PANEL
  // ════════════════════════════════════════════════════════════════════════════

  return (
    <div style={{ maxWidth: "1200px", margin: "0 auto" }}>
      <div style={{
        display: "flex", gap: "10px", marginBottom: "20px",
        borderBottom: "1px solid #334155", paddingBottom: "15px"
      }}>
        {[
          { id: "rbac", label: "👥 RBAC" },
          { id: "scheduling", label: "⏰ Scheduling" },
          { id: "reporting", label: "📊 Reports" },
        ].map(({ id, label }) => (
          <button
            key={id}
            onClick={() => setAdminTab(id)}
            style={{
              padding: "10px 20px",
              background: adminTab === id ? "#ef4444" : "#1e293b",
              color: "#f1f5f9",
              border: "1px solid #334155",
              borderRadius: "6px",
              cursor: "pointer",
              fontWeight: "bold"
            }}
          >
            {label}
          </button>
        ))}
      </div>

      {adminTab === "rbac" && <RBACTab />}
      {adminTab === "scheduling" && <SchedulingTab />}
      {adminTab === "reporting" && <ReportingTab />}
    </div>
  );
}
