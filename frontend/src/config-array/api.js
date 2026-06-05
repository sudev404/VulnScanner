/**
 * API Service with JWT Token Handling
 * 
 * This file handles all API requests and automatically adds JWT tokens
 * to the Authorization header for authenticated requests.
 */

import axios from 'axios'

const API_BASE_URL = 'http://localhost:5000'

// Create axios instance
const api = axios.create({
  baseURL: API_BASE_URL,
  headers: {
    'Content-Type': 'application/json'
  }
})

// ════════════════════════════════════════════════════════════════════════
// REQUEST INTERCEPTOR - Add token to every request
// ════════════════════════════════════════════════════════════════════════

api.interceptors.request.use(
  (config) => {
    const token = localStorage.getItem('token')
    
    if (token) {
      // Add token to Authorization header
      config.headers.Authorization = `Bearer ${token}`
      console.log(`✅ Token added to request: ${config.method.toUpperCase()} ${config.url}`)
      console.log(`   Token: ${token.substring(0, 30)}...`)
    } else {
      console.warn(`⚠️  No token found for request: ${config.method.toUpperCase()} ${config.url}`)
    }
    
    return config
  },
  (error) => {
    console.error('❌ Request interceptor error:', error)
    return Promise.reject(error)
  }
)

// ════════════════════════════════════════════════════════════════════════
// RESPONSE INTERCEPTOR - Handle 401 errors
// ════════════════════════════════════════════════════════════════════════

api.interceptors.response.use(
  (response) => {
    // Success response
    console.log(`✅ Response: ${response.status} ${response.config.url}`)
    return response
  },
  (error) => {
    // Error response
    const status = error.response?.status
    const url = error.config?.url
    const errorMessage = error.response?.data?.error

    console.error(`❌ Error: ${status} ${url}`)
    console.error(`   Message: ${errorMessage}`)

    // Handle 401 Unauthorized - Token invalid/expired
    if (status === 401) {
      console.warn('🔓 Token invalid or expired - logging out')
      localStorage.removeItem('token')
      localStorage.removeItem('user')
      
      // Redirect to login page if on protected page
      if (window.location.pathname !== '/login') {
        console.log('Redirecting to login...')
        window.location.href = '/login'
      }
    }

    // Handle 403 Forbidden - Permission denied
    if (status === 403) {
      console.warn('🔒 Permission denied')
    }

    return Promise.reject(error)
  }
)

// ════════════════════════════════════════════════════════════════════════
// AUTHENTICATION API
// ════════════════════════════════════════════════════════════════════════

export const authAPI = {
  // Register new user
  register: (username, email, password) => {
    console.log('📝 Registering user:', username)
    return api.post('/api/auth/register', {
      username,
      email,
      password
    })
  },

  // Login user
  login: (username, password) => {
    console.log('🔐 Logging in user:', username)
    return api.post('/api/auth/login', {
      username,
      password
    })
  },

  // Get current user
  getMe: () => {
    console.log('👤 Fetching current user')
    return api.get('/api/auth/me')
  },

  // Logout user
  logout: () => {
    console.log('🚪 Logging out')
    localStorage.removeItem('token')
    localStorage.removeItem('user')
    return Promise.resolve()
  }
}

// ════════════════════════════════════════════════════════════════════════
// SCAN API
// ════════════════════════════════════════════════════════════════════════

export const scanAPI = {
  // Create new scan
  createScan: (target, profile, modules) => {
    console.log('🔍 Creating scan for target:', target)
    return api.post('/api/scan', {
      target,
      profile,
      modules
    })
  },

  // Get all scans
  getAllScans: () => {
    console.log('📋 Fetching all scans')
    return api.get('/api/scans')
  },

  // Get scan by ID
  getScan: (scanId) => {
    console.log('📊 Fetching scan:', scanId)
    return api.get(`/api/scan/${scanId}`)
  },

  // Get scan results
  getScanResults: (scanId) => {
    console.log('📈 Fetching scan results:', scanId)
    return api.get(`/api/scan/${scanId}/results`)
  },

  // Delete scan
  deleteScan: (scanId) => {
    console.log('🗑️  Deleting scan:', scanId)
    return api.delete(`/api/scan/${scanId}`)
  }
}

// ════════════════════════════════════════════════════════════════════════
// ADMIN API
// ════════════════════════════════════════════════════════════════════════

export const adminAPI = {
  // Get all users
  getUsers: () => {
    console.log('👥 Fetching all users')
    return api.get('/api/admin/users')
  },

  // Update user
  updateUser: (userId, data) => {
    console.log('✏️  Updating user:', userId)
    return api.patch(`/api/admin/users/${userId}`, data)
  },

  // Delete user
  deleteUser: (userId) => {
    console.log('🗑️  Deleting user:', userId)
    return api.delete(`/api/admin/users/${userId}`)
  },

  // Create user
  createUser: (username, email, password, role) => {
    console.log('➕ Creating user:', username)
    return api.post('/api/admin/users', {
      username,
      email,
      password,
      role
    })
  }
}

// ════════════════════════════════════════════════════════════════════════
// REPORT API
// ════════════════════════════════════════════════════════════════════════

export const reportAPI = {
  // Get dashboard report
  getDashboard: () => {
    console.log('📊 Fetching dashboard')
    return api.get('/api/reports/dashboard')
  },

  // Generate PDF report
  generatePDF: (scanId) => {
    console.log('📄 Generating PDF for scan:', scanId)
    return api.get(`/api/scan/${scanId}/report/pdf`)
  },

  // Generate HTML report
  generateHTML: (scanId) => {
    console.log('🌐 Generating HTML for scan:', scanId)
    return api.get(`/api/scan/${scanId}/report/html`)
  }
}

// ════════════════════════════════════════════════════════════════════════
// SCHEDULED SCAN API
// ════════════════════════════════════════════════════════════════════════

export const scheduledScanAPI = {
  // Create scheduled scan
  create: (scanData) => {
    console.log('⏰ Creating scheduled scan')
    return api.post('/api/scheduled-scans', scanData)
  },

  // Get all scheduled scans
  getAll: () => {
    console.log('📅 Fetching scheduled scans')
    return api.get('/api/scheduled-scans')
  },

  // Update scheduled scan
  update: (scanId, data) => {
    console.log('✏️  Updating scheduled scan:', scanId)
    return api.patch(`/api/scheduled-scans/${scanId}`, data)
  },

  // Delete scheduled scan
  delete: (scanId) => {
    console.log('🗑️  Deleting scheduled scan:', scanId)
    return api.delete(`/api/scheduled-scans/${scanId}`)
  }
}

// ════════════════════════════════════════════════════════════════════════
// UTILITY FUNCTIONS
// ════════════════════════════════════════════════════════════════════════

/**
 * Check if user is authenticated (has valid token)
 */
export const isAuthenticated = () => {
  const token = localStorage.getItem('token')
  console.log('🔐 Authentication check:', token ? 'Authenticated' : 'Not authenticated')
  return !!token
}

/**
 * Get stored user object
 */
export const getStoredUser = () => {
  const user = localStorage.getItem('user')
  return user ? JSON.parse(user) : null
}

/**
 * Set token in localStorage
 */
export const setToken = (token) => {
  localStorage.setItem('token', token)
  console.log('💾 Token saved:', token.substring(0, 30) + '...')
}

/**
 * Clear all auth data
 */
export const clearAuth = () => {
  localStorage.removeItem('token')
  localStorage.removeItem('user')
  console.log('🧹 Auth data cleared')
}

// ════════════════════════════════════════════════════════════════════════
// EXPORT API INSTANCE
// ════════════════════════════════════════════════════════════════════════

export default api
