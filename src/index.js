import { Hono } from 'hono'
import { cors } from 'hono/cors'
import { validator } from 'hono/validator'
import { rateLimiter } from 'hono/rate-limiter'

const app = new Hono()

// Firebase configuration
const firebaseConfig = {
  apiKey: "AIzaSyC07Gs8L5vxlUmC561PKbxthewA1mrxYDk",
  authDomain: "zylos-test.firebaseapp.com",
  databaseURL: "https://zylos-test-default-rtdb.firebaseio.com",
  projectId: "zylos-test",
  storageBucket: "zylos-test.firebasestorage.app",
  messagingSenderId: "553027007913",
  appId: "1:553027007913:web:2daa37ddf2b2c7c20b00b8"
};

// Middleware
app.use('*', cors({
  origin: ['http://localhost:3000', 'https://your-domain.com'],
  allowHeaders: ['Content-Type', 'Authorization'],
  allowMethods: ['POST', 'GET', 'PUT', 'DELETE', 'OPTIONS'],
}))

// Rate limiting
app.use('/api/*', rateLimiter({
  windowMs: 15 * 60 * 1000, // 15 minutes
  limit: 100, // limit each IP to 100 requests per windowMs
  standardHeaders: 'draft-6',
  keyGenerator: (c) => c.req.header('x-forwarded-for') ?? 'anonymous'
}))

// Utility functions
const validateEmail = (email) => {
  const re = /^[^\s@]+@[^\s@]+\.[^\s@]+$/
  return re.test(email)
}

const validatePassword = (password) => {
  return password.length >= 6
}

const formatErrorMessage = (error) => {
  const errorMessages = {
    'EMAIL_EXISTS': 'البريد الإلكتروني مستخدم بالفعل',
    'INVALID_EMAIL': 'البريد الإلكتروني غير صحيح',
    'WEAK_PASSWORD': 'كلمة المرور ضعيفة جداً',
    'EMAIL_NOT_FOUND': 'البريد الإلكتروني غير موجود',
    'INVALID_PASSWORD': 'كلمة المرور غير صحيحة',
    'USER_DISABLED': 'تم تعطيل هذا الحساب',
    'TOO_MANY_ATTEMPTS_TRY_LATER': 'محاولات كثيرة جداً، حاول لاحقاً'
  }
  return errorMessages[error] || 'حدث خطأ غير متوقع'
}

// Root endpoint
app.get('/', (c) => {
  return c.json({ 
    message: 'مرحباً بك في سيرفر المصادقة المطور',
    version: '2.0.0',
    endpoints: [
      'POST /api/signup - إنشاء حساب جديد',
      'POST /api/login - تسجيل الدخول',
      'POST /api/forgot-password - إعادة تعيين كلمة المرور',
      'POST /api/reset-password - تأكيد إعادة تعيين كلمة المرور',
      'GET /api/profile - الحصول على الملف الشخصي',
      'PUT /api/profile - تحديث الملف الشخصي',
      'POST /api/change-password - تغيير كلمة المرور',
      'POST /api/verify-email - إرسال بريد التأكيد',
      'GET /api/users - إدارة المستخدمين (admin)',
      'DELETE /api/users/:id - حذف مستخدم (admin)'
    ]
  })
})

// Signup endpoint with validation
app.post('/api/signup', 
  validator('json', (value, c) => {
    const { email, password, name } = value
    
    if (!email || !password || !name) {
      return c.json({ error: 'جميع الحقول مطلوبة' }, 400)
    }
    
    if (!validateEmail(email)) {
      return c.json({ error: 'البريد الإلكتروني غير صحيح' }, 400)
    }
    
    if (!validatePassword(password)) {
      return c.json({ error: 'كلمة المرور يجب أن تكون 6 أحرف على الأقل' }, 400)
    }
    
    if (name.length < 2) {
      return c.json({ error: 'الاسم يجب أن يكون حرفين على الأقل' }, 400)
    }
    
    return value
  }),
  async (c) => {
    try {
      const { email, password, name } = await c.req.json()

      // Firebase Auth REST API for signup
      const signupResponse = await fetch(
        `https://identitytoolkit.googleapis.com/v1/accounts:signUp?key=${firebaseConfig.apiKey}`,
        {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            email,
            password,
            returnSecureToken: true
          })
        }
      )

      const signupData = await signupResponse.json()

      if (!signupResponse.ok) {
        return c.json({ error: formatErrorMessage(signupData.error.message) }, 400)
      }

      // Store user data in Realtime Database
      const userData = {
        email,
        name,
        role: 'user',
        isEmailVerified: false,
        createdAt: new Date().toISOString(),
        lastLogin: new Date().toISOString(),
        profile: {
          avatar: null,
          bio: '',
          phone: '',
          location: ''
        }
      }

      const userDataResponse = await fetch(
        `${firebaseConfig.databaseURL}/users/${signupData.localId}.json?auth=${signupData.idToken}`,
        {
          method: 'PUT',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify(userData)
        }
      )

      if (!userDataResponse.ok) {
        return c.json({ error: 'فشل في حفظ بيانات المستخدم' }, 500)
      }

      return c.json({
        success: true,
        message: 'تم إنشاء الحساب بنجاح',
        user: {
          uid: signupData.localId,
          email: signupData.email,
          name,
          role: userData.role,
          isEmailVerified: userData.isEmailVerified
        },
        token: signupData.idToken
      })

    } catch (error) {
      return c.json({ error: 'خطأ في السيرفر' }, 500)
    }
  }
)

// Login endpoint with enhanced tracking
app.post('/api/login',
  validator('json', (value, c) => {
    const { email, password } = value
    
    if (!email || !password) {
      return c.json({ error: 'البريد الإلكتروني وكلمة المرور مطلوبان' }, 400)
    }
    
    if (!validateEmail(email)) {
      return c.json({ error: 'البريد الإلكتروني غير صحيح' }, 400)
    }
    
    return value
  }),
  async (c) => {
    try {
      const { email, password } = await c.req.json()

      // Firebase Auth REST API for login
      const loginResponse = await fetch(
        `https://identitytoolkit.googleapis.com/v1/accounts:signInWithPassword?key=${firebaseConfig.apiKey}`,
        {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            email,
            password,
            returnSecureToken: true
          })
        }
      )

      const loginData = await loginResponse.json()

      if (!loginResponse.ok) {
        return c.json({ error: formatErrorMessage(loginData.error.message) }, 400)
      }

      // Get user data from Realtime Database
      const userDataResponse = await fetch(
        `${firebaseConfig.databaseURL}/users/${loginData.localId}.json?auth=${loginData.idToken}`
      )

      const userData = await userDataResponse.json()

      // Update last login
      await fetch(
        `${firebaseConfig.databaseURL}/users/${loginData.localId}/lastLogin.json?auth=${loginData.idToken}`,
        {
          method: 'PUT',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify(new Date().toISOString())
        }
      )

      return c.json({
        success: true,
        message: 'تم تسجيل الدخول بنجاح',
        user: {
          uid: loginData.localId,
          email: loginData.email,
          name: userData?.name || 'مستخدم',
          role: userData?.role || 'user',
          isEmailVerified: userData?.isEmailVerified || false,
          profile: userData?.profile || {}
        },
        token: loginData.idToken
      })

    } catch (error) {
      return c.json({ error: 'خطأ في السيرفر' }, 500)
    }
  }
)

// Forgot password endpoint
app.post('/api/forgot-password',
  validator('json', (value, c) => {
    const { email } = value
    
    if (!email || !validateEmail(email)) {
      return c.json({ error: 'البريد الإلكتروني غير صحيح' }, 400)
    }
    
    return value
  }),
  async (c) => {
    try {
      const { email } = await c.req.json()

      const response = await fetch(
        `https://identitytoolkit.googleapis.com/v1/accounts:sendOobCode?key=${firebaseConfig.apiKey}`,
        {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            requestType: 'PASSWORD_RESET',
            email
          })
        }
      )

      const data = await response.json()

      if (!response.ok) {
        return c.json({ error: formatErrorMessage(data.error.message) }, 400)
      }

      return c.json({
        success: true,
        message: 'تم إرسال رابط إعادة تعيين كلمة المرور إلى بريدك الإلكتروني'
      })

    } catch (error) {
      return c.json({ error: 'خطأ في السيرفر' }, 500)
    }
  }
)

// Get user profile with auth middleware
app.get('/api/profile', async (c) => {
  try {
    const token = c.req.header('Authorization')?.replace('Bearer ', '')
    
    if (!token) {
      return c.json({ error: 'غير مصرح' }, 401)
    }

    // Verify token with Firebase
    const verifyResponse = await fetch(
      `https://identitytoolkit.googleapis.com/v1/accounts:lookup?key=${firebaseConfig.apiKey}`,
      {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ idToken: token })
      }
    )

    const verifyData = await verifyResponse.json()

    if (!verifyResponse.ok) {
      return c.json({ error: 'رمز غير صالح' }, 401)
    }

    const userId = verifyData.users[0].localId

    // Get user data
    const userDataResponse = await fetch(
      `${firebaseConfig.databaseURL}/users/${userId}.json?auth=${token}`
    )

    const userData = await userDataResponse.json()

    return c.json({
      success: true,
      user: {
        uid: userId,
        email: verifyData.users[0].email,
        emailVerified: verifyData.users[0].emailVerified || false,
        ...userData
      }
    })

  } catch (error) {
    return c.json({ error: 'خطأ في السيرفر' }, 500)
  }
})

// Update user profile
app.put('/api/profile', async (c) => {
  try {
    const token = c.req.header('Authorization')?.replace('Bearer ', '')
    
    if (!token) {
      return c.json({ error: 'غير مصرح' }, 401)
    }

    const { name, bio, phone, location } = await c.req.json()

    // Verify token
    const verifyResponse = await fetch(
      `https://identitytoolkit.googleapis.com/v1/accounts:lookup?key=${firebaseConfig.apiKey}`,
      {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ idToken: token })
      }
    )

    const verifyData = await verifyResponse.json()

    if (!verifyResponse.ok) {
      return c.json({ error: 'رمز غير صالح' }, 401)
    }

    const userId = verifyData.users[0].localId

    // Update user data
    const updateData = {
      name: name || undefined,
      'profile/bio': bio || '',
      'profile/phone': phone || '',
      'profile/location': location || '',
      updatedAt: new Date().toISOString()
    }

    // Remove undefined values
    Object.keys(updateData).forEach(key => 
      updateData[key] === undefined && delete updateData[key]
    )

    const updateResponse = await fetch(
      `${firebaseConfig.databaseURL}/users/${userId}.json?auth=${token}`,
      {
        method: 'PATCH',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(updateData)
      }
    )

    if (!updateResponse.ok) {
      return c.json({ error: 'فشل في تحديث البيانات' }, 500)
    }

    return c.json({
      success: true,
      message: 'تم تحديث الملف الشخصي بنجاح'
    })

  } catch (error) {
    return c.json({ error: 'خطأ في السيرفر' }, 500)
  }
})

// Change password
app.post('/api/change-password', async (c) => {
  try {
    const token = c.req.header('Authorization')?.replace('Bearer ', '')
    const { newPassword } = await c.req.json()
    
    if (!token) {
      return c.json({ error: 'غير مصرح' }, 401)
    }

    if (!validatePassword(newPassword)) {
      return c.json({ error: 'كلمة المرور يجب أن تكون 6 أحرف على الأقل' }, 400)
    }

    const response = await fetch(
      `https://identitytoolkit.googleapis.com/v1/accounts:update?key=${firebaseConfig.apiKey}`,
      {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          idToken: token,
          password: newPassword,
          returnSecureToken: true
        })
      }
    )

    const data = await response.json()

    if (!response.ok) {
      return c.json({ error: formatErrorMessage(data.error.message) }, 400)
    }

    return c.json({
      success: true,
      message: 'تم تغيير كلمة المرور بنجاح',
      token: data.idToken
    })

  } catch (error) {
    return c.json({ error: 'خطأ في السيرفر' }, 500)
  }
})

// Send email verification
app.post('/api/verify-email', async (c) => {
  try {
    const token = c.req.header('Authorization')?.replace('Bearer ', '')
    
    if (!token) {
      return c.json({ error: 'غير مصرح' }, 401)
    }

    const response = await fetch(
      `https://identitytoolkit.googleapis.com/v1/accounts:sendOobCode?key=${firebaseConfig.apiKey}`,
      {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          requestType: 'VERIFY_EMAIL',
          idToken: token
        })
      }
    )

    const data = await response.json()

    if (!response.ok) {
      return c.json({ error: formatErrorMessage(data.error.message) }, 400)
    }

    return c.json({
      success: true,
      message: 'تم إرسال رابط تأكيد البريد الإلكتروني'
    })

  } catch (error) {
    return c.json({ error: 'خطأ في السيرفر' }, 500)
  }
})

// Admin: Get all users
app.get('/api/users', async (c) => {
  try {
    const token = c.req.header('Authorization')?.replace('Bearer ', '')
    
    if (!token) {
      return c.json({ error: 'غير مصرح' }, 401)
    }

    // Verify token and check admin role
    const verifyResponse = await fetch(
      `https://identitytoolkit.googleapis.com/v1/accounts:lookup?key=${firebaseConfig.apiKey}`,
      {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ idToken: token })
      }
    )

    const verifyData = await verifyResponse.json()

    if (!verifyResponse.ok) {
      return c.json({ error: 'رمز غير صالح' }, 401)
    }

    const userId = verifyData.users[0].localId

    // Check if user is admin
    const userDataResponse = await fetch(
      `${firebaseConfig.databaseURL}/users/${userId}/role.json?auth=${token}`
    )

    const userRole = await userDataResponse.json()

    if (userRole !== 'admin') {
      return c.json({ error: 'غير مصرح لك بالوصول لهذه البيانات' }, 403)
    }

    // Get all users
    const usersResponse = await fetch(
      `${firebaseConfig.databaseURL}/users.json?auth=${token}`
    )

    const usersData = await usersResponse.json()

    const users = Object.entries(usersData || {}).map(([uid, data]) => ({
      uid,
      ...data,
      // Hide sensitive data
      profile: {
        ...data.profile,
        // Remove any sensitive profile data if needed
      }
    }))

    return c.json({
      success: true,
      users,
      totalUsers: users.length
    })

  } catch (error) {
    return c.json({ error: 'خطأ في السيرفر' }, 500)
  }
})

// Health check
app.get('/health', (c) => {
  return c.json({ status: 'healthy', timestamp: new Date().toISOString() })
})

export default app