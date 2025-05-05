
```
import { useSelector, useDispatch } from 'react-redux'
import { logout } from '../store/authSlice'

const Home = () => {
    const { user, token } = useSelector(state => state.auth)
    const dispatch = useDispatch()

    return (
        <div>
            <h1>Home Page</h1>
            {token ? (
                <div>
                    <p>Welcome, {user?.name}</p>
                    <p>Email: {user?.email}</p>
                    <p>DOB: {user?.date_of_birth}</p>
                    <button onClick={() => dispatch(logout())}>Logout</button>
                </div>
            ) : (
                <p>Please login</p>
            )}
        </div>
    )
}

export default Home



import { useState } from 'react'
import axios from 'axios'
import { useNavigate } from 'react-router-dom'
import { useDispatch } from 'react-redux'
import { loginSuccess } from '../store/authSlice' // adjust path as needed
import axiosInstance from '../api/axios'

const Login = () => {
  const navigate = useNavigate()
  const dispatch = useDispatch()

  const [formData, setFormData] = useState({
    email: '',
    password: ''
  })

  const [errors, setErrors] = useState({})
  const [serverError, setServerError] = useState('')
  const [loading, setLoading] = useState(false)

  const handleChange = (e) => {
    setFormData({ ...formData, [e.target.name]: e.target.value })
    setErrors({ ...errors, [e.target.name]: '' })
    setServerError('')
  }

  const handleSubmit = async (e) => {
    e.preventDefault()
    setLoading(true)
    setErrors({})
    setServerError('')

    try {
      const response = await axiosInstance.post('/signin', formData)

      const { token, user } = response.data
      localStorage.setItem('token', token)

      dispatch(loginSuccess({ user, token }))
      navigate('/')
    } catch (error) {
      if (error.response?.status === 422) {
        setErrors(error.response.data.errors || {})
      } else if (error.response?.status === 401) {
        setServerError('Invalid email or password')
      } else {
        setServerError('Something went wrong. Try again.')
      }
    } finally {
      setLoading(false)
    }
  }

  return (
    <div style={{ maxWidth: '400px', margin: '0 auto' }}>
      <h2>Login</h2>
      <form onSubmit={handleSubmit}>
        <div>
          <label>Email:</label><br />
          <input
            type="email"
            name="email"
            value={formData.email}
            onChange={handleChange}
          />
          {errors.email && <p style={{ color: 'red' }}>{errors.email[0]}</p>}
        </div>

        <div>
          <label>Password:</label><br />
          <input
            type="password"
            name="password"
            value={formData.password}
            onChange={handleChange}
          />
          {errors.password && <p style={{ color: 'red' }}>{errors.password[0]}</p>}
        </div>

        <button type="submit" disabled={loading}>
          {loading ? 'Logging in...' : 'Login'}
        </button>

        {serverError && <p style={{ color: 'red' }}>{serverError}</p>}
      </form>
    </div>
  )
}

export default Login

import { useState, useEffect } from 'react'
import { useSelector, useDispatch } from 'react-redux'
import { useNavigate } from 'react-router-dom'
import axiosInstance from '../api/axios'
import { loginSuccess } from '../store/authSlice'

const Profile = () => {
  const { user, token } = useSelector(state => state.auth)
  const dispatch = useDispatch()
  const navigate = useNavigate()

  const [formData, setFormData] = useState({
    name: '',
    date_of_birth: ''
  })

  const [errors, setErrors] = useState({})
  const [serverError, setServerError] = useState('')
  const [loading, setLoading] = useState(false)

  useEffect(() => {
    if (user) {
      setFormData({
        name: user.name || '',
        date_of_birth: user.date_of_birth || ''
      })
    }
  }, [user])

  const handleChange = (e) => {
    setFormData({ ...formData, [e.target.name]: e.target.value })
    setErrors({ ...errors, [e.target.name]: '' })
  }

  const handleSubmit = async (e) => {
    e.preventDefault()
    setErrors({})
    setServerError('')
    setLoading(true)

    try {
      const response = await axiosInstance.put('/profile', formData, {
        headers: {
          Authorization: `Bearer ${token}`
        }
      })

      dispatch(loginSuccess({ user: response.data.user, token }))
      navigate('/')
    } catch (error) {
      if (error.response?.status === 422) {
        setErrors(error.response.data.errors || {})
      } else {
        setServerError('Failed to update profile. Try again.')
      }
    } finally {
      setLoading(false)
    }
  }

  return (
    <div style={{ maxWidth: '400px', margin: '0 auto' }}>
      <h2>Update Profile</h2>
      <form onSubmit={handleSubmit}>
        <div>
          <label>Name:</label><br />
          <input
            type="text"
            name="name"
            value={formData.name}
            onChange={handleChange}
          />
          {errors.name && <p style={{ color: 'red' }}>{errors.name[0]}</p>}
        </div>

        <div>
          <label>Date of Birth:</label><br />
          <input
            type="date"
            name="date_of_birth"
            value={formData.date_of_birth}
            onChange={handleChange}
          />
          {errors.date_of_birth && <p style={{ color: 'red' }}>{errors.date_of_birth[0]}</p>}
        </div>

        <button type="submit" disabled={loading}>
          {loading ? 'Updating...' : 'Update'}
        </button>

        {serverError && <p style={{ color: 'red' }}>{serverError}</p>}
      </form>
    </div>
  )
}

export default Profile


import { useState } from 'react'
import { useNavigate } from 'react-router-dom'
import { useDispatch } from 'react-redux'
import axiosInstance from '../api/axios'
import { loginSuccess } from '../store/authSlice' 

const Register = () => {
  const navigate = useNavigate()
  const dispatch = useDispatch()

  const [formData, setFormData] = useState({
    name: '',
    email: '',
    password: ''
  })

  const [errors, setErrors] = useState({})
  const [serverError, setServerError] = useState('')
  const [loading, setLoading] = useState(false)

  const handleChange = (e) => {
    setFormData({ ...formData, [e.target.name]: e.target.value })
    setErrors({ ...errors, [e.target.name]: '' })
    setServerError('')
  }

  const handleSubmit = async (e) => {
    e.preventDefault()
    setErrors({})
    setServerError('')
    setLoading(true)

    try {
      const response = await axiosInstance.post('/register', formData)

      const { token, user } = response.data

      localStorage.setItem('token', token)

      dispatch(loginSuccess({ user, token }))

      navigate('/')
    } catch (error) {
      if (error.response?.status === 422) {
        setErrors(error.response.data.errors || {})
      } else {
        setServerError('Something went wrong. Try again.')
      }
    } finally {
      setLoading(false)
    }
  }

  return (
    <div style={{ maxWidth: '400px', margin: '0 auto' }}>
      <h2>Register</h2>
      <form onSubmit={handleSubmit}>
        <div>
          <label>Name:</label><br />
          <input
            type="text"
            name="name"
            value={formData.name}
            onChange={handleChange}
          />
          {errors.name && <p style={{ color: 'red' }}>{errors.name[0]}</p>}
        </div>

        <div>
          <label>Email:</label><br />
          <input
            type="email"
            name="email"
            value={formData.email}
            onChange={handleChange}
          />
          {errors.email && <p style={{ color: 'red' }}>{errors.email[0]}</p>}
        </div>

        <div>
          <label>Password:</label><br />
          <input
            type="password"
            name="password"
            value={formData.password}
            onChange={handleChange}
          />
          {errors.password && <p style={{ color: 'red' }}>{errors.password[0]}</p>}
        </div>

        <button type="submit" disabled={loading}>
          {loading ? 'Registering...' : 'Register'}
        </button>

        {serverError && <p style={{ color: 'red' }}>{serverError}</p>}
      </form>
    </div>
  )
}

export default Register

import axios from 'axios'

const axiosInstance = axios.create({
  baseURL: 'http://127.0.0.1:8000/api',
  headers: {
    'Content-Type': 'application/json'
  }
})

export default axiosInstance


import React from 'react'
import { Link, useNavigate } from 'react-router-dom'
import { useDispatch, useSelector } from 'react-redux'
import { logout } from '../store/authSlice'

const withLayout = (Component) => {
  return function WrappedComponent(props) {
    const user = useSelector((state) => state.auth.user)
    const dispatch = useDispatch()
    const navigate = useNavigate()

    const handleLogout = () => {
      dispatch(logout())
      navigate('/login')
    }

    return (
      <>
        <nav style={{ padding: 10, borderBottom: '1px solid #ccc' }}>
          <Link to="/" style={{ marginRight: 10 }}>Home</Link>
          {user && (
            <Link to="/profile" style={{ marginRight: 10 }}>Profile</Link>
          )}
          {!user ? (
            <>
              <Link to="/login" style={{ marginRight: 10 }}>Login</Link>
              <Link to="/register" style={{ marginRight: 10 }}>Register</Link>
            </>
          ) : (
            <button
              onClick={handleLogout}
              style={{ marginRight: 10, cursor: 'pointer', border: 'none', padding: '5px 10px' }}
            >
              Logout
            </button>
          )}
        </nav>
        <div style={{ padding: 20 }}>
          <Component {...props} />
        </div>
      </>
    )
  }
}

export default withLayout

import { createSlice } from '@reduxjs/toolkit'

const initialState = {
    user: null,
    token: localStorage.getItem('token') || null,
}
const authSlice = createSlice({
    name: 'auth',
    initialState,
    reducers: {
        loginSuccess: (state, action) => {
            state.user = action.payload.user
            state.token = action.payload.token
        },
        logout: (state) => {
            state.user = null
            state.token = null
            localStorage.removeItem('token')
        },
        setUser: (state, action) => {
            state.user = action.payload
        }
    }
})

export const { loginSuccess, logout, setUser } = authSlice.actions
export default authSlice.reducer

import { configureStore } from '@reduxjs/toolkit'
import authReducer from './authSlice'

export const store = configureStore({
  reducer: {
    auth: authReducer,
  },
})



import React, { useEffect } from 'react'
import { Routes, Route } from 'react-router-dom'
import { useDispatch } from 'react-redux'
import withLayout from './components/withLayout'
import Home from './pages/home'
import Login from './pages/login'
import Profile from './pages/profile'
import Register from './pages/register'
import { loginSuccess, logout } from './store/authSlice'
import axiosInstance from './api/axios'

const App = () => {
  const dispatch = useDispatch()

  useEffect(() => {
    const token = localStorage.getItem('token')

    if (token) {
      axiosInstance.defaults.headers.common['Authorization'] = `Bearer ${token}`

      axiosInstance
        .get('/me')
        .then((response) => {
          console.log("🚀 ~ .then ~ response:", response)
          dispatch(loginSuccess({ user: response.data.user, token }))
        })
        .catch(() => {
          dispatch(logout())
          localStorage.removeItem('token')
        })
    }
  }, [dispatch])

  const LayoutHome = withLayout(Home)
  const LayoutProfile = withLayout(Profile)
  const LayoutLogin = withLayout(Login)
  const LayoutRegister = withLayout(Register)

  return (
    <Routes>
      <Route path="/" element={<LayoutHome />} />
      <Route path="/profile" element={<LayoutProfile />} />
      <Route path="/login" element={<LayoutLogin />} />
      <Route path="/register" element={<LayoutRegister />} />
    </Routes>
  )
}

export default App
```


<?php

namespace App\Http\Controllers;

use App\Models\User;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Facades\Validator;
use Illuminate\Support\Facades\Auth;

class AuthController extends Controller
{
    public function register(Request $request)
    {
        $validator = Validator::make($request->all(), [
            'name'     => 'required|string|max:255',
            'email'    => 'required|string|email|unique:users,email',
            'password' => [
                'required',
                'string',
                'min:8',
                'regex:/[a-z]/',
                'regex:/[A-Z]/',
                'regex:/[0-9]/',
                'regex:/[@$!%*?&]/',
            ],
        ]);

        if ($validator->fails()) {
            return response()->json(['errors' => $validator->errors()], 422);
        }

        $user = User::create([
            'name'     => $request->name,
            'email'    => $request->email,
            'password' => Hash::make($request->password),
        ]);

        $token = $user->createToken('auth_token')->plainTextToken;

        return response()->json(['user' => $user, 'token' => $token], 201);
    }

    public function login(Request $request)
    {
        $validator = Validator::make($request->all(), [
            'email'    => 'required|email',
            'password' => 'required|string',
        ]);

        if ($validator->fails()) {
            return response()->json(['errors' => $validator->errors()], 422);
        }

        if (!Auth::attempt($request->only('email', 'password'))) {
            return response()->json(['message' => 'Invalid credentials'], 401);
        }

        $user = Auth::user();
        $token = $user->createToken('auth_token')->plainTextToken;

        return response()->json(['user' => $user, 'token' => $token], 200);
    }

    public function me(Request $request)
    {
        return response()->json(['user' => $request->user()], 200);
    }
    public function logout(Request $request)
    {
        $request->user()->tokens()->delete();

        return response()->json(['message' => 'Logged out successfully'], 200);
    }

    public function updateProfile(Request $request)
    {
        $validator = Validator::make($request->all(), [
            'date_of_birth' => 'required|date|before:today',
        ]);

        if ($validator->fails()) {
            return response()->json(['errors' => $validator->errors()], 422);
        }

        $user = $request->user();
        $user->date_of_birth = $request->date_of_birth;
        $user->save();

        return response()->json(['message' => 'Profile updated', 'user' => $user], 200);
    }
}

Route::post('/register', [AuthController::class, 'register']);
Route::post('/signin', [AuthController::class, 'login']);

Route::middleware('auth:sanctum')->group(function () {
    Route::post('/logout', [AuthController::class, 'logout']);
    Route::put('/profile', [AuthController::class, 'updateProfile']);
    Route::get('/me', [AuthController::class, 'me']);
});
