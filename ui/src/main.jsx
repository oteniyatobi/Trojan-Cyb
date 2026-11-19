import { StrictMode } from 'react'
import { createRoot } from 'react-dom/client'
import './styles/main.css'
import App from './App.jsx'
import AdminApp from './admin/AdminApp.jsx'
import { isAdminSite } from './lib/site.js'

createRoot(document.getElementById('root')).render(
  <StrictMode>
    {isAdminSite() ? <AdminApp /> : <App />}
  </StrictMode>,
)
