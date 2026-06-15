import { StrictMode } from 'react'
import { createRoot } from 'react-dom/client'
import PostureDash from './PostureDash.jsx'

const root = createRoot(document.getElementById('root'))
root.render(<StrictMode><PostureDash /></StrictMode>)
