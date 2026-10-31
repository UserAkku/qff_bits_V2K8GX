import { StrictMode } from 'react'
import { createRoot } from 'react-dom/client'
import { createBrowserRouter, Navigate, RouterProvider } from 'react-router'
import { Shell } from '@/app/Shell'
import { Chat } from '@/pages/chat/Chat'
import { Experiments } from '@/pages/experiments/Experiments'
import { KeyLab } from '@/pages/lab/KeyLab'
import { SecurityModel } from '@/pages/security/SecurityModel'
import './styles.css'

const router = createBrowserRouter([
  {
    path: '/',
    element: <Shell />,
    children: [
      { index: true, element: <Navigate to="/chat" replace /> },
      { path: 'chat', element: <Chat /> },
      { path: 'lab', element: <KeyLab /> },
      { path: 'experiments', element: <Experiments /> },
      { path: 'security', element: <SecurityModel /> },
    ],
  },
])

createRoot(document.getElementById('root')!).render(
  <StrictMode>
    <RouterProvider router={router} />
  </StrictMode>,
)
