import React from 'react';
import ReactDOM from 'react-dom/client';
import { ConfigProvider, App as AntApp } from 'antd';
import zhCN from 'antd/locale/zh_CN';
import 'antd/dist/reset.css';
import './monitor.css';
import { createHashRouter, RouterProvider } from 'react-router-dom';
import Shell from './Shell';
import Sessions from './pages/Sessions';
import Live from './pages/Live';
import Recordings from './pages/Recordings';
import Player from './pages/Player';
import Login from './pages/Login';
import Connect from './pages/Connect';
import { tokenSession } from './api';

const router = createHashRouter([
  { path: '/login', element: <Login /> },
  {
    path: '/',
    element: <Shell />,
    children: [
      { index: true, element: <Sessions /> },
      { path: 'connect', element: <Connect /> },
      { path: 'connect/:id', element: <Live /> },
      { path: 'live/:id', element: <Live /> },
      { path: 'recordings', element: <Recordings /> },
      { path: 'recordings/:id', element: <Player /> },
    ],
  },
]);

// Exchange a stored API token for the stream cookie before any page opens a WebSocket.
void tokenSession().finally(() => ReactDOM.createRoot(document.getElementById('root')!).render(
  <React.StrictMode>
    <ConfigProvider locale={zhCN} theme={{ token: { colorPrimary: '#1677ff' } }}>
      <AntApp>
        <RouterProvider router={router} />
      </AntApp>
    </ConfigProvider>
  </React.StrictMode>,
));
