import ParticleCanvas from './components/layout/ParticleCanvas';
import Navbar from './components/layout/Navbar';
import LoginPage from './components/login/LoginPage';

export default function App() {
  return (
    <>
      {/* Animated particle background */}
      <ParticleCanvas />

      {/* Faint grid */}
      <div className="grid-overlay" />

      {/* Edge vignette */}
      <div className="vignette" />

      {/* CRT scanlines */}
      <div className="scanlines" />

      {/* Main UI */}
      <div className="app">
        <Navbar />
        <LoginPage />
      </div>
    </>
  );
}
