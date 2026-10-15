import React, { useState } from 'react';
import { SystemConfig } from './types';
import { TelemetryService } from './services/telemetryService';
import { Navbar } from './components/Navbar';
import { Banner } from './components/Banner';
import { Dashboard } from './components/Dashboard';
import { Settings } from './components/Settings';
import { HealthModal } from './components/HealthModal';
import { Footer } from './components/Footer';

export const App: React.FC = () => {
  const [currentTab, setCurrentTab] = useState<'dashboard' | 'settings'>('dashboard');
  const [config, setConfig] = useState<SystemConfig>(() => TelemetryService.getConfig());
  const [isHealthOpen, setIsHealthOpen] = useState<boolean>(false);
  const [isUploadOpen, setIsUploadOpen] = useState<boolean>(false);

  const handleUpdateConfig = (newConfig: SystemConfig) => {
    setConfig(newConfig);
  };

  return (
    <>
      <Navbar
        currentTab={currentTab}
        setCurrentTab={setCurrentTab}
        onOpenHealth={() => setIsHealthOpen(true)}
        onOpenUpload={() => {
          setCurrentTab('dashboard');
          setIsUploadOpen(true);
        }}
      />

      <Banner />

      <main className="container">
        {currentTab === 'dashboard' ? (
          <Dashboard
            config={config}
            onUpdateConfig={handleUpdateConfig}
            isExternalUploadOpen={isUploadOpen}
            onCloseExternalUpload={() => setIsUploadOpen(false)}
          />
        ) : (
          <Settings
            config={config}
            onUpdateConfig={handleUpdateConfig}
            onBackToDashboard={() => setCurrentTab('dashboard')}
          />
        )}
      </main>

      <Footer />

      <HealthModal
        isOpen={isHealthOpen}
        onClose={() => setIsHealthOpen(false)}
        config={config}
      />
    </>
  );
};

export default App;
