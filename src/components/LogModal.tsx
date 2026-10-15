import React from 'react';

interface LogModalProps {
  isOpen: boolean;
  title: string;
  content: string;
  onClose: () => void;
}

export const LogModal: React.FC<LogModalProps> = ({ isOpen, title, content, onClose }) => {
  if (!isOpen) return null;

  return (
    <div
      className="modal-overlay"
      onClick={(e) => {
        if (e.target === e.currentTarget) onClose();
      }}
    >
      <div className="modal-content">
        <div className="modal-header">
          <h3 style={{ color: 'var(--cyber-cyan)', fontSize: '1.05rem' }}>{title}</h3>
          <button className="modal-close-btn" onClick={onClose}>
            &times;
          </button>
        </div>
        <div className="modal-body">
          <p style={{ fontSize: '0.8rem', color: 'var(--text-muted)', marginBottom: '0.8rem' }}>
            Complete raw event record extracted from Splunk Enterprise:
          </p>
          <pre
            style={{
              whiteSpace: 'pre-wrap',
              wordBreak: 'break-all',
              color: '#a7f3d0',
              background: 'rgba(0,0,0,0.4)',
              padding: '1rem',
              borderRadius: '6px',
              border: '1px solid var(--border-subtle)',
            }}
          >
            {content}
          </pre>
        </div>
      </div>
    </div>
  );
};
