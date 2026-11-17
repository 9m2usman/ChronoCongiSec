import { Component, ErrorInfo, ReactNode } from 'react';
import { AlertTriangle, RefreshCw } from 'lucide-react';

interface Props {
  children: ReactNode;
  fallbackTitle?: string;
  is3dView?: boolean;
}

interface State {
  hasError: boolean;
  error: Error | null;
  webGlSupported: boolean;
}

export function isWebGLAvailable(): boolean {
  try {
    const canvas = document.createElement('canvas');
    return !!(
      window.WebGLRenderingContext &&
      (canvas.getContext('webgl') || canvas.getContext('experimental-webgl'))
    );
  } catch {
    return false;
  }
}

export class ForensicErrorBoundary extends Component<Props, State> {
  public state: State = {
    hasError: false,
    error: null,
    webGlSupported: true,
  };

  public static getDerivedStateFromError(error: Error): State {
    return {
      hasError: true,
      error,
      webGlSupported: isWebGLAvailable(),
    };
  }

  public componentDidCatch(error: Error, errorInfo: ErrorInfo) {
    console.error('ForensicErrorBoundary caught rendering error:', error, errorInfo);
  }

  private handleReset = () => {
    this.setState({ hasError: false, error: null });
  };

  public render() {
    if (this.state.hasError) {
      const isWebGLError = this.props.is3dView && (!this.state.webGlSupported || this.state.error?.message.toLowerCase().includes('webgl'));

      return (
        <div className="flex flex-col items-center justify-center p-8 bg-slate-900/80 border border-amber-500/30 rounded-lg text-slate-200">
          <div className="p-3 bg-amber-500/10 rounded-full border border-amber-500/30 text-amber-400 mb-3">
            <AlertTriangle className="w-8 h-8" />
          </div>
          <h3 className="text-base font-semibold text-slate-100 mb-1">
            {this.props.fallbackTitle || (isWebGLError ? '3D WebGL Acceleration Unavailable' : 'Forensic Component Fault')}
          </h3>
          <p className="text-xs text-slate-400 max-w-md text-center mb-4 font-mono">
            {isWebGLError
              ? 'Your browser or GPU context does not support hardware-accelerated WebGL3D rendering. Automatic fallback to 2D DAG topological view is recommended.'
              : this.state.error?.message || 'An unexpected rendering error occurred inside this visualization.'}
          </p>
          <div className="flex items-center gap-3">
            <button
              onClick={this.handleReset}
              className="flex items-center gap-2 px-3 py-1.5 bg-slate-800 hover:bg-slate-700 text-xs font-mono font-medium rounded border border-slate-700 text-slate-200 transition-colors"
            >
              <RefreshCw className="w-3.5 h-3.5" /> Retry Render
            </button>
          </div>
        </div>
      );
    }

    return this.props.children;
  }
}
