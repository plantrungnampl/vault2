import { Navigate, useLocation } from 'react-router-dom';
import { useAuth } from '../../contexts/AuthContext';

interface ProtectedRouteProps {
  children: React.ReactNode;
  requireAdmin?: boolean;
}

export function ProtectedRoute({ children, requireAdmin = false }: ProtectedRouteProps) {
  const { state } = useAuth();
  const location = useLocation();

  // Check if user is authenticated
  if (!state.isAuthenticated) {
    return <Navigate to="/login" state={{ from: location }} replace />;
  }

  // Check if admin privileges are required
  if (requireAdmin) {
    const adminRoles = ['vault_admin', 'security_admin', 'super_admin'];
    if (!adminRoles.includes(state.user?.role || '')) {
      return (
        <div className="min-h-screen flex items-center justify-center bg-gray-50">
          <div className="text-center">
            <h1 className="text-2xl font-bold text-gray-900 mb-4">Truy cập bị từ chối</h1>
            <p className="text-gray-600 mb-8">Bạn không có quyền truy cập trang này</p>
            <a 
              href="/vault" 
              className="inline-flex items-center px-4 py-2 border border-transparent text-base font-medium rounded-md text-white bg-blue-600 hover:bg-blue-700"
            >
              Về trang chủ
            </a>
          </div>
        </div>
      );
    }
  }

  // Check if MFA is required for sensitive operations
  if (state.user?.mfa_enabled && !state.mfaValid) {
    // Some routes might require MFA verification
    const mfaRequiredRoutes = ['/admin', '/settings/security'];
    const requiresMFA = mfaRequiredRoutes.some(route => location.pathname.startsWith(route));
    
    if (requiresMFA) {
      return <Navigate to="/mfa-verify" state={{ from: location }} replace />;
    }
  }

  return <>{children}</>;
}
