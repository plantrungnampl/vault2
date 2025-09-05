export function LoadingSpinner() {
  return (
    <div className="min-h-screen flex items-center justify-center bg-gradient-to-br from-blue-50 to-indigo-100">
      <div className="text-center">
        <div className="relative">
          {/* Main spinner */}
          <div className="w-16 h-16 border-4 border-blue-200 border-t-blue-600 rounded-full animate-spin mx-auto"></div>
          
          {/* Inner spinner */}
          <div className="absolute top-2 left-2 w-12 h-12 border-4 border-transparent border-t-blue-400 rounded-full animate-spin"></div>
        </div>
        
        <div className="mt-4">
          <h2 className="text-lg font-semibold text-gray-900">SecureVault</h2>
          <p className="text-sm text-gray-600 mt-1">Đang tải...</p>
        </div>
        
        {/* Security indicators */}
        <div className="mt-6 flex items-center justify-center space-x-4 text-xs text-gray-500">
          <div className="flex items-center">
            <div className="w-2 h-2 bg-green-500 rounded-full mr-1"></div>
            <span>Mã hóa AES-256</span>
          </div>
          <div className="flex items-center">
            <div className="w-2 h-2 bg-green-500 rounded-full mr-1"></div>
            <span>TLS 1.3</span>
          </div>
          <div className="flex items-center">
            <div className="w-2 h-2 bg-green-500 rounded-full mr-1"></div>
            <span>Zero-Knowledge</span>
          </div>
        </div>
      </div>
    </div>
  );
}
