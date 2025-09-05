import { useState } from 'react';
import { Link, useNavigate, useLocation } from 'react-router-dom';
import { useForm } from 'react-hook-form';
import { zodResolver } from '@hookform/resolvers/zod';
import { z } from 'zod';
import { EyeIcon, EyeSlashIcon, ShieldCheckIcon } from '@heroicons/react/24/outline';
import { useAuth } from '../contexts/AuthContext';
import { Toast } from '../components/ui/Toast';

// Validation schema
const loginSchema = z.object({
  email: z
    .string()
    .min(1, 'Email là bắt buộc')
    .email('Địa chỉ email không hợp lệ'),
  password: z
    .string()
    .min(1, 'Mật khẩu là bắt buộc'),
  mfaCode: z
    .string()
    .optional(),
});

type LoginFormData = z.infer<typeof loginSchema>;

export function LoginPage() {
  const navigate = useNavigate();
  const location = useLocation();
  const { state, login, verifyMFA } = useAuth();
  const [showPassword, setShowPassword] = useState(false);
  const [toast, setToast] = useState<{ message: string; type: 'success' | 'error' } | null>(null);

  const {
    register,
    handleSubmit,
    formState: { errors, isSubmitting },
    watch,
  } = useForm<LoginFormData>({
    resolver: zodResolver(loginSchema),
  });

  const from = location.state?.from?.pathname || '/vault';

  const onSubmit = async (data: LoginFormData) => {
    try {
      if (state.mfaRequired) {
        await verifyMFA(data.mfaCode || '');
      } else {
        await login(data.email, data.password, data.mfaCode);
      }

      if (!state.mfaRequired) {
        setToast({ message: 'Đăng nhập thành công!', type: 'success' });
        setTimeout(() => {
          navigate(from, { replace: true });
        }, 1000);
      }
    } catch (error: any) {
      setToast({ message: error.message, type: 'error' });
    }
  };

  return (
    <div className="min-h-screen flex items-center justify-center bg-gradient-to-br from-blue-50 to-indigo-100 py-12 px-4 sm:px-6 lg:px-8">
      <div className="max-w-md w-full space-y-8">
        <div className="text-center">
          <div className="flex justify-center">
            <ShieldCheckIcon className="h-12 w-12 text-blue-600" />
          </div>
          <h2 className="mt-6 text-3xl font-extrabold text-gray-900">
            Đăng nhập SecureVault
          </h2>
          <p className="mt-2 text-sm text-gray-600">
            Hệ thống quản lý mật khẩu bảo mật cấp doanh nghiệp
          </p>
        </div>

        <div className="bg-white rounded-lg shadow-xl p-8">
          {state.mfaRequired && (
            <div className="mb-6 p-4 bg-blue-50 border border-blue-200 rounded-md">
              <div className="flex">
                <ShieldCheckIcon className="h-5 w-5 text-blue-400" />
                <div className="ml-3">
                  <h3 className="text-sm font-medium text-blue-800">
                    Xác thực hai bước
                  </h3>
                  <p className="mt-1 text-sm text-blue-700">
                    Vui lòng nhập mã xác thực từ ứng dụng authenticator của bạn.
                  </p>
                </div>
              </div>
            </div>
          )}

          <form className="space-y-6" onSubmit={handleSubmit(onSubmit)}>
            {!state.mfaRequired && (
              <>
                <div>
                  <label htmlFor="email" className="block text-sm font-medium text-gray-700">
                    Địa chỉ email
                  </label>
                  <div className="mt-1">
                    <input
                      {...register('email')}
                      type="email"
                      autoComplete="email"
                      className={`appearance-none block w-full px-3 py-2 border ${
                        errors.email ? 'border-red-300' : 'border-gray-300'
                      } rounded-md placeholder-gray-400 focus:outline-none focus:ring-blue-500 focus:border-blue-500 sm:text-sm`}
                      placeholder="user@example.com"
                    />
                    {errors.email && (
                      <p className="mt-1 text-sm text-red-600">{errors.email.message}</p>
                    )}
                  </div>
                </div>

                <div>
                  <label htmlFor="password" className="block text-sm font-medium text-gray-700">
                    Mật khẩu
                  </label>
                  <div className="mt-1 relative">
                    <input
                      {...register('password')}
                      type={showPassword ? 'text' : 'password'}
                      autoComplete="current-password"
                      className={`appearance-none block w-full px-3 py-2 pr-10 border ${
                        errors.password ? 'border-red-300' : 'border-gray-300'
                      } rounded-md placeholder-gray-400 focus:outline-none focus:ring-blue-500 focus:border-blue-500 sm:text-sm`}
                      placeholder="••••••••••••••"
                    />
                    <button
                      type="button"
                      className="absolute inset-y-0 right-0 pr-3 flex items-center"
                      onClick={() => setShowPassword(!showPassword)}
                    >
                      {showPassword ? (
                        <EyeSlashIcon className="h-5 w-5 text-gray-400" />
                      ) : (
                        <EyeIcon className="h-5 w-5 text-gray-400" />
                      )}
                    </button>
                    {errors.password && (
                      <p className="mt-1 text-sm text-red-600">{errors.password.message}</p>
                    )}
                  </div>
                </div>
              </>
            )}

            {state.mfaRequired && (
              <div>
                <label htmlFor="mfaCode" className="block text-sm font-medium text-gray-700">
                  Mã xác thực (6 chữ số)
                </label>
                <div className="mt-1">
                  <input
                    {...register('mfaCode')}
                    type="text"
                    maxLength={6}
                    className={`appearance-none block w-full px-3 py-2 border ${
                      errors.mfaCode ? 'border-red-300' : 'border-gray-300'
                    } rounded-md placeholder-gray-400 focus:outline-none focus:ring-blue-500 focus:border-blue-500 sm:text-sm text-center text-lg tracking-widest`}
                    placeholder="123456"
                  />
                  {errors.mfaCode && (
                    <p className="mt-1 text-sm text-red-600">{errors.mfaCode.message}</p>
                  )}
                </div>
              </div>
            )}

            <div className="flex items-center justify-between">
              <div className="flex items-center">
                <input
                  id="remember-me"
                  name="remember-me"
                  type="checkbox"
                  className="h-4 w-4 text-blue-600 focus:ring-blue-500 border-gray-300 rounded"
                />
                <label htmlFor="remember-me" className="ml-2 block text-sm text-gray-900">
                  Ghi nhớ đăng nhập
                </label>
              </div>

              <div className="text-sm">
                <a href="#" className="font-medium text-blue-600 hover:text-blue-500">
                  Quên mật khẩu?
                </a>
              </div>
            </div>

            <div>
              <button
                type="submit"
                disabled={isSubmitting || state.isLoading}
                className="group relative w-full flex justify-center py-2 px-4 border border-transparent text-sm font-medium rounded-md text-white bg-blue-600 hover:bg-blue-700 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-blue-500 disabled:opacity-50 disabled:cursor-not-allowed"
              >
                {isSubmitting || state.isLoading ? (
                  <div className="flex items-center">
                    <svg className="animate-spin -ml-1 mr-3 h-5 w-5 text-white" xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24">
                      <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4"></circle>
                      <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z"></path>
                    </svg>
                    {state.mfaRequired ? 'Đang xác thực...' : 'Đang đăng nhập...'}
                  </div>
                ) : (
                  state.mfaRequired ? 'Xác thực' : 'Đăng nhập'
                )}
              </button>
            </div>

            <div className="text-center">
              <span className="text-sm text-gray-600">
                Chưa có tài khoản?{' '}
                <Link to="/register" className="font-medium text-blue-600 hover:text-blue-500">
                  Đăng ký ngay
                </Link>
              </span>
            </div>
          </form>
        </div>

        {/* Security notice */}
        <div className="text-center">
          <p className="text-xs text-gray-500">
            🔒 Kết nối được bảo vệ bằng mã hóa TLS 1.3
          </p>
          <p className="text-xs text-gray-500 mt-1">
            SecureVault tuân thủ các tiêu chuẩn bảo mật quốc tế
          </p>
        </div>

        {/* Toast notification */}
        {toast && (
          <Toast
            message={toast.message}
            type={toast.type}
            onClose={() => setToast(null)}
          />
        )}
      </div>
    </div>
  );
}
