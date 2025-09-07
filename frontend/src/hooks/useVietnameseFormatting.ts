import { useTranslation } from 'react-i18next';
import { useLanguage } from '../contexts/LanguageContext';

export const useVietnameseFormatting = () => {
  const { t, i18n } = useTranslation();
  const { currentLanguage } = useLanguage();

  const isVietnamese = currentLanguage === 'vi';

  // Format date according to Vietnamese locale
  const formatDate = (date: Date | string | number) => {
    const dateObj = new Date(date);
    if (isVietnamese) {
      return dateObj.toLocaleDateString('vi-VN', {
        year: 'numeric',
        month: '2-digit',
        day: '2-digit'
      });
    }
    return dateObj.toLocaleDateString('en-US', {
      year: 'numeric',
      month: 'short',
      day: '2-digit'
    });
  };

  // Format time according to Vietnamese locale
  const formatTime = (date: Date | string | number) => {
    const dateObj = new Date(date);
    return dateObj.toLocaleTimeString(isVietnamese ? 'vi-VN' : 'en-US', {
      hour: '2-digit',
      minute: '2-digit',
      hour12: !isVietnamese
    });
  };

  // Format datetime according to Vietnamese locale
  const formatDateTime = (date: Date | string | number) => {
    return `${formatDate(date)} ${formatTime(date)}`;
  };

  // Format currency (VND for Vietnamese, USD for English)
  const formatCurrency = (amount: number) => {
    if (isVietnamese) {
      return new Intl.NumberFormat('vi-VN', {
        style: 'currency',
        currency: 'VND'
      }).format(amount);
    }
    return new Intl.NumberFormat('en-US', {
      style: 'currency',
      currency: 'USD'
    }).format(amount);
  };

  // Format numbers according to locale
  const formatNumber = (number: number) => {
    return new Intl.NumberFormat(isVietnamese ? 'vi-VN' : 'en-US').format(number);
  };

  // Get Vietnamese-first name format
  const formatName = (firstName: string, lastName: string) => {
    if (isVietnamese) {
      return `${lastName} ${firstName}`;
    }
    return `${firstName} ${lastName}`;
  };

  // Vietnamese-specific password strength messages
  const getPasswordStrengthMessage = (strength: number) => {
    const strengthKeys = ['weak', 'medium', 'strong', 'veryStrong'];
    const strengthKey = strengthKeys[Math.min(strength, 3)];
    return t(`security.passwordStrength.${strengthKey}`);
  };

  // Vietnamese phone number formatting
  const formatPhoneNumber = (phone: string) => {
    if (isVietnamese) {
      // Vietnamese phone format: +84 (0) 123 456 789
      const cleaned = phone.replace(/\D/g, '');
      if (cleaned.startsWith('84')) {
        return `+84 ${cleaned.slice(2, 4)} ${cleaned.slice(4, 7)} ${cleaned.slice(7)}`;
      }
      if (cleaned.startsWith('0')) {
        return `${cleaned.slice(0, 4)} ${cleaned.slice(4, 7)} ${cleaned.slice(7)}`;
      }
    }
    // Default US format
    const cleaned = phone.replace(/\D/g, '');
    return cleaned.replace(/(\d{3})(\d{3})(\d{4})/, '($1) $2-$3');
  };

  // Vietnamese address formatting
  const formatAddress = (address: {
    street?: string;
    ward?: string;
    district?: string;
    city?: string;
    country?: string;
  }) => {
    if (isVietnamese) {
      // Vietnamese format: Street, Ward, District, City
      const parts = [address.street, address.ward, address.district, address.city]
        .filter(Boolean);
      return parts.join(', ');
    }
    // English format: Street, City, Country
    const parts = [address.street, address.city, address.country]
      .filter(Boolean);
    return parts.join(', ');
  };

  return {
    formatDate,
    formatTime,
    formatDateTime,
    formatCurrency,
    formatNumber,
    formatName,
    formatPhoneNumber,
    formatAddress,
    getPasswordStrengthMessage,
    isVietnamese,
    t,
    currentLanguage
  };
};