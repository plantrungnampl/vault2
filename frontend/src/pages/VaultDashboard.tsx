import React, { useState, useEffect } from 'react';
import { useMutation, useQueryClient, useQuery } from '@tanstack/react-query';
import { useAuth } from '../contexts/AuthContext';
import { Toast } from '../components/ui/Toast';
import { LoadingSpinner } from '../components/ui/LoadingSpinner';
import VaultHeader from '../components/VaultHeader';
import VaultSidebar from '../components/VaultSidebar';
import VaultItemCard from '../components/VaultItemCard';
import AddItemModal from '../components/AddItemModal';
import { apiClient } from '../services/api';
import type { VaultItem, VaultFolder, VaultStats, CreateVaultItemRequest, UpdateVaultItemRequest } from '../services/api';

interface VaultSortOptions {
  field: 'name' | 'created_at' | 'updated_at' | 'type';
  direction: 'asc' | 'desc';
}

const VaultDashboard: React.FC = () => {
  const { state } = useAuth();
  const user = state.user;
  const queryClient = useQueryClient();
  
  // State management
  const [searchQuery, setSearchQuery] = useState('');
  const [selectedFilter, setSelectedFilter] = useState('all');
  const [sortOptions, setSortOptions] = useState<VaultSortOptions>({
    field: 'name',
    direction: 'asc',
  });
  const [viewMode, setViewMode] = useState<'grid' | 'list'>('grid');
  const [selectedItems] = useState<string[]>([]);
  const [showAddModal, setShowAddModal] = useState(false);
  const [editingItem, setEditingItem] = useState<VaultItem | null>(null);
  const [showSidebar, setShowSidebar] = useState(true);
  const [currentPage, setCurrentPage] = useState(1);
  const [toast, setToast] = useState<{
    message: string;
    type: 'success' | 'error' | 'info';
  } | null>(null);

  // API Queries
  const { data: vaultStats, isLoading: statsLoading } = useQuery({
    queryKey: ['vault-stats'],
    queryFn: () => apiClient.getVaultStats(),
    refetchInterval: 30000, // Refetch every 30 seconds
  });

  const { data: vaultFolders, isLoading: foldersLoading } = useQuery({
    queryKey: ['vault-folders'],
    queryFn: () => apiClient.getVaultFolders(),
  });

  const { 
    data: vaultItemsResponse, 
    isLoading: itemsLoading, 
    error: itemsError 
  } = useQuery({
    queryKey: ['vault-items', currentPage, selectedFilter, searchQuery],
    queryFn: () => apiClient.getVaultItems({
      page: currentPage,
      limit: 20,
      type: selectedFilter !== 'all' ? selectedFilter : undefined,
      search: searchQuery || undefined,
    }),
  });

  const { data: recentItems } = useQuery({
    queryKey: ['recent-items'],
    queryFn: () => apiClient.getRecentItems(5),
  });

  const { data: folders = [] } = useQuery<VaultFolder[]>({
    queryKey: ['folders'],
    queryFn: () => apiClient.getFolders(),
  });

  const { data: vaultStats } = useQuery<VaultStats>({
    queryKey: ['vault-stats'],
    queryFn: () => apiClient.getVaultStats(),
  });

  const stats: VaultStats = vaultStats || {
    total_items: 0,
    total_folders: 0,
    favorite_items: 0,
    recent_items: 0,
    type_stats: {
      password: 1,
      credit_card: 1,
    }
  };

  // Mutations
  const createItemMutation = useMutation({
    mutationFn: (data: CreateVaultItemRequest) => apiClient.createVaultItem(data),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['vault-items'] });
      setToast({ message: 'Đã tạo mục vault thành công!', type: 'success' });
      setShowAddModal(false);
    },
    onError: (error: any) => {
      setToast({ 
        message: error.message || 'Có lỗi xảy ra khi tạo mục vault',
        type: 'error' 
      });
    },
  });

  const deleteItemMutation = useMutation({
    mutationFn: (id: string) => apiClient.deleteVaultItem(id),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['vault-items'] });
      setToast({ message: 'Đã xóa mục vault thành công!', type: 'success' });
    },
    onError: (error: any) => {
      setToast({ 
        message: error.message || 'Có lỗi xảy ra khi xóa mục vault',
        type: 'error' 
      });
    },
  });

  // Event handlers
  const handleAddItem = () => {
    setEditingItem(null);
    setShowAddModal(true);
  };

  const handleEditItem = (item: VaultItem) => {
    setEditingItem(item);
    setShowAddModal(true);
  };

  const handleDeleteItem = (id: string) => {
    if (window.confirm('Bạn có chắc chắn muốn xóa mục này?')) {
      deleteItemMutation.mutate(id);
    }
  };

  const handleCreateItem = (data: CreateVaultItemRequest) => {
    createItemMutation.mutate(data);
  };

  const handleCopyField = async (value: string, fieldName: string) => {
    try {
      await navigator.clipboard.writeText(value);
      setToast({ 
        message: `Đã sao chép ${fieldName} vào clipboard!`,
        type: 'success' 
      });
    } catch (error) {
      setToast({ 
        message: 'Không thể sao chép vào clipboard',
        type: 'error' 
      });
    }
  };

  const handleBulkAction = (action: string) => {
    if (selectedItems.length === 0) return;
    
    switch (action) {
      case 'delete':
        selectedItems.forEach(itemId => {
          deleteItemMutation.mutate(itemId);
        });
        break;
      case 'move':
        // TODO: Implement bulk move functionality
        break;
      case 'favorite':
        // TODO: Implement bulk favorite functionality
        break;
    }
    setSelectedItems([]);
  };

  const handleSecurityReport = () => {
    // Navigate to security report page
    window.open('/security-report', '_blank');
  };

  const handleSettings = () => {
    // Navigate to settings
    console.log('Navigate to settings');
  };

  const handleProfile = () => {
    // Navigate to profile
    console.log('Navigate to profile');
  };

  const handleLogout = () => {
    // Handle logout
    console.log('Handle logout');
  };

  const handleCreateFolder = () => {
    const folderName = prompt('Nhập tên thư mục:');
    if (folderName) {
      // Create folder logic here
      console.log('Create folder:', folderName);
    }
  };

  const handleDeleteFolder = (folderId: string) => {
    if (window.confirm('Bạn có chắc chắn muốn xóa thư mục này?')) {
      // Delete folder logic here
      console.log('Delete folder:', folderId);
    }
  };

  // Filter and sort items
  const getFilteredItems = () => {
    let filtered = [...mockItems];

    // Apply text search
    if (searchQuery) {
      filtered = filtered.filter(item =>
        item.name.toLowerCase().includes(searchQuery.toLowerCase()) ||
        item.notes?.toLowerCase().includes(searchQuery.toLowerCase())
      );
    }

    // Apply filters
    if (selectedFilter !== 'all') {
      if (selectedFilter === 'favorite') {
        filtered = filtered.filter(item => item.favorite);
      } else if (selectedFilter.startsWith('folder:')) {
        const folderId = selectedFilter.replace('folder:', '');
        filtered = filtered.filter(item => item.folder_id === folderId);
      } else {
        filtered = filtered.filter(item => item.type === selectedFilter);
      }
    }

    // Apply sorting
    filtered.sort((a, b) => {
      let aValue = (a as any)[sortOptions.field];
      let bValue = (b as any)[sortOptions.field];

      if (typeof aValue === 'string' && typeof bValue === 'string') {
        aValue = aValue.toLowerCase();
        bValue = bValue.toLowerCase();
      }

      // Handle undefined values
      if (aValue === undefined && bValue === undefined) return 0;
      if (aValue === undefined) return 1;
      if (bValue === undefined) return -1;

      if (sortOptions.direction === 'asc') {
        return aValue < bValue ? -1 : aValue > bValue ? 1 : 0;
      } else {
        return aValue > bValue ? -1 : aValue < bValue ? 1 : 0;
      }
    });

    return filtered;
  };

  const filteredItems = getFilteredItems();

  return (
    <div className="flex h-screen bg-gray-50">
      {/* Sidebar */}
      <div
        className={`${
          showSidebar ? 'w-80' : 'w-0'
        } transition-all duration-300 overflow-hidden`}
      >
        <VaultSidebar
          selectedFilter={selectedFilter}
          onFilterChange={setSelectedFilter}
          folders={folders}
          stats={stats}
          onCreateFolder={handleCreateFolder}
          onDeleteFolder={handleDeleteFolder}
          onSecurityReport={handleSecurityReport}
        />
      </div>

      {/* Main Content */}
      <div className="flex-1 flex flex-col overflow-hidden">
        {/* Header */}
        <VaultHeader
          searchQuery={searchQuery}
          onSearchChange={setSearchQuery}
          sortOptions={sortOptions}
          onSortChange={setSortOptions}
          viewMode={viewMode}
          onViewModeChange={setViewMode}
          selectedCount={selectedItems.length}
          totalCount={filteredItems.length}
          onAddItem={handleAddItem}
          onBulkAction={handleBulkAction}
          onSecurityReport={handleSecurityReport}
          onToggleSidebar={() => setShowSidebar(!showSidebar)}
          onSettings={handleSettings}
          onProfile={handleProfile}
          onLogout={handleLogout}
          userName={user?.email?.split('@')[0] || 'Người dùng'}
        />

        {/* Content Area */}
        <main className="flex-1 overflow-auto p-6">
          {filteredItems.length === 0 ? (
            <div className="flex flex-col items-center justify-center h-full text-gray-500">
              <p className="text-xl mb-4">Không có mục nào được tìm thấy</p>
              <button
                onClick={handleAddItem}
                className="bg-blue-600 text-white px-6 py-3 rounded-lg hover:bg-blue-700 transition-colors"
              >
                Thêm mục đầu tiên
              </button>
            </div>
          ) : (
            <div
              className={
                viewMode === 'grid'
                  ? 'grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4'
                  : 'space-y-4'
              }
            >
              {filteredItems.map((item) => (
                <VaultItemCard
                  key={item.id}
                  item={item}
                  onEdit={handleEditItem}
                  onDelete={handleDeleteItem}
                  onCopyField={handleCopyField}
                />
              ))}
            </div>
          )}
        </main>
      </div>

      {/* Add/Edit Modal */}
      <AddItemModal
        isOpen={showAddModal}
        onClose={() => setShowAddModal(false)}
        onSubmit={handleCreateItem}
        folders={folders}
        editItem={editingItem}
      />

      {/* Toast Notifications */}
      {toast && (
        <Toast
          message={toast.message}
          type={toast.type}
          onClose={() => setToast(null)}
        />
      )}

      {/* Loading Spinner */}
      {(createItemMutation.isPending || deleteItemMutation.isPending) && (
        <LoadingSpinner />
      )}
    </div>
  );
};

export default VaultDashboard;
