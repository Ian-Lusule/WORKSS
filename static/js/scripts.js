/*
 * MoneyFlow - Custom JavaScript
 * Advanced financial management application
 */

// ================= GLOBAL VARIABLES =================
let currentUser = null;
let notificationCount = 0;
let charts = {};
let dataTableInstances = {};

// ================= DOCUMENT READY =================
$(document).ready(function() {
    console.log('MoneyFlow initialized');
    
    // Initialize components
    initTheme();
    initTooltips();
    initPopovers();
    initToasts();
    initModals();
    initDataTables();
    initCharts();
    initNotifications();
    initFormValidation();
    initEventListeners();
    
    // Check authentication status
    checkAuthStatus();
    
    // Start periodic updates
    startPeriodicUpdates();
});

// ================= THEME MANAGEMENT =================
function initTheme() {
    // Check for saved theme preference
    const savedTheme = localStorage.getItem('moneyflow-theme') || 'dark';
    document.documentElement.setAttribute('data-bs-theme', savedTheme);
    
    // Theme toggle button
    $('#themeToggle').click(function() {
        const currentTheme = document.documentElement.getAttribute('data-bs-theme');
        const newTheme = currentTheme === 'dark' ? 'light' : 'dark';
        
        document.documentElement.setAttribute('data-bs-theme', newTheme);
        localStorage.setItem('moneyflow-theme', newTheme);
        
        // Update icon
        const icon = $(this).find('i');
        icon.toggleClass('fa-moon fa-sun');
        
        showToast(`Switched to ${newTheme} theme`, 'info');
    });
    
    // Add theme toggle button to navbar if not exists
    if ($('#themeToggle').length === 0) {
        const themeToggle = `
            <li class="nav-item">
                <button id="themeToggle" class="btn btn-link nav-link" title="Toggle theme">
                    <i class="fas fa-moon"></i>
                </button>
            </li>
        `;
        $('.navbar-nav:last').prepend(themeToggle);
    }
}

// ================= TOOLTIPS & POPOVERS =================
function initTooltips() {
    const tooltipTriggerList = [].slice.call(document.querySelectorAll('[data-bs-toggle="tooltip"]'));
    tooltipTriggerList.map(function(tooltipTriggerEl) {
        return new bootstrap.Tooltip(tooltipTriggerEl, {
            delay: { show: 500, hide: 100 }
        });
    });
}

function initPopovers() {
    const popoverTriggerList = [].slice.call(document.querySelectorAll('[data-bs-toggle="popover"]'));
    popoverTriggerList.map(function(popoverTriggerEl) {
        return new bootstrap.Popover(popoverTriggerEl);
    });
}

// ================= TOAST NOTIFICATIONS =================
function initToasts() {
    // Create toast container if not exists
    if ($('.toast-container').length === 0) {
        $('body').append('<div class="toast-container position-fixed bottom-0 end-0 p-3"></div>');
    }
}

function showToast(message, type = 'info', duration = 3000) {
    const icons = {
        success: 'check-circle',
        error: 'exclamation-circle',
        warning: 'exclamation-triangle',
        info: 'info-circle',
        danger: 'exclamation-circle'
    };
    
    const icon = icons[type] || 'info-circle';
    
    const toast = $(`
        <div class="toast align-items-center text-bg-${type} border-0" role="alert">
            <div class="d-flex">
                <div class="toast-body">
                    <i class="fas fa-${icon} me-2"></i>
                    ${message}
                </div>
                <button type="button" class="btn-close btn-close-white me-2 m-auto" data-bs-dismiss="toast"></button>
            </div>
        </div>
    `);
    
    $('.toast-container').append(toast);
    const bsToast = new bootstrap.Toast(toast[0], {
        delay: duration
    });
    
    bsToast.show();
    
    toast.on('hidden.bs.toast', function() {
        $(this).remove();
    });
}

// ================= MODAL MANAGEMENT =================
function initModals() {
    // Auto-focus first input in modals
    $(document).on('shown.bs.modal', '.modal', function() {
        $(this).find('input[type="text"], input[type="email"], input[type="password"]').first().focus();
    });
    
    // Clear form on modal hide
    $(document).on('hidden.bs.modal', '.modal', function() {
        $(this).find('form').trigger('reset');
        $(this).find('.is-invalid').removeClass('is-invalid');
        $(this).find('.invalid-feedback').remove();
    });
}

// ================= DATA TABLES =================
function initDataTables() {
    // Initialize all tables with DataTables class
    $('.data-table').each(function() {
        const tableId = $(this).attr('id') || 'table-' + Math.random().toString(36).substr(2, 9);
        $(this).attr('id', tableId);
        
        dataTableInstances[tableId] = $(this).DataTable({
            pageLength: 10,
            responsive: true,
            language: {
                search: "Search:",
                lengthMenu: "Show _MENU_ entries",
                info: "Showing _START_ to _END_ of _TOTAL_ entries",
                paginate: {
                    first: "First",
                    last: "Last",
                    next: "Next",
                    previous: "Previous"
                }
            },
            dom: '<"row"<"col-sm-12 col-md-6"l><"col-sm-12 col-md-6"f>>' +
                 '<"row"<"col-sm-12"tr>>' +
                 '<"row"<"col-sm-12 col-md-5"i><"col-sm-12 col-md-7"p>>'
        });
    });
}

// ================= CHARTS =================
function initCharts() {
    // Initialize all charts on page
    $('.chart-canvas').each(function() {
        const canvas = $(this)[0];
        const ctx = canvas.getContext('2d');
        const chartType = $(this).data('chart-type') || 'line';
        const chartId = $(this).attr('id') || 'chart-' + Math.random().toString(36).substr(2, 9);
        
        // Get data from data attributes
        const labels = JSON.parse($(this).data('labels') || '[]');
        const datasets = JSON.parse($(this).data('datasets') || '[]');
        
        if (labels.length > 0 && datasets.length > 0) {
            charts[chartId] = new Chart(ctx, {
                type: chartType,
                data: {
                    labels: labels,
                    datasets: datasets
                },
                options: {
                    responsive: true,
                    maintainAspectRatio: false,
                    plugins: {
                        legend: {
                            position: 'bottom'
                        }
                    }
                }
            });
        }
    });
}

// ================= NOTIFICATION SYSTEM =================
function initNotifications() {
    // Load notification count
    updateNotificationCount();
    
    // Setup notification polling
    setInterval(updateNotificationCount, 30000); // Every 30 seconds
}

function updateNotificationCount() {
    if (!isAuthenticated()) return;
    
    $.ajax({
        url: '/api/notifications/count',
        method: 'GET',
        success: function(data) {
            notificationCount = data.count || 0;
            updateNotificationBadge();
        },
        error: function() {
            // Silently fail
        }
    });
}

function updateNotificationBadge() {
    const badge = $('#notificationCount');
    if (notificationCount > 0) {
        badge.text(notificationCount);
        badge.show();
        
        // Add animation for new notifications
        if (notificationCount > parseInt(badge.text() || 0)) {
            badge.addClass('pulse');
            setTimeout(() => badge.removeClass('pulse'), 2000);
        }
    } else {
        badge.hide();
    }
}

// ================= FORM VALIDATION =================
function initFormValidation() {
    // Custom validation for amount fields
    $('input[type="number"][min="0"]').on('blur', function() {
        const value = parseFloat($(this).val());
        const min = parseFloat($(this).attr('min')) || 0;
        
        if (value < min) {
            $(this).val(min);
            showToast(`Minimum value is ${min}`, 'warning');
        }
    });
    
    // Date validation
    $('input[type="date"]').on('change', function() {
        const selectedDate = new Date($(this).val());
        const today = new Date();
        
        if (selectedDate > today) {
            showToast('Future dates are not allowed', 'warning');
            $(this).val(today.toISOString().split('T')[0]);
        }
    });
}

// ================= EVENT LISTENERS =================
function initEventListeners() {
    // Logout confirmation
    $(document).on('click', '[data-action="logout"]', function(e) {
        e.preventDefault();
        
        if (confirm('Are you sure you want to logout?')) {
            window.location.href = $(this).attr('href');
        }
    });
    
    // Delete confirmation
    $(document).on('click', '[data-action="delete"]', function(e) {
        e.preventDefault();
        
        const message = $(this).data('confirm') || 'Are you sure you want to delete this item?';
        
        if (confirm(message)) {
            const url = $(this).attr('href');
            const method = $(this).data('method') || 'DELETE';
            
            $.ajax({
                url: url,
                method: method,
                success: function(response) {
                    if (response.success) {
                        showToast('Item deleted successfully', 'success');
                        // Reload or remove item from DOM
                        if ($(e.target).closest('tr').length) {
                            $(e.target).closest('tr').fadeOut(300, function() {
                                $(this).remove();
                            });
                        } else {
                            setTimeout(() => location.reload(), 1000);
                        }
                    } else {
                        showToast(response.error || 'Delete failed', 'danger');
                    }
                },
                error: function(xhr) {
                    const error = xhr.responseJSON?.error || 'Delete failed';
                    showToast(error, 'danger');
                }
            });
        }
    });
    
    // Quick add expense
    $('#quickAddExpense').submit(function(e) {
        e.preventDefault();
        const amount = $(this).find('input[name="amount"]').val();
        const category = $(this).find('select[name="category"]').val();
        
        if (!amount || !category) {
            showToast('Please fill all fields', 'warning');
            return;
        }
        
        $.ajax({
            url: '/expenses/add',
            method: 'POST',
            contentType: 'application/json',
            data: JSON.stringify({
                amount: parseFloat(amount),
                category: category,
                date: new Date().toISOString().split('T')[0]
            }),
            success: function(response) {
                if (response.success) {
                    showToast('Expense added!', 'success');
                    $('#quickAddExpense')[0].reset();
                    
                    // Update dashboard if on dashboard
                    if (window.location.pathname === '/dashboard') {
                        setTimeout(() => location.reload(), 500);
                    }
                } else {
                    showToast(response.error, 'danger');
                }
            }
        });
    });
    
    // Keyboard shortcuts
    $(document).keydown(function(e) {
        // Ctrl+E to add expense
        if (e.ctrlKey && e.key === 'e') {
            e.preventDefault();
            $('#addExpenseModal').modal('show');
        }
        
        // Ctrl+B to add budget
        if (e.ctrlKey && e.key === 'b') {
            e.preventDefault();
            $('#addBudgetModal').modal('show');
        }
        
        // Ctrl+R to refresh
        if (e.ctrlKey && e.key === 'r') {
            e.preventDefault();
            location.reload();
        }
        
        // Escape to close modals
        if (e.key === 'Escape') {
            $('.modal').modal('hide');
        }
    });
}

// ================= AUTHENTICATION =================
function checkAuthStatus() {
    // Check if user is authenticated
    $.ajax({
        url: '/api/auth/check',
        method: 'GET',
        success: function(response) {
            currentUser = response.user;
            updateUIForAuth();
        },
        error: function() {
            currentUser = null;
            updateUIForAuth();
        }
    });
}

function isAuthenticated() {
    return currentUser !== null;
}

function updateUIForAuth() {
    if (isAuthenticated()) {
        $('[data-show="authenticated"]').show();
        $('[data-show="unauthenticated"]').hide();
        
        // Update user info in navbar
        $('.user-name').text(currentUser?.full_name || 'User');
        $('.user-email').text(currentUser?.email || '');
    } else {
        $('[data-show="authenticated"]').hide();
        $('[data-show="unauthenticated"]').show();
    }
}

// ================= PERIODIC UPDATES =================
function startPeriodicUpdates() {
    // Update dashboard stats every minute
    if (window.location.pathname === '/dashboard') {
        setInterval(updateDashboardStats, 60000);
    }
    
    // Update charts every 5 minutes
    setInterval(updateCharts, 300000);
}

function updateDashboardStats() {
    $.ajax({
        url: '/api/dashboard/stats',
        method: 'GET',
        success: function(data) {
            // Update stats cards
            $('#totalExpenses').text('$' + data.total_expenses.toFixed(2));
            $('#activeBudgets').text(data.active_budgets);
            $('#monthlyAverage').text('$' + data.monthly_average.toFixed(2));
        }
    });
}

function updateCharts() {
    // Refresh all charts
    Object.keys(charts).forEach(chartId => {
        if (charts[chartId]) {
            charts[chartId].update();
        }
    });
}

// ================= UTILITY FUNCTIONS =================
function formatCurrency(amount) {
    return new Intl.NumberFormat('en-US', {
        style: 'currency',
        currency: 'USD'
    }).format(amount);
}

function formatDate(dateString) {
    const date = new Date(dateString);
    return date.toLocaleDateString('en-US', {
        year: 'numeric',
        month: 'short',
        day: 'numeric'
    });
}

function formatDateTime(dateString) {
    const date = new Date(dateString);
    return date.toLocaleDateString('en-US', {
        year: 'numeric',
        month: 'short',
        day: 'numeric',
        hour: '2-digit',
        minute: '2-digit'
    });
}

function debounce(func, wait) {
    let timeout;
    return function executedFunction(...args) {
        const later = () => {
            clearTimeout(timeout);
            func(...args);
        };
        clearTimeout(timeout);
        timeout = setTimeout(later, wait);
    };
}

function throttle(func, limit) {
    let inThrottle;
    return function() {
        const args = arguments;
        const context = this;
        if (!inThrottle) {
            func.apply(context, args);
            inThrottle = true;
            setTimeout(() => inThrottle = false, limit);
        }
    };
}

// ================= FILE UPLOAD =================
function handleFileUpload(input, onSuccess, onError) {
    const file = input.files[0];
    if (!file) return;
    
    // Validate file size (max 5MB)
    if (file.size > 5 * 1024 * 1024) {
        onError('File size must be less than 5MB');
        return;
    }
    
    // Validate file type
    const allowedTypes = ['image/jpeg', 'image/png', 'image/gif', 'application/pdf'];
    if (!allowedTypes.includes(file.type)) {
        onError('Invalid file type. Allowed: JPG, PNG, GIF, PDF');
        return;
    }
    
    const formData = new FormData();
    formData.append('file', file);
    
    $.ajax({
        url: '/api/upload',
        method: 'POST',
        data: formData,
        processData: false,
        contentType: false,
        success: function(response) {
            onSuccess(response);
        },
        error: function(xhr) {
            onError(xhr.responseJSON?.error || 'Upload failed');
        }
    });
}

// ================= EXPORT FUNCTIONS =================
function exportToCSV(data, filename) {
    const csv = convertToCSV(data);
    const blob = new Blob([csv], { type: 'text/csv' });
    const url = window.URL.createObjectURL(blob);
    const a = document.createElement('a');
    
    a.href = url;
    a.download = filename || 'export.csv';
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    window.URL.revokeObjectURL(url);
}

function convertToCSV(data) {
    if (data.length === 0) return '';
    
    const headers = Object.keys(data[0]);
    const rows = data.map(row => 
        headers.map(header => 
            JSON.stringify(row[header] || '')
        ).join(',')
    );
    
    return [headers.join(','), ...rows].join('\n');
}

// ================= PRINT FUNCTIONS =================
function printPage(elementId) {
    const element = document.getElementById(elementId);
    if (!element) {
        showToast('Element not found', 'warning');
        return;
    }
    
    const printWindow = window.open('', '_blank');
    printWindow.document.write(`
        <html>
            <head>
                <title>Print - MoneyFlow</title>
                <style>
                    body { font-family: Arial, sans-serif; }
                    table { width: 100%; border-collapse: collapse; }
                    th, td { border: 1px solid #ddd; padding: 8px; text-align: left; }
                    th { background-color: #f2f2f2; }
                    @media print {
                        .no-print { display: none; }
                    }
                </style>
            </head>
            <body>
                ${element.innerHTML}
            </body>
        </html>
    `);
    
    printWindow.document.close();
    printWindow.focus();
    printWindow.print();
    printWindow.close();
}

// ================= ERROR HANDLING =================
window.onerror = function(message, source, lineno, colno, error) {
    console.error('Global error:', { message, source, lineno, colno, error });
    showToast('An unexpected error occurred', 'danger');
    return false;
};

// ================= OFFLINE DETECTION =================
function checkOnlineStatus() {
    if (!navigator.onLine) {
        showToast('You are offline. Some features may not work.', 'warning');
    }
}

window.addEventListener('online', checkOnlineStatus);
window.addEventListener('offline', checkOnlineStatus);

// Initialize offline check
checkOnlineStatus();

// ================= SESSION MANAGEMENT =================
function checkSession() {
    const lastActivity = localStorage.getItem('lastActivity');
    const now = Date.now();
    
    if (lastActivity && (now - lastActivity > 30 * 60 * 1000)) { // 30 minutes
        showToast('Session expired. Please login again.', 'warning');
        window.location.href = '/logout';
    }
    
    localStorage.setItem('lastActivity', now);
}

// Update last activity on user interaction
$(document).on('mousemove keydown click', debounce(checkSession, 60000));

// ================= INITIALIZATION COMPLETE =================
$(window).on('load', function() {
    // Add loading animation removal
    $('.loading').removeClass('loading');
    
    // Show welcome message for new users
    if (localStorage.getItem('firstVisit') === null) {
        showToast('Welcome to MoneyFlow! Start by adding your first expense or budget.', 'info');
        localStorage.setItem('firstVisit', 'true');
    }
    
    // Initialize tour for new users
    if (localStorage.getItem('tourCompleted') === null) {
        setTimeout(() => {
            if (confirm('Would you like a quick tour of the application?')) {
                startTour();
            }
            localStorage.setItem('tourCompleted', 'true');
        }, 2000);
    }
});

// ================= TOUR GUIDE =================
function startTour() {
    const steps = [
        {
            element: '.navbar-brand',
            title: 'Welcome to MoneyFlow',
            content: 'This is your personal finance manager. Let me show you around!'
        },
        {
            element: '[href="/dashboard"]',
            title: 'Dashboard',
            content: 'View your financial overview, recent expenses, and budget progress here.'
        },
        {
            element: '[href="/expenses"]',
            title: 'Expenses',
            content: 'Track and manage all your expenses in one place.'
        },
        {
            element: '[href="/budgets"]',
            title: 'Budgets',
            content: 'Set spending limits and track your progress.'
        },
        {
            element: '[href="/insights"]',
            title: 'Insights',
            content: 'Get detailed analytics and visualizations of your spending.'
        }
    ];
    
    // Simple tour implementation
    let currentStep = 0;
    
    function showStep(step) {
        if (step >= steps.length) {
            showToast('Tour completed!', 'success');
            return;
        }
        
        const { element, title, content } = steps[step];
        const $el = $(element);
        
        if ($el.length) {
            $el.addClass('tour-highlight');
            
            if (confirm(`${title}\n\n${content}\n\nClick OK for next step or Cancel to end tour.`)) {
                $el.removeClass('tour-highlight');
                currentStep++;
                setTimeout(() => showStep(currentStep), 100);
            } else {
                $el.removeClass('tour-highlight');
                showToast('Tour ended', 'info');
            }
        } else {
            currentStep++;
            showStep(currentStep);
        }
    }
    
    showStep(currentStep);
}

// ================= GLOBAL EXPORTS =================
window.MoneyFlow = {
    showToast,
    formatCurrency,
    formatDate,
    exportToCSV,
    printPage
};

// ================= END OF FILE =================