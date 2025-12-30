// api.js - Frontend API service
const API_BASE_URL = 'http://localhost:3000/api';

class ApiService {
    constructor() {
        this.token = localStorage.getItem('ce_token') || null;
        this.currentUser = JSON.parse(localStorage.getItem('ce_current_user') || 'null');
    }

    setAuthToken(token, user) {
        this.token = token;
        this.currentUser = user;
        localStorage.setItem('ce_token', token);
        localStorage.setItem('ce_current_user', JSON.stringify(user));
    }

    clearAuth() {
        this.token = null;
        this.currentUser = null;
        localStorage.removeItem('ce_token');
        localStorage.removeItem('ce_current_user');
    }

    async request(endpoint, options = {}) {
        const url = `${API_BASE_URL}${endpoint}`;
        const headers = {
            'Content-Type': 'application/json',
            ...options.headers
        };

        if (this.token) {
            headers['Authorization'] = `Bearer ${this.token}`;
        }

        try {
            const response = await fetch(url, {
                ...options,
                headers
            });

            if (!response.ok) {
                throw new Error(`HTTP ${response.status}: ${response.statusText}`);
            }

            return await response.json();
        } catch (error) {
            console.error('API Request failed:', error);
            throw error;
        }
    }

    // Authentication
    async adminLogin(email, password) {
        const data = await this.request('/admin/login', {
            method: 'POST',
            body: JSON.stringify({ email, password })
        });
        this.setAuthToken(data.token, data.user);
        return data;
    }

    async employeeLogin(email, password) {
        const data = await this.request('/employee/login', {
            method: 'POST',
            body: JSON.stringify({ email, password })
        });
        this.setAuthToken(data.token, data.user);
        return data;
    }

    // Admin endpoints
    async getEmployees() {
        return await this.request('/admin/employees');
    }

    async addEmployee(employeeData) {
        return await this.request('/admin/employees', {
            method: 'POST',
            body: JSON.stringify(employeeData)
        });
    }

    async deleteEmployee(id) {
        return await this.request(`/admin/employees/${id}`, {
            method: 'DELETE'
        });
    }

    async getAdminRecords(filters = {}) {
        const queryParams = new URLSearchParams(filters).toString();
        return await this.request(`/admin/records?${queryParams}`);
    }

    async getAdminDashboardStats() {
        return await this.request('/admin/dashboard/stats');
    }

    // Employee endpoints
    async getEmployeeRecords(filters = {}) {
        const queryParams = new URLSearchParams(filters).toString();
        return await this.request(`/employee/records?${queryParams}`);
    }

    async startTimer(project, task) {
        return await this.request('/employee/timer/start', {
            method: 'POST',
            body: JSON.stringify({ project, task })
        });
    }

    async stopTimer(timerId) {
        return await this.request(`/employee/timer/stop/${timerId}`, {
            method: 'POST'
        });
    }

    async pauseTimer(timerId, action) {
        return await this.request(`/employee/timer/pause/${timerId}`, {
            method: 'POST',
            body: JSON.stringify({ action })
        });
    }

    async addManualEntry(entryData) {
        return await this.request('/employee/records/manual', {
            method: 'POST',
            body: JSON.stringify(entryData)
        });
    }

    async getEmployeeDashboardStats() {
        return await this.request('/employee/dashboard/stats');
    }
}

// Create global API instance
window.api = new ApiService();
