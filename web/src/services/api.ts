import { QueryClient } from "@tanstack/react-query";

// Define the base URL for the API
const API_BASE_URL = import.meta.env.VITE_API_URL || "http://localhost:3000/api";

// Create an HTTP client with common configuration
const createHttpClient = (token?: string) => {
  return {
    get: async (url: string) => {
      const response = await fetch(`${API_BASE_URL}${url}`, {
        method: "GET",
        headers: {
          "Content-Type": "application/json",
          ...(token && { Authorization: `Bearer ${token}` }),
        },
      });
      return handleResponse(response);
    },
    post: async (url: string, data?: any) => {
      const response = await fetch(`${API_BASE_URL}${url}`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          ...(token && { Authorization: `Bearer ${token}` }),
        },
        body: data ? JSON.stringify(data) : undefined,
      });
      return handleResponse(response);
    },
    put: async (url: string, data?: any) => {
      const response = await fetch(`${API_BASE_URL}${url}`, {
        method: "PUT",
        headers: {
          "Content-Type": "application/json",
          ...(token && { Authorization: `Bearer ${token}` }),
        },
        body: data ? JSON.stringify(data) : undefined,
      });
      return handleResponse(response);
    },
    delete: async (url: string) => {
      const response = await fetch(`${API_BASE_URL}${url}`, {
        method: "DELETE",
        headers: {
          "Content-Type": "application/json",
          ...(token && { Authorization: `Bearer ${token}` }),
        },
      });
      return handleResponse(response);
    },
  };
};

// Handle API responses
const handleResponse = async (response: Response) => {
  if (!response.ok) {
    const errorData = await response.json().catch(() => ({}));
    throw new Error(errorData.message || `HTTP error! status: ${response.status}`);
  }
  // For successful responses that have content, parse the JSON
  const contentType = response.headers.get("content-type");
  if (contentType && contentType.includes("application/json")) {
    return response.json();
  }
  return response.text();
};

// API service with all endpoints
class ApiService {
  private client;

  constructor() {
    this.client = createHttpClient();
  }

  // Set authentication token for subsequent requests
  setToken(token: string) {
    this.client = createHttpClient(token);
  }

  // Public endpoints
  health = () => this.client.get("/health");
  login = (credentials: { username: string; password: string }) =>
    this.client.post("/login", credentials);
  register = (agentData: any) => this.client.post("/register", agentData);

  // Protected endpoints (Dashboard)
  getDashboardStats = () => this.client.get("/dashboard/stats");
  getTimeline = () => this.client.get("/dashboard/timeline");
  getAgentsStatus = () => this.client.get("/dashboard/agents-status");

  // Agents
  getAgents = () => this.client.get("/agents");
  getAgent = (id: number) => this.client.get(`/agents/${id}`);
  updateAgent = (id: number, data: any) => this.client.put(`/agents/${id}`, data);
  deleteAgent = (id: number) => this.client.delete(`/agents/${id}`);
  quarantineAgent = (id: number) => this.client.post(`/agents/${id}/quarantine`);
  unquarantineAgent = (id: number) => this.client.post(`/agents/${id}/unquarantine`);
  getAgentScans = (id: number) => this.client.get(`/agents/${id}/scans`);
  getAgentThreats = (id: number) => this.client.get(`/agents/${id}/threats`);
  getAgentEvents = (id: number) => this.client.get(`/agents/${id}/events`);

  // Scans
  getScanResults = () => this.client.get("/scans");
  getScanResult = (id: number) => this.client.get(`/scans/${id}`);
  createScanResult = (data: any) => this.client.post("/scans", data);
  getScanThreats = (id: number) => this.client.get(`/scans/${id}/threats`);
  triggerScan = (data: { agent_id: number; scan_type: string; target_path?: string }) => this.client.post("/scans/trigger", data);

  // Threats
  getThreats = () => this.client.get("/threats");
  getThreat = (id: number) => this.client.get(`/threats/${id}`);
  createThreat = (data: any) => this.client.post("/threats", data);
  updateThreat = (id: number, data: any) => this.client.put(`/threats/${id}`, data);
  deleteThreat = (id: number) => this.client.delete(`/threats/${id}`);
  getThreatsBySeverity = (severity: string) => this.client.get(`/threats/severity/${severity}`);

  // Signatures
  getSignatures = () => this.client.get("/signatures");
  createSignature = (data: any) => this.client.post("/signatures", data);
  getSignature = (id: number) => this.client.get(`/signatures/${id}`);
  updateSignature = (id: number, data: any) => this.client.put(`/signatures/${id}`, data);
  deleteSignature = (id: number) => this.client.delete(`/signatures/${id}`);
  syncSignatures = () => this.client.get("/signatures/sync");

  // Events
  getEvents = () => this.client.get("/events");
  getEvent = (id: number) => this.client.get(`/events/${id}`);
  createEvent = (data: any) => this.client.post("/events", data);
  getEventsByType = (type: string) => this.client.get(`/events/type/${type}`);

  // Quarantine
  getQuarantinedFiles = () => this.client.get("/quarantine");
  getQuarantinedFile = (id: number) => this.client.get(`/quarantine/${id}`);
  createQuarantinedFile = (data: any) => this.client.post("/quarantine", data);
  restoreQuarantinedFile = (id: number) => this.client.post(`/quarantine/${id}/restore`);
  deleteQuarantinedFile = (id: number) => this.client.delete(`/quarantine/${id}/delete`);

  // Users
  getUsers = () => this.client.get("/users");
  createUser = (data: any) => this.client.post("/users", data);
  getUser = (id: number) => this.client.get(`/users/${id}`);
  updateUser = (id: number, data: any) => this.client.put(`/users/${id}`, data);
  deleteUser = (id: number) => this.client.delete(`/users/${id}`);
  getProfile = () => this.client.get("/users/profile");
  updateProfile = (data: any) => this.client.put("/users/profile", data);
  changePassword = (data: any) => this.client.post("/users/change-password", data);
}

// Create a single instance of the API service
export const apiService = new ApiService();

// Create a query client for React Query with proper defaults
export const queryClient = new QueryClient({
  defaultOptions: {
    queries: {
      staleTime: 5 * 60 * 1000, // 5 minutes
      retry: 1,
      refetchOnWindowFocus: false,
    },
  },
});

// Define TypeScript interfaces for the data models
export interface Agent {
  id: number;
  agent_id: string;
  name: string;
  hostname?: string;
  platform?: string;
  version?: string;
  ip_address?: string;
  public_key?: string;
  last_seen?: string;
  registered_at: string;
  is_active: boolean;
  quarantine: boolean;
  policy?: string;
  created_at: string;
  updated_at: string;
}

export interface ScanResult {
  id: number;
  agent_id: number;
  scan_type: string;
  file_paths: string[];
  threats: Threat[];
  scan_time: string;
  duration: number;
  status: string;
  created_at: string;
  updated_at: string;
}

export interface Threat {
  id: number;
  scan_result_id?: number;
  agent_id?: number;
  file_path: string;
  threat_type: string;
  threat_name: string;
  severity: string;
  action_taken?: string;
  created_at: string;
}

export interface Event {
  id: number;
  agent_id: number;
  agent: Agent;
  event_type: string;
  event_source: string;
  description: string;
  severity: string;
  data: string;
  timestamp: string;
  created_at: string;
}

export interface Signature {
  id: number;
  name: string;
  type: string;
  content: string;
  hash_type?: string;
  threat_type?: string;
  description?: string;
  version?: string;
  status: string;
  created_by: string;
  updated_at: string;
  created_at: string;
}

export interface User {
  id: number;
  username: string;
  email?: string;
  role: string;
  is_active: boolean;
  last_seen?: string;
  created_at: string;
  updated_at: string;
}

export interface DashboardStats {
  agents_online: number;
  last_scan_count: number;
  threats_detected: number;
  active_scans: number;
}