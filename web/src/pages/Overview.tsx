import { Shield, Search, AlertTriangle, CheckCircle, Loader2, Play } from "lucide-react";
import { StatCard } from "@/components/StatCard";
import { Card } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { BarChart, Bar, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer, LineChart, Line, PieChart, Pie, Cell, Legend } from "recharts";
import { useQuery, useMutation } from "@tanstack/react-query";
import { apiService, DashboardStats } from "@/services/api";
import { toast } from "@/hooks/use-toast";

export default function Overview() {
  // Fetch dashboard stats
  const { data: stats, isLoading: statsLoading, error: statsError } = useQuery({
    queryKey: ['dashboard-stats'],
    queryFn: () => apiService.getDashboardStats(),
    staleTime: 60000, // 1 minute
  });

  // Fetch timeline data (scan and threat trends)
  const { data: timeline, isLoading: timelineLoading, error: timelineError } = useQuery({
    queryKey: ['timeline'],
    queryFn: () => apiService.getTimeline(),
    staleTime: 60000, // 1 minute
  });

  // Calculate chart data from timeline
  const scanData = timeline?.scanActivity || [
    { name: "Mon", scans: 0 },
    { name: "Tue", scans: 0 },
    { name: "Wed", scans: 0 },
    { name: "Thu", scans: 0 },
    { name: "Fri", scans: 0 },
    { name: "Sat", scans: 0 },
    { name: "Sun", scans: 0 },
  ];

  const threatData = timeline?.threatTrends || [
    { name: "Mon", threats: 0 },
    { name: "Tue", threats: 0 },
    { name: "Wed", threats: 0 },
    { name: "Thu", threats: 0 },
    { name: "Fri", threats: 0 },
    { name: "Sat", threats: 0 },
    { name: "Sun", threats: 0 },
  ];

  const vulnData = timeline?.vulnerabilityTypes || [
    { name: "Critical", value: 0, color: "hsl(0, 72%, 50%)" },
    { name: "High", value: 0, color: "hsl(25, 95%, 53%)" },
    { name: "Medium", value: 0, color: "hsl(45, 93%, 47%)" },
    { name: "Low", value: 0, color: "hsl(142, 76%, 36%)" },
  ];

  // Mutation for triggering a scan
  const triggerScanMutation = useMutation({
    mutationFn: (scanData: { agent_id?: number; scan_type: string; target_path?: string }) =>
      apiService.triggerScan({
        agent_id: scanData.agent_id || 1, // Default to first agent if none specified
        scan_type: scanData.scan_type,
        target_path: scanData.target_path || "/"
      }),
    onSuccess: () => {
      toast({
        title: "Scan initiated",
        description: "The scan has been successfully queued for execution.",
      });
    },
    onError: (error) => {
      toast({
        title: "Error initiating scan",
        description: error.message || "Failed to queue the scan. Please try again.",
        variant: "destructive",
      });
    }
  });

  // Show loading state
  if (statsLoading || timelineLoading) {
    return (
      <div className="flex items-center justify-center h-64">
        <Loader2 className="h-8 w-8 animate-spin" />
      </div>
    );
  }

  const handleFullScan = () => {
    triggerScanMutation.mutate({ scan_type: "full" });
  };

  const handleQuickScan = () => {
    triggerScanMutation.mutate({ scan_type: "quick" });
  };

  return (
    <div className="space-y-6">
      <div>
        <h2 className="text-3xl font-bold text-foreground mb-2">System Overview</h2>
        <p className="text-muted-foreground">Monitor your antivirus protection status</p>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6">
        <StatCard
          title="System Status"
          value={stats?.systemStatus || "Protected"}
          icon={Shield}
          trend={{ value: "All systems operational", positive: true }}
        />
        <StatCard
          title="Total Scans"
          value={stats?.lastScanCount || 0}
          icon={Search}
          trend={{ value: "+12% from last week", positive: true }}
        />
        <StatCard
          title="Threats Detected"
          value={stats?.threatsDetected || 0}
          icon={AlertTriangle}
          trend={{ value: "-43% from last week", positive: true }}
        />
        <StatCard
          title="Agents Online"
          value={stats?.agentsOnline || 0}
          icon={CheckCircle}
          trend={{ value: "+2 this week", positive: true }}
        />
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        <Card className="p-6">
          <h3 className="text-lg font-semibold text-foreground mb-4">Scan Activity</h3>
          <ResponsiveContainer width="100%" height={300}>
            <BarChart data={scanData}>
              <CartesianGrid strokeDasharray="3 3" className="stroke-border" />
              <XAxis dataKey="name" className="text-muted-foreground" />
              <YAxis className="text-muted-foreground" />
              <Tooltip
                contentStyle={{
                  backgroundColor: "hsl(var(--card))",
                  border: "1px solid hsl(var(--border))",
                  borderRadius: "8px",
                }}
              />
              <Bar dataKey="scans" fill="hsl(var(--primary))" radius={[8, 8, 0, 0]} />
            </BarChart>
          </ResponsiveContainer>
        </Card>

        <Card className="p-6">
          <h3 className="text-lg font-semibold text-foreground mb-4">Threat Trends</h3>
          <ResponsiveContainer width="100%" height={300}>
            <LineChart data={threatData}>
              <CartesianGrid strokeDasharray="3 3" className="stroke-border" />
              <XAxis dataKey="name" className="text-muted-foreground" />
              <YAxis className="text-muted-foreground" />
              <Tooltip
                contentStyle={{
                  backgroundColor: "hsl(var(--card))",
                  border: "1px solid hsl(var(--border))",
                  borderRadius: "8px",
                }}
              />
              <Line type="monotone" dataKey="threats" stroke="hsl(var(--destructive))" strokeWidth={2} />
            </LineChart>
          </ResponsiveContainer>
        </Card>

        <Card className="p-6">
          <h3 className="text-lg font-semibold text-foreground mb-4">Vulnerability Types</h3>
          <ResponsiveContainer width="100%" height={300}>
            <PieChart>
              <Pie
                data={vulnData}
                cx="50%"
                cy="50%"
                labelLine={false}
                label={({ name, percent }) => `${name} ${(percent * 100).toFixed(0)}%`}
                outerRadius={80}
                fill="hsl(var(--primary))"
                dataKey="value"
              >
                {vulnData.map((entry, index) => (
                  <Cell key={`cell-${index}`} fill={entry.color} />
                ))}
              </Pie>
              <Tooltip
                contentStyle={{
                  backgroundColor: "hsl(var(--card))",
                  border: "1px solid hsl(var(--border))",
                  borderRadius: "8px",
                }}
              />
              <Legend />
            </PieChart>
          </ResponsiveContainer>
        </Card>
      </div>

      <Card className="p-6">
        <div className="flex items-center justify-between mb-4">
          <div>
            <h3 className="text-lg font-semibold text-foreground">Quick Actions</h3>
            <p className="text-sm text-muted-foreground">Manage your system protection</p>
          </div>
        </div>
        <div className="flex gap-4">
          <Button className="flex-1" onClick={handleFullScan} disabled={triggerScanMutation.isPending}>
            {triggerScanMutation.isPending ? (
              <>
                <Loader2 className="mr-2 h-4 w-4 animate-spin" /> Running...
              </>
            ) : (
              <>
                <Play className="mr-2 h-4 w-4" /> Run Full Scan
              </>
            )}
          </Button>
          <Button variant="outline" className="flex-1" onClick={handleQuickScan} disabled={triggerScanMutation.isPending}>
            {triggerScanMutation.isPending ? (
              <>
                <Loader2 className="mr-2 h-4 w-4 animate-spin" /> Running...
              </>
            ) : (
              <>
                <Play className="mr-2 h-4 w-4" /> Quick Scan
              </>
            )}
          </Button>
          <Button variant="outline" className="flex-1">Update Definitions</Button>
        </div>
      </Card>
    </div>
  );
}
