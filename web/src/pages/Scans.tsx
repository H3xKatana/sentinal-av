import { Search, Play, Clock, Loader2 } from "lucide-react";
import { Card } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import { useQuery, useMutation } from "@tanstack/react-query";
import { apiService, ScanResult } from "@/services/api";
import { toast } from "@/hooks/use-toast";

interface ScanHistoryItem {
  id: number;
  type: string;
  date: string;
  duration: string;
  filesScanned: number;
  threatsFound: number;
  status: string;
}

export default function Scans() {
  // Fetch scan results
  const { data: scans, isLoading, error } = useQuery({
    queryKey: ['scan-results'],
    queryFn: () => apiService.getScanResults(),
    staleTime: 60000, // 1 minute
  });

  // Mutation for triggering a scan
  const triggerScanMutation = useMutation({
    mutationFn: (scanData: { agent_id?: number; scan_type: string; target_path?: string }) =>
      apiService.triggerScan({
        agent_id: scanData.agent_id || 1, // Default to first agent if none specified
        scan_type: scanData.scan_type || "full",
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
  if (isLoading) {
    return (
      <div className="flex items-center justify-center h-64">
        <Loader2 className="h-8 w-8 animate-spin" />
      </div>
    );
  }

  // Calculate stats
  const totalScans = scans?.length || 0;
  const threatsFound = scans?.reduce((acc, scan) => {
    return acc + (scan.threats?.length || 0);
  }, 0) || 0;
  const avgScanTime = scans && scans.length > 0
    ? Math.round(scans.reduce((acc, scan) => acc + (scan.duration || 0), 0) / scans.length)
    : 0;

  // Convert scan results to the expected format
  const scanHistory: ScanHistoryItem[] = scans?.map((scan: any) => ({
    id: scan.id,
    type: scan.scan_type || 'Unknown',
    date: scan.scan_time ? new Date(scan.scan_time).toLocaleString() : 'N/A',
    duration: scan.duration ? `${Math.floor(scan.duration / 60000)}m ${Math.floor((scan.duration % 60000) / 1000)}s` : 'N/A',
    filesScanned: scan.file_paths?.length || 0,
    threatsFound: scan.threats?.length || 0,
    status: scan.status || 'completed'
  })) || [];

  const handleStartNewScan = () => {
    triggerScanMutation.mutate({ scan_type: "full" });
  };

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h2 className="text-3xl font-bold text-foreground mb-2">Scan Management</h2>
          <p className="text-muted-foreground">View scan history and run new scans</p>
        </div>
        <Button className="gap-2" onClick={handleStartNewScan} disabled={triggerScanMutation.isPending}>
          {triggerScanMutation.isPending ? (
            <>
              <Loader2 className="h-4 w-4 animate-spin" /> Starting...
            </>
          ) : (
            <>
              <Play className="h-4 w-4" /> Start New Scan
            </>
          )}
        </Button>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
        <Card className="p-6">
          <div className="flex items-center gap-4">
            <div className="p-3 rounded-lg bg-primary/10">
              <Search className="h-6 w-6 text-primary" />
            </div>
            <div>
              <p className="text-2xl font-bold text-foreground">{totalScans}</p>
              <p className="text-sm text-muted-foreground">Total Scans</p>
            </div>
          </div>
        </Card>

        <Card className="p-6">
          <div className="flex items-center gap-4">
            <div className="p-3 rounded-lg bg-primary/10">
              <Clock className="h-6 w-6 text-primary" />
            </div>
            <div>
              <p className="text-2xl font-bold text-foreground">{avgScanTime > 0 ? `${Math.floor(avgScanTime/60)}m ${avgScanTime%60}s` : 'N/A'}</p>
              <p className="text-sm text-muted-foreground">Avg. Scan Time</p>
            </div>
          </div>
        </Card>

        <Card className="p-6">
          <div className="flex items-center gap-4">
            <div className="p-3 rounded-lg bg-destructive/10">
              <Search className="h-6 w-6 text-destructive" />
            </div>
            <div>
              <p className="text-2xl font-bold text-foreground">{threatsFound}</p>
              <p className="text-sm text-muted-foreground">Threats Found</p>
            </div>
          </div>
        </Card>
      </div>

      <Card>
        <div className="p-6 border-b border-border">
          <h3 className="text-lg font-semibold text-foreground">Scan History</h3>
        </div>
        <Table>
          <TableHeader>
            <TableRow>
              <TableHead>Scan Type</TableHead>
              <TableHead>Date & Time</TableHead>
              <TableHead>Duration</TableHead>
              <TableHead>Files Scanned</TableHead>
              <TableHead>Threats Found</TableHead>
              <TableHead>Status</TableHead>
            </TableRow>
          </TableHeader>
          <TableBody>
            {scanHistory.length > 0 ? (
              scanHistory.map((scan) => (
                <TableRow key={scan.id}>
                  <TableCell className="font-medium">{scan.type}</TableCell>
                  <TableCell>{scan.date}</TableCell>
                  <TableCell>{scan.duration}</TableCell>
                  <TableCell>{scan.filesScanned.toLocaleString()}</TableCell>
                  <TableCell>
                    <span className={scan.threatsFound > 0 ? "text-destructive font-medium" : ""}>
                      {scan.threatsFound}
                    </span>
                  </TableCell>
                  <TableCell>
                    <Badge variant="outline" className="capitalize">
                      {scan.status}
                    </Badge>
                  </TableCell>
                </TableRow>
              ))
            ) : (
              <TableRow>
                <TableCell colSpan={6} className="text-center text-muted-foreground">
                  No scan results available
                </TableCell>
              </TableRow>
            )}
          </TableBody>
        </Table>
      </Card>
    </div>
  );
}
