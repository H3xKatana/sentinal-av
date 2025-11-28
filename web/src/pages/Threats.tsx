import { AlertTriangle, Shield, Archive, Loader2 } from "lucide-react";
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
import { useQuery } from "@tanstack/react-query";
import { apiService, Threat } from "@/services/api";

const getSeverityVariant = (severity: string) => {
  switch (severity) {
    case "critical":
    case "high":
      return "destructive";
    case "medium":
      return "default";
    case "low":
      return "secondary";
    default:
      return "outline";
  }
};

export default function Threats() {
  // Fetch threats
  const { data: threats, isLoading, error } = useQuery({
    queryKey: ['threats'],
    queryFn: () => apiService.getThreats(),
    staleTime: 60000, // 1 minute
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
  const totalThreats = threats?.length || 0;
  const quarantined = threats?.filter((threat: any) => threat.action_taken === "quarantined").length || 0;
  const deleted = threats?.filter((threat: any) => threat.action_taken === "deleted").length || 0;

  return (
    <div className="space-y-6">
      <div>
        <h2 className="text-3xl font-bold text-foreground mb-2">Threat Management</h2>
        <p className="text-muted-foreground">Monitor and manage detected threats</p>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
        <Card className="p-6">
          <div className="flex items-center gap-4">
            <div className="p-3 rounded-lg bg-destructive/10">
              <AlertTriangle className="h-6 w-6 text-destructive" />
            </div>
            <div>
              <p className="text-2xl font-bold text-foreground">{totalThreats}</p>
              <p className="text-sm text-muted-foreground">Total Threats</p>
            </div>
          </div>
        </Card>

        <Card className="p-6">
          <div className="flex items-center gap-4">
            <div className="p-3 rounded-lg bg-primary/10">
              <Shield className="h-6 w-6 text-primary" />
            </div>
            <div>
              <p className="text-2xl font-bold text-foreground">{quarantined}</p>
              <p className="text-sm text-muted-foreground">Quarantined</p>
            </div>
          </div>
        </Card>

        <Card className="p-6">
          <div className="flex items-center gap-4">
            <div className="p-3 rounded-lg bg-primary/10">
              <Archive className="h-6 w-6 text-primary" />
            </div>
            <div>
              <p className="text-2xl font-bold text-foreground">{deleted}</p>
              <p className="text-sm text-muted-foreground">Deleted</p>
            </div>
          </div>
        </Card>
      </div>

      <Card>
        <div className="p-6 border-b border-border flex items-center justify-between">
          <div>
            <h3 className="text-lg font-semibold text-foreground">Detected Threats</h3>
            <p className="text-sm text-muted-foreground mt-1">Recent threats detected by the system</p>
          </div>
          <Button variant="outline" size="sm">Clear All Quarantined</Button>
        </div>
        <Table>
          <TableHeader>
            <TableRow>
              <TableHead>Threat Name</TableHead>
              <TableHead>File Path</TableHead>
              <TableHead>Severity</TableHead>
              <TableHead>Detected</TableHead>
              <TableHead>Status</TableHead>
              <TableHead>Actions</TableHead>
            </TableRow>
          </TableHeader>
          <TableBody>
            {threats && threats.length > 0 ? (
              threats.map((threat: any) => (
                <TableRow key={threat.id}>
                  <TableCell className="font-medium">{threat.threat_name || threat.name || 'Unknown'}</TableCell>
                  <TableCell className="text-sm text-muted-foreground max-w-xs truncate">
                    {threat.file_path || threat.file || 'Unknown'}
                  </TableCell>
                  <TableCell>
                    <Badge variant={getSeverityVariant(threat.severity)} className="capitalize">
                      {threat.severity}
                    </Badge>
                  </TableCell>
                  <TableCell className="text-sm">
                    {threat.created_at ? new Date(threat.created_at).toLocaleString() : 'N/A'}
                  </TableCell>
                  <TableCell>
                    <Badge variant="outline" className="capitalize">
                      {threat.action_taken || threat.status || 'detected'}
                    </Badge>
                  </TableCell>
                  <TableCell>
                    <Button variant="ghost" size="sm">
                      Remove
                    </Button>
                  </TableCell>
                </TableRow>
              ))
            ) : (
              <TableRow>
                <TableCell colSpan={6} className="text-center text-muted-foreground">
                  No threats detected
                </TableCell>
              </TableRow>
            )}
          </TableBody>
        </Table>
      </Card>
    </div>
  );
}
