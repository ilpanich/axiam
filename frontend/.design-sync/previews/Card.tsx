import {
  Button,
  Card,
  CardContent,
  CardDescription,
  CardFooter,
  CardHeader,
  CardTitle,
  InfoRow,
} from "frontend";

export const Basic = () => (
  <Card className="max-w-md">
    <CardHeader>
      <CardTitle>Production tenant</CardTitle>
      <CardDescription>
        Isolated realm for the acme-prod workloads.
      </CardDescription>
    </CardHeader>
    <CardContent>
      <p className="text-sm text-foreground/80">
        1,284 users · 37 roles · 12 service accounts
      </p>
    </CardContent>
  </Card>
);

export const WithFooter = () => (
  <Card className="max-w-md">
    <CardHeader>
      <CardTitle>Signing CA</CardTitle>
      <CardDescription>
        Ed25519 · expires 14 Mar 2027
      </CardDescription>
    </CardHeader>
    <CardContent className="space-y-1">
      <InfoRow label="Issuer">CN=AXIAM Root CA</InfoRow>
      <InfoRow label="Serial">3f:a9:1c:04:8b:e2</InfoRow>
    </CardContent>
    <CardFooter className="gap-2">
      <Button size="sm">Rotate</Button>
      <Button size="sm" variant="outline">
        Download chain
      </Button>
    </CardFooter>
  </Card>
);

export const Stat = () => (
  <Card className="max-w-xs">
    <CardHeader className="pb-2">
      <CardDescription>Active sessions</CardDescription>
      <CardTitle className="text-3xl text-primary">2,481</CardTitle>
    </CardHeader>
    <CardContent>
      <p className="text-xs text-muted-foreground">+12% vs. last hour</p>
    </CardContent>
  </Card>
);
