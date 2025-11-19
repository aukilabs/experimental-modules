import AukilabsExpoAuthenticationModule from "@aukilabs/expo-authentication";
import { useEffect, useState } from "react";
import {
  Button,
  SafeAreaView,
  ScrollView,
  Text,
  TextInput,
  TouchableOpacity,
  View,
} from "react-native";

type CredentialType = "email" | "appkey" | "token";

export default function App() {
  const [credentialType, setCredentialType] = useState<CredentialType>("email");

  // Email credentials
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");

  // App key credentials
  const [appKey, setAppKey] = useState("");
  const [appSecret, setAppSecret] = useState("");

  // Token credentials
  const [token, setToken] = useState("");
  const [tokenRefreshToken, setTokenRefreshToken] = useState("");
  const [expiresAt, setExpiresAt] = useState("");
  const [refreshTokenExpiresAt, setRefreshTokenExpiresAt] = useState("");
  const [oidcClientId, setOidcClientId] = useState("");

  // Configuration
  const [apiUrl, setApiUrl] = useState("https://api.dev.aukiverse.com");
  const [refreshUrl, setRefreshUrl] = useState("https://api.dev.aukiverse.com/user/refresh");
  const [ddsUrl, setDdsUrl] = useState("https://dds.dev.aukiverse.com");
  const [clientId, setClientId] = useState("expo-example");

  // Domain ID
  const [domainId, setDomainId] = useState("");

  // Result state
  const [result, setResult] = useState<string>("");
  const [isLoading, setIsLoading] = useState(false);
  const [clientCreated, setClientCreated] = useState(false);

  // Token state
  const [networkToken, setNetworkToken] = useState<{
    token: string;
    refreshToken: string;
    expiresAt: number;
  } | null>(null);
  const [discoveryToken, setDiscoveryToken] = useState<{
    token: string;
    expiresAt: number;
  } | null>(null);
  const [domainAccessToken, setDomainAccessToken] = useState<{
    token: string;
    expiresAt: number;
    domainId: string;
    domainName: string;
  } | null>(null);

  // Set up event listeners
  useEffect(() => {
    const refreshFailedSub = AukilabsExpoAuthenticationModule.addListener(
      "onRefreshFailed",
      (event) => {
        console.log(
          `Token refresh failed: ${event.tokenType} - ${event.reason}`
        );
        setResult(
          `❌ Token Refresh Failed\n\n${event.tokenType.toUpperCase()} token refresh failed\nReason: ${event.reason}${event.requiresReauth ? "\n\n⚠️ Re-authentication required - please authenticate again" : ""}`
        );
        setIsLoading(false);

        if (event.requiresReauth) {
          // User needs to re-authenticate
          // In a real app, you might show a login screen here
        }
      }
    );

    const domainAccessDeniedSub = AukilabsExpoAuthenticationModule.addListener(
      "onDomainAccessDenied",
      (event) => {
        console.log(
          `Domain access denied: ${event.domainId} - Status ${event.statusCode} - ${event.reason}`
        );
        setResult(
          `❌ Domain Access Denied\n\nDomain ID: ${event.domainId}\nStatus Code: ${event.statusCode}\nReason: ${event.reason}\n\n${event.statusCode === 402 ? "💰 Payment Required: This domain requires payment to access." : ""}`
        );
        setIsLoading(false);
      }
    );

    return () => {
      refreshFailedSub.remove();
      domainAccessDeniedSub.remove();
    };
  }, []);

  const handleAuthenticate = async () => {
    setIsLoading(true);
    setResult("");

    try {
      // Prepare credentials based on type
      let credentials: any;
      if (credentialType === "email") {
        if (!email || !password) {
          setResult("Error: Email and password are required");
          setIsLoading(false);
          return;
        }
        credentials = {
          type: "email",
          email,
          password,
        };
      } else if (credentialType === "appkey") {
        if (!appKey || !appSecret) {
          setResult("Error: App key and app secret are required");
          setIsLoading(false);
          return;
        }
        credentials = {
          type: "appKey",
          appKey,
          appSecret,
        };
      } else {
        if (!token || !expiresAt) {
          setResult("Error: Token and expiry are required");
          setIsLoading(false);
          return;
        }
        credentials = {
          type: "opaque",
          token,
          refreshToken: tokenRefreshToken || undefined,
          expiryMs: parseInt(expiresAt, 10),
          refreshTokenExpiryMs: refreshTokenExpiresAt ? parseInt(refreshTokenExpiresAt, 10) : undefined,
          oidcClientId: oidcClientId || undefined,
        };
      }

      // Prepare config
      const config = {
        apiUrl,
        refreshUrl,
        ddsUrl,
        clientId,
      };

      // Only create client if it doesn't exist yet
      if (!clientCreated) {
        setResult("Creating client...");
        await AukilabsExpoAuthenticationModule.createClient(config);
        setClientCreated(true);
      }

      setResult("Checking authentication status...");

      // Check if already authenticated before calling authenticate()
      // authenticate() clears ALL tokens (including domain access), so we should avoid calling it unnecessarily
      const isAlreadyAuthenticated = AukilabsExpoAuthenticationModule.isAuthenticated();

      let networkToken;
      if (isAlreadyAuthenticated) {
        // Already authenticated - just get the existing network token
        networkToken = AukilabsExpoAuthenticationModule.getNetworkToken();
        setResult("✅ Already Authenticated!\n\nUsing existing network token.");
        console.log("Already authenticated, using existing token");
      } else {
        setResult("Authenticating...");

        // Authenticate with credentials (this will clear any existing tokens and authenticate as new user)
        networkToken = await AukilabsExpoAuthenticationModule.authenticate(credentials);

        setResult("✅ Authentication Successful!\n\nNetwork token received.");
        console.log("New authentication completed");
      }

      // Store network token
      setNetworkToken(networkToken);

      console.log("Network token:", networkToken ? `${networkToken.token.substring(0, 20)}...` : "None");
    } catch (error: any) {
      const errorMessage = error.message || String(error);
      setResult(`❌ Error: ${errorMessage}`);
      console.error("Authentication error:", error);
    } finally {
      setIsLoading(false);
    }
  };

  const handleGetDomainAccess = async () => {
    setIsLoading(true);
    setResult("");

    try {
      if (!domainId) {
        setResult("Error: Domain ID is required");
        setIsLoading(false);
        return;
      }

      if (!clientCreated) {
        setResult("Error: Please authenticate first");
        setIsLoading(false);
        return;
      }

      setResult("Getting domain access...");

      // Get domain access (this will automatically handle network and discovery auth)
      const domainAccess =
        await AukilabsExpoAuthenticationModule.getDomainAccess(domainId);

      // Format the result
      const resultText = `✅ Domain Access Granted!

Domain: ${domainAccess.name}
Domain ID: ${domainAccess.id}
Organization ID: ${domainAccess.organizationId}
Access Token: ${domainAccess.accessToken.substring(0, 20)}...
Expires At: ${new Date(domainAccess.expiresAt).toLocaleString()}

Server: ${domainAccess.domainServer.name}
Server URL: ${domainAccess.domainServer.url}
Server Status: ${domainAccess.domainServer.status}
Server Mode: ${domainAccess.domainServer.mode}
Cloud Region: ${domainAccess.domainServer.cloudRegion}`;

      setResult(resultText);

      // Check authentication status
      const isAuth = AukilabsExpoAuthenticationModule.isAuthenticated();
      console.log("Is authenticated:", isAuth);

      // Get and store tokens
      const networkTokenData =
        AukilabsExpoAuthenticationModule.getNetworkToken();
      const discoveryTokenData =
        AukilabsExpoAuthenticationModule.getDiscoveryToken();

      setNetworkToken(networkTokenData);
      setDiscoveryToken(discoveryTokenData);

      // Store domain access token
      setDomainAccessToken({
        token: domainAccess.accessToken,
        expiresAt: domainAccess.expiresAt,
        domainId: domainAccess.id,
        domainName: domainAccess.name,
      });

      console.log(
        "Network token:",
        networkTokenData
          ? `${networkTokenData.token.substring(0, 20)}...`
          : "None"
      );
      console.log(
        "Discovery token:",
        discoveryTokenData
          ? `${discoveryTokenData.token.substring(0, 20)}...`
          : "None"
      );
    } catch (error: any) {
      const errorMessage = error.message || String(error);
      setResult(`❌ Error: ${errorMessage}`);
      console.error("Authentication error:", error);
    } finally {
      setIsLoading(false);
    }
  };

  const handleClearClient = () => {
    try {
      AukilabsExpoAuthenticationModule.releaseClient();
      setClientCreated(false);
      setNetworkToken(null);
      setDiscoveryToken(null);
      setDomainAccessToken(null);
      setResult("Client released");
    } catch (error) {
      console.error("Error releasing client:", error);
    }
  };

  return (
    <SafeAreaView style={styles.container}>
      <ScrollView style={styles.scrollContainer}>
        <Text style={styles.header}>Auki Authentication</Text>

        {/* Credential Type Selector */}
        <Group name="Credential Type">
          <View style={styles.buttonRow}>
            <TouchableOpacity
              style={[
                styles.tabButton,
                credentialType === "email" && styles.tabButtonActive,
              ]}
              onPress={() => setCredentialType("email")}
            >
              <Text
                style={[
                  styles.tabButtonText,
                  credentialType === "email" && styles.tabButtonTextActive,
                ]}
              >
                Email
              </Text>
            </TouchableOpacity>
            <TouchableOpacity
              style={[
                styles.tabButton,
                credentialType === "appkey" && styles.tabButtonActive,
              ]}
              onPress={() => setCredentialType("appkey")}
            >
              <Text
                style={[
                  styles.tabButtonText,
                  credentialType === "appkey" && styles.tabButtonTextActive,
                ]}
              >
                App Key
              </Text>
            </TouchableOpacity>
            <TouchableOpacity
              style={[
                styles.tabButton,
                credentialType === "token" && styles.tabButtonActive,
              ]}
              onPress={() => setCredentialType("token")}
            >
              <Text
                style={[
                  styles.tabButtonText,
                  credentialType === "token" && styles.tabButtonTextActive,
                ]}
              >
                Token
              </Text>
            </TouchableOpacity>
          </View>
        </Group>

        {/* Credentials Input */}
        {credentialType === "email" && (
          <Group name="Email Credentials">
            <TextInput
              style={styles.input}
              placeholder="Email"
              value={email}
              onChangeText={setEmail}
              autoCapitalize="none"
              keyboardType="email-address"
            />
            <TextInput
              style={styles.input}
              placeholder="Password"
              value={password}
              onChangeText={setPassword}
              secureTextEntry
            />
          </Group>
        )}

        {credentialType === "appkey" && (
          <Group name="App Key Credentials">
            <TextInput
              style={styles.input}
              placeholder="App Key"
              value={appKey}
              onChangeText={setAppKey}
              autoCapitalize="none"
            />
            <TextInput
              style={styles.input}
              placeholder="App Secret"
              value={appSecret}
              onChangeText={setAppSecret}
              secureTextEntry
            />
          </Group>
        )}

        {credentialType === "token" && (
          <Group name="Token Credentials">
            <TextInput
              style={styles.input}
              placeholder="Opaque Token"
              value={token}
              onChangeText={setToken}
              multiline
              numberOfLines={3}
            />
            <TextInput
              style={styles.input}
              placeholder="Refresh Token (optional)"
              value={tokenRefreshToken}
              onChangeText={setTokenRefreshToken}
              multiline
              numberOfLines={2}
            />
            <TextInput
              style={styles.input}
              placeholder="Expires At (milliseconds)"
              value={expiresAt}
              onChangeText={setExpiresAt}
              keyboardType="numeric"
            />
            <TextInput
              style={styles.input}
              placeholder="Refresh Token Expires At (milliseconds, optional)"
              value={refreshTokenExpiresAt}
              onChangeText={setRefreshTokenExpiresAt}
              keyboardType="numeric"
            />
            <TextInput
              style={styles.input}
              placeholder="OIDC Client ID (optional, for OAuth refresh)"
              value={oidcClientId}
              onChangeText={setOidcClientId}
            />
          </Group>
        )}

        {/* Configuration */}
        <Group name="Configuration">
          <TextInput
            style={styles.input}
            placeholder="API URL"
            value={apiUrl}
            onChangeText={setApiUrl}
            autoCapitalize="none"
          />
          <TextInput
            style={styles.input}
            placeholder="Refresh URL"
            value={refreshUrl}
            onChangeText={setRefreshUrl}
            autoCapitalize="none"
          />
          <TextInput
            style={styles.input}
            placeholder="DDS URL"
            value={ddsUrl}
            onChangeText={setDdsUrl}
            autoCapitalize="none"
          />
          <TextInput
            style={styles.input}
            placeholder="Client ID"
            value={clientId}
            onChangeText={setClientId}
          />
        </Group>

        {/* Authentication */}
        <Group name="Authentication">
          <Button
            title={isLoading ? "Authenticating..." : "Authenticate"}
            onPress={handleAuthenticate}
            disabled={isLoading}
          />
          <View style={{ height: 8 }} />
          <Button
            title="Clear Client"
            onPress={handleClearClient}
            color="#666"
          />
        </Group>

        {/* Domain Access */}
        <Group name="Domain Access">
          <TextInput
            style={styles.input}
            placeholder="Domain ID"
            value={domainId}
            onChangeText={setDomainId}
          />
          <Button
            title={isLoading ? "Getting Access..." : "Get Domain Access"}
            onPress={handleGetDomainAccess}
            disabled={isLoading || !domainId || !clientCreated}
          />
        </Group>

        {/* Tokens */}
        {(networkToken || discoveryToken || domainAccessToken) && (
          <Group name="Tokens">
            {networkToken && (
              <View style={styles.tokenContainer}>
                <Text style={styles.tokenLabel}>Network Token</Text>
                <Text style={styles.tokenValue}>
                  {networkToken.token.substring(0, 30)}...
                </Text>
                <Text style={styles.tokenLabel}>Network Refresh Token</Text>
                <Text style={styles.tokenValue}>
                  {networkToken.refreshToken.substring(0, 30)}...
                </Text>
                <Text style={styles.tokenExpiry}>
                  Expires: {new Date(networkToken.expiresAt).toLocaleString()}
                </Text>
              </View>
            )}
            {discoveryToken && (
              <View style={styles.tokenContainer}>
                <Text style={styles.tokenLabel}>Discovery Token</Text>
                <Text style={styles.tokenValue}>
                  {discoveryToken.token.substring(0, 30)}...
                </Text>
                <Text style={styles.tokenExpiry}>
                  Expires: {new Date(discoveryToken.expiresAt).toLocaleString()}
                </Text>
              </View>
            )}
            {domainAccessToken && (
              <View style={styles.tokenContainer}>
                <Text style={styles.tokenLabel}>
                  Domain Access Token ({domainAccessToken.domainName})
                </Text>
                <Text style={styles.tokenValue}>
                  {domainAccessToken.token.substring(0, 30)}...
                </Text>
                <Text style={styles.tokenExpiry}>
                  Expires:{" "}
                  {new Date(domainAccessToken.expiresAt).toLocaleString()}
                </Text>
              </View>
            )}
          </Group>
        )}

        {/* Result */}
        {result && (
          <Group name="Result">
            <Text style={styles.resultText}>{result}</Text>
          </Group>
        )}
      </ScrollView>
    </SafeAreaView>
  );
}

function Group(props: { name: string; children: React.ReactNode }) {
  return (
    <View style={styles.group}>
      <Text style={styles.groupHeader}>{props.name}</Text>
      {props.children}
    </View>
  );
}

const styles = {
  container: {
    flex: 1,
    backgroundColor: "#f5f5f5",
  },
  scrollContainer: {
    flex: 1,
  },
  header: {
    fontSize: 28,
    fontWeight: "700" as const,
    margin: 20,
    marginBottom: 10,
    color: "#333",
  },
  group: {
    margin: 16,
    marginBottom: 20,
    backgroundColor: "#fff",
    borderRadius: 12,
    padding: 16,
    shadowColor: "#000",
    shadowOffset: { width: 0, height: 2 },
    shadowOpacity: 0.1,
    shadowRadius: 4,
    elevation: 3,
  },
  groupHeader: {
    fontSize: 16,
    fontWeight: "600" as const,
    marginBottom: 12,
    color: "#555",
  },
  input: {
    borderWidth: 1,
    borderColor: "#ddd",
    borderRadius: 8,
    padding: 12,
    marginBottom: 12,
    fontSize: 16,
    backgroundColor: "#fafafa",
  },
  buttonRow: {
    flexDirection: "row" as const,
    gap: 8,
  },
  tabButton: {
    flex: 1,
    paddingVertical: 10,
    paddingHorizontal: 16,
    borderRadius: 8,
    borderWidth: 1,
    borderColor: "#ddd",
    backgroundColor: "#fff",
    alignItems: "center" as const,
  },
  tabButtonActive: {
    backgroundColor: "#007AFF",
    borderColor: "#007AFF",
  },
  tabButtonText: {
    fontSize: 14,
    fontWeight: "500" as const,
    color: "#666",
  },
  tabButtonTextActive: {
    color: "#fff",
  },
  resultText: {
    fontSize: 14,
    color: "#333",
    lineHeight: 20,
  },
  tokenContainer: {
    marginBottom: 16,
    padding: 12,
    backgroundColor: "#f0f9ff",
    borderRadius: 8,
    borderWidth: 1,
    borderColor: "#bae6fd",
  },
  tokenLabel: {
    fontSize: 14,
    fontWeight: "600" as const,
    color: "#0369a1",
    marginBottom: 4,
  },
  tokenValue: {
    fontSize: 12,
    fontFamily: "monospace" as const,
    color: "#334155",
    marginBottom: 6,
  },
  tokenExpiry: {
    fontSize: 12,
    color: "#64748b",
  },
};
