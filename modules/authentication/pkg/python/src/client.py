"""
Auki Authentication Library - High-Level Async Client

This module provides a high-level async API that handles HTTP requests
and event processing internally. The underlying sans-I/O core is abstracted away.
"""

from __future__ import annotations
import json
from typing import Optional, Dict, Any, Callable, List
from dataclasses import dataclass
import httpx

from .bindings.authentication import (
    NativeClient,
    NativeConfig,
    NativeCredentials,
    current_time_ms,
    is_expired,
    is_near_expiry,
)


@dataclass
class Config:
    """Configuration for the authentication client"""
    api_url: str
    refresh_url: str
    dds_url: str
    client_id: str
    refresh_threshold_ms: int = 300_000  # 5 minutes


@dataclass
class Token:
    """Token information"""
    token: str
    expires_at: int


@dataclass
class DomainServer:
    """Domain server information"""
    id: str
    organization_id: str
    name: str
    url: str
    version: str
    status: str
    mode: str
    variants: List[str]
    ip: str
    latitude: float
    longitude: float
    cloud_region: str


@dataclass
class DomainAccess:
    """Domain access information"""
    id: str
    name: str
    organization_id: str
    domain_server_id: str
    access_token: str
    expires_at: int
    domain_server: DomainServer
    owner_wallet_address: str


class AuthenticationError(Exception):
    """Authentication error"""
    def __init__(self, message: str, retryable: bool = False):
        super().__init__(message)
        self.retryable = retryable


class Client:
    """
    Authentication client for the Auki Network

    This client provides a high-level async API that handles HTTP requests
    and event processing internally. The underlying sans-I/O core is abstracted away.

    Example:
        ```python
        import asyncio
        from auki_authentication import Client, Config

        async def main():
            config = Config(
                api_url='https://api.aukiverse.com',
                refresh_url='https://api.aukiverse.com/user/refresh',
                dds_url='https://dds.posemesh.org',
                client_id='my-app'
            )

            credentials = {
                'type': 'email',
                'email': 'user@example.com',
                'password': 'secret'
            }

            async with Client(config, credentials) as client:
                # Get domain access - automatically handles full authentication chain!
                domain_access = await client.get_domain_access('my-domain-id')
                print(f'Connected to: {domain_access.domain_server.url}')

        asyncio.run(main())
        ```
    """

    def __init__(self, config: Config, credentials: Optional[Dict[str, Any]] = None):
        """
        Create a new authentication client

        Args:
            config: Client configuration
            credentials: Optional user credentials dict with 'type' key ('email', 'app_key', or 'opaque')
                       Can be set later with set_credentials()
        """
        self.config = config
        self._refresh_failed_callback: Optional[Callable] = None
        self._domain_access_denied_callback: Optional[Callable] = None
        self._http_client: Optional[httpx.AsyncClient] = None

        # Convert config to native format
        native_config = NativeConfig(
            api_url=config.api_url,
            refresh_url=config.refresh_url,
            dds_url=config.dds_url,
            client_id=config.client_id,
            refresh_threshold_ms=config.refresh_threshold_ms
        )

        self._inner = NativeClient(native_config)

        # Set credentials if provided
        if credentials:
            self.set_credentials(credentials)

    @classmethod
    def from_state(cls, state_json: str, config: Config) -> 'Client':
        """
        Create a client from saved state (without credentials)

        Args:
            state_json: Saved state as JSON string
            config: Client configuration
        """
        client = object.__new__(cls)
        client.config = config
        client._refresh_failed_callback = None
        client._http_client = None

        native_config = NativeConfig(
            api_url=config.api_url,
            refresh_url=config.refresh_url,
            dds_url=config.dds_url,
            client_id=config.client_id,
            refresh_threshold_ms=config.refresh_threshold_ms
        )

        client._inner = NativeClient.from_state(state_json, native_config)
        return client

    def set_credentials(self, credentials: Dict[str, Any]) -> None:
        """
        Set credentials for the client

        Args:
            credentials: User credentials dict with 'type' key ('email', 'app_key', or 'opaque')
        """
        # Convert credentials to native format
        cred_type = credentials.get('type')
        if cred_type == 'email':
            native_creds = NativeCredentials.EMAIL_PASSWORD(
                email=credentials['email'],
                password=credentials['password']
            )
        elif cred_type == 'app_key':
            native_creds = NativeCredentials.APP_KEY(
                app_key=credentials['app_key'],
                app_secret=credentials['app_secret']
            )
        elif cred_type == 'opaque':
            native_creds = NativeCredentials.OPAQUE(
                token=credentials['token'],
                refresh_token=credentials.get('refresh_token'),
                expiry_ms=credentials['expiry_ms'],
                refresh_token_expiry_ms=credentials.get('refresh_token_expiry_ms'),
                oidc_client_id=credentials.get('oidc_client_id')
            )
        else:
            raise ValueError(f"Unknown credential type: {cred_type}")

        self._inner.set_credentials(native_creds)

    def has_credentials(self) -> bool:
        """Check if the client has credentials set"""
        return self._inner.has_credentials()

    async def __aenter__(self):
        """Async context manager entry"""
        self._http_client = httpx.AsyncClient()
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        """Async context manager exit"""
        if self._http_client:
            await self._http_client.aclose()
            self._http_client = None

    async def _execute_actions(self, actions_json: str) -> List[Dict[str, Any]]:
        """
        Execute actions returned by the core client and process events

        Args:
            actions_json: JSON string of actions to execute

        Returns:
            List of events generated from executing the actions
        """
        actions = json.loads(actions_json)
        events = []

        if not self._http_client:
            self._http_client = httpx.AsyncClient()

        for action in actions:
            if action['type'] == 'HttpRequest':
                try:
                    response = await self._http_client.request(
                        method=action['method'],
                        url=action['url'],
                        headers=action.get('headers', {}),
                        content=action.get('body')
                    )

                    response_events_json = self._inner.handle_response(
                        response.status_code,
                        response.text
                    )
                    response_events = json.loads(response_events_json)
                    events.extend(response_events)

                    # Check for events and trigger callbacks
                    for event in response_events:
                        if event['type'] == 'NetworkTokenRefreshFailed' and self._refresh_failed_callback:
                            self._refresh_failed_callback({
                                'token_type': 'network',
                                'reason': event['reason'],
                                'requires_reauth': event['requires_reauth']
                            })
                        elif event['type'] == 'DiscoveryAuthFailed' and self._refresh_failed_callback:
                            self._refresh_failed_callback({
                                'token_type': 'discovery',
                                'reason': event['reason'],
                                'requires_reauth': True
                            })
                        elif event['type'] == 'DomainAccessDenied' and self._domain_access_denied_callback:
                            # Extract status code from reason (format: "HTTP XXX: ...")
                            import re
                            status_match = re.search(r'HTTP (\d+):', event['reason'])
                            status_code = int(status_match.group(1)) if status_match else 0
                            self._domain_access_denied_callback({
                                'domain_id': event['domain_id'],
                                'reason': event['reason'],
                                'status_code': status_code
                            })

                except Exception as e:
                    raise AuthenticationError(
                        f"HTTP request failed: {str(e)}",
                        retryable=True
                    )

            elif action['type'] == 'Wait':
                import asyncio
                await asyncio.sleep(action['duration_ms'] / 1000.0)

        return events

    def on_refresh_failed(self, callback: Callable[[Dict[str, Any]], None]):
        """
        Set a callback to be called when token refresh fails

        Args:
            callback: Function to call when refresh fails

        Example:
            ```python
            def handle_refresh_failure(info):
                print(f"{info['token_type']} token refresh failed: {info['reason']}")
                if info['requires_reauth']:
                    # Need to re-authenticate
                    asyncio.create_task(client.authenticate())

            client.on_refresh_failed(handle_refresh_failure)
            ```
        """
        self._refresh_failed_callback = callback

    def on_domain_access_denied(self, callback: Callable[[Dict[str, Any]], None]):
        """
        Set a callback to be called when domain access is denied

        Args:
            callback: Function to call with domain access denied info dict containing:
                - domain_id: The domain ID that was denied
                - reason: Reason for denial
                - status_code: HTTP status code (e.g., 402 for payment required)

        Example:
            ```python
            def handle_denied(info):
                print(f"Domain {info['domain_id']} denied: {info['reason']}")
                if info['status_code'] == 402:
                    # Payment required
                    show_payment_dialog(info['domain_id'])

            client.on_domain_access_denied(handle_denied)
            ```
        """
        self._domain_access_denied_callback = callback

    async def authenticate_with(self, credentials: Dict[str, Any]) -> Token:
        """
        Authenticate with specific credentials
        This will clear all existing tokens and authenticate as a new user

        Args:
            credentials: User credentials dict with 'type' key ('email', 'app_key', or 'opaque')

        Returns:
            Network token information

        Raises:
            AuthenticationError: If authentication fails
        """
        # Convert credentials to native format
        cred_type = credentials.get('type')
        if cred_type == 'email':
            native_creds = NativeCredentials.EMAIL_PASSWORD(
                email=credentials['email'],
                password=credentials['password']
            )
        elif cred_type == 'app_key':
            native_creds = NativeCredentials.APP_KEY(
                app_key=credentials['app_key'],
                app_secret=credentials['app_secret']
            )
        elif cred_type == 'opaque':
            native_creds = NativeCredentials.OPAQUE(
                token=credentials['token'],
                refresh_token=credentials.get('refresh_token'),
                expiry_ms=credentials['expiry_ms'],
                refresh_token_expiry_ms=credentials.get('refresh_token_expiry_ms'),
                oidc_client_id=credentials.get('oidc_client_id')
            )
        else:
            raise ValueError(f"Unknown credential type: {cred_type}")

        now = current_time_ms()
        actions_json = self._inner.authenticate_with(native_creds, now)
        events = await self._execute_actions(actions_json)

        for event in events:
            if event['type'] == 'NetworkAuthSuccess':
                return Token(
                    token=event['token'],
                    expires_at=event['expires_at']
                )
            elif event['type'] == 'NetworkAuthFailed':
                raise AuthenticationError(
                    event['reason'],
                    retryable=event.get('retry_possible', False)
                )

        raise AuthenticationError('Authentication failed: No response')

    async def switch_user(self, credentials: Dict[str, Any]) -> Token:
        """
        Switch to a different user
        Alias for authenticate_with() - clears existing state and authenticates as new user

        Args:
            credentials: User credentials dict with 'type' key ('email', 'app_key', or 'opaque')

        Returns:
            Network token information

        Raises:
            AuthenticationError: If authentication fails
        """
        return await self.authenticate_with(credentials)

    async def authenticate(self) -> Token:
        """
        Authenticate to the Auki network

        Returns:
            Network token information

        Raises:
            AuthenticationError: If authentication fails
        """
        now = current_time_ms()
        actions_json = self._inner.authenticate(now)
        events = await self._execute_actions(actions_json)

        for event in events:
            if event['type'] == 'NetworkAuthSuccess':
                return Token(
                    token=event['token'],
                    expires_at=event['expires_at']
                )
            elif event['type'] == 'NetworkAuthFailed':
                raise AuthenticationError(
                    event['reason'],
                    retryable=event.get('retry_possible', False)
                )

        raise AuthenticationError('Authentication failed: No response')

    async def authenticate_discovery(self) -> Token:
        """
        Authenticate to the Discovery service
        Requires prior network authentication

        Returns:
            Discovery token information

        Raises:
            AuthenticationError: If authentication fails
        """
        now = current_time_ms()
        actions_json = self._inner.authenticate_discovery(now)
        events = await self._execute_actions(actions_json)

        for event in events:
            if event['type'] == 'DiscoveryAuthSuccess':
                return Token(
                    token=event['token'],
                    expires_at=event['expires_at']
                )
            elif event['type'] == 'DiscoveryAuthFailed':
                raise AuthenticationError(event['reason'])

        raise AuthenticationError('Discovery authentication failed: No response')

    async def get_domain_access(self, domain_id: str) -> DomainAccess:
        """
        Get access to a specific domain

        Automatically handles the full authentication chain if needed:
        - Authenticates to network if not already authenticated
        - Authenticates to discovery service if needed
        - Requests domain access

        Args:
            domain_id: The ID of the domain to access

        Returns:
            Domain access information including access token

        Raises:
            AuthenticationError: If any step fails
        """
        # The sans-I/O core can only return actions based on current state.
        # We need to keep calling get_domain_access() and processing responses
        # until we get the DomainAccessGranted event (may take 1-3 iterations
        # depending on whether network/discovery auth is needed).
        max_iterations = 10  # Safety limit

        for iteration in range(max_iterations):
            now = current_time_ms()
            actions_json = self._inner.get_domain_access(domain_id, now)
            actions = json.loads(actions_json)

            # If no actions returned, check if we already have cached access
            if not actions:
                cached_access = self.get_cached_domain_access(domain_id)
                if cached_access:
                    return cached_access
                raise AuthenticationError('Domain access failed: No actions and no cached access')

            # Execute the actions and collect events
            events = await self._execute_actions(actions_json)

            # Check for any authentication failures
            for event in events:
                if event['type'] == 'NetworkAuthFailed':
                    raise AuthenticationError(
                        event['reason'],
                        retryable=event.get('retry_possible', False)
                    )
                elif event['type'] == 'DiscoveryAuthFailed':
                    raise AuthenticationError(f"Discovery authentication failed: {event['reason']}")
                elif event['type'] == 'DomainAccessDenied':
                    raise AuthenticationError(f"Domain access denied: {event['reason']}")

            # Check if we got the domain access
            for event in events:
                if event['type'] == 'DomainAccessGranted':
                    domain_data = event['domain']
                    server_data = domain_data['domain_server']

                    return DomainAccess(
                        id=domain_data['id'],
                        name=domain_data['name'],
                        organization_id=domain_data['organization_id'],
                        domain_server_id=domain_data['domain_server_id'],
                        access_token=domain_data['access_token'],
                        expires_at=domain_data['expires_at'],
                        domain_server=DomainServer(
                            id=server_data['id'],
                            organization_id=server_data['organization_id'],
                            name=server_data['name'],
                            url=server_data['url'],
                            version=server_data['version'],
                            status=server_data['status'],
                            mode=server_data['mode'],
                            variants=server_data['variants'],
                            ip=server_data['ip'],
                            latitude=server_data['latitude'],
                            longitude=server_data['longitude'],
                            cloud_region=server_data['cloud_region']
                        ),
                        owner_wallet_address=domain_data['owner_wallet_address']
                    )

            # Continue to next iteration - the core will return the next required action

        raise AuthenticationError('Domain access failed: Maximum iterations exceeded')

    def is_authenticated(self) -> bool:
        """Check if the client is authenticated"""
        now = current_time_ms()
        return self._inner.is_authenticated(now)

    def get_network_token(self) -> Optional[Token]:
        """Get the network token if available"""
        token_json = self._inner.network_token()
        if token_json is None:
            return None
        token_data = json.loads(token_json)
        return Token(
            token=token_data['token'],
            expires_at=token_data['expires_at']
        )

    def get_discovery_token(self) -> Optional[Token]:
        """Get the discovery token if available"""
        token_json = self._inner.discovery_token()
        if token_json is None:
            return None
        token_data = json.loads(token_json)
        return Token(
            token=token_data['token'],
            expires_at=token_data['expires_at']
        )

    def get_cached_domain_access(self, domain_id: str) -> Optional[DomainAccess]:
        """
        Get cached domain access information if available

        Args:
            domain_id: The domain ID to query
        """
        access_json = self._inner.domain_access(domain_id)
        if access_json is None:
            return None

        domain_data = json.loads(access_json)
        server_data = domain_data['domain_server']

        return DomainAccess(
            id=domain_data['id'],
            name=domain_data['name'],
            organization_id=domain_data['organization_id'],
            domain_server_id=domain_data['domain_server_id'],
            access_token=domain_data['access_token'],
            expires_at=domain_data['expires_at'],
            domain_server=DomainServer(
                id=server_data['id'],
                organization_id=server_data['organization_id'],
                name=server_data['name'],
                url=server_data['url'],
                version=server_data['version'],
                status=server_data['status'],
                mode=server_data['mode'],
                variants=server_data['variants'],
                ip=server_data['ip'],
                latitude=server_data['latitude'],
                longitude=server_data['longitude'],
                cloud_region=server_data['cloud_region']
            ),
            owner_wallet_address=domain_data['owner_wallet_address']
        )

    def save_state(self) -> str:
        """
        Save the current state to JSON
        Note: Credentials are not included in the saved state
        """
        return self._inner.save_state()

    def force_reauth(self):
        """Force re-authentication (invalidate all tokens)"""
        self._inner.force_reauth()

    def validate_state(self):
        """
        Validate state after loading from storage
        Clears any expired tokens
        """
        now = current_time_ms()
        self._inner.validate_state(now)


# Re-export utility functions
__all__ = [
    'Client',
    'Config',
    'Token',
    'DomainAccess',
    'DomainServer',
    'AuthenticationError',
    'current_time_ms',
    'is_expired',
    'is_near_expiry',
]
