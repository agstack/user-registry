# User registry

User registry (`user-registry`) is a web application API developed using Flask. This API is used as the backend for user registration and tasks related to user accounts. The authentication method is JSON Web Token (JWT), and user information is self‑managed and provided by the API client.

## User data collection

Flask database models are used to create and store user registry data. The main database tables are:

### User

A table containing the following user information:

* `id`: Unique user ID. **Required**
* `phone_number`: User phone number. **Optional**
* `email`: User email address. **Required**
* `password`: Hashed password for authentication. **Required**
* `token_required`: Unique access token generated when the user is created.
* Additional discoverable user fields such as `geoID`, `boundaries`, `polygon`, etc.

### DomainCheck

A table containing allowed and blocked email domains:

* `id`: Unique ID. **Required**
* `belongs_to`: Indicates domain permission. `0` = allowed, `1` = blocked.
* `domains`: Domain names such as `gmail.com`, `hotmail.com`, etc.

## API Endpoints

List of user registry API endpoints:

### **/signup**

Verifies user details (email, password, phone number) and checks them against `DomainChecks`.

* If the domain is blocked → **401**: `You are not allowed to register.`
* If the email already exists → **202**: `User already exists. Please log in.`

### **/update**

Used to update user details. Currently allows updating **phone number only**.

### **/login**

Validates user login credentials.

* If user does not exist → `User does not exist`
* If password does not match → `Wrong password`

### **/logout**

Logs out the user.

### **/authority-token**

Returns the authority token for the provided domain.

## Signing up

To create a new user account, select **Sign up** on the Login screen. The **Sign up now** form will appear where the user can enter their details.

## Example Authentication Requests

## Token Refresh

If an access token expires during login-required operations, the client must use the refresh flow to obtain a new access token without requiring user credentials again.

### **When Does a Token Expire?**

Access tokens have a short lifespan for security. When expired, protected endpoints will return an error such as:

```json
{
  "message": "Invalid token: Signature has expired"
}
```

In this situation, proceed immediately to the **Refresh Token** request.

### **Refresh Access Token**

* **Endpoint:** `GET https://user-registry.agstack.org/refresh`
* **Cookie Required:** `refresh_token_cookie`

**Request:**

```bash
curl -X GET https://user-registry.agstack.org/refresh \
  --cookie "refresh_token_cookie=YOUR_LONG_LIVED_REFRESH_TOKEN"
```

**Example Response:**

```json
{
  "access_token": "YOUR_NEWLY_GENERATED_ACCESS_TOKEN"
}
```

### **Expired Token Example**

If you attempt an authenticated request with an expired access token, you may receive:

```json
{
  "message": "Invalid token: Signature has expired"
}
```

At this point, use the **Refresh Access Token** endpoint above.

### **Login Request**

```bash
curl -X POST https://user-registry.agstack.org/login \
  -H "Content-Type: application/json" \
  -H "X-FROM-ASSET-REGISTRY: True" \
  -d '{"email": "test@gmail.com", "password": "Test@12345"}'
```

**Response:**

```json
{
  "access_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "refresh_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."
}
```

### **Refresh Token Request**

```bash
curl -X GET https://user-registry.agstack.org/refresh \
  --cookie "refresh_token_cookie=<REFRESH_TOKEN_HERE>"
```

**Response:**

```json
{
  "access_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."
}
```
