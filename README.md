# User registry

User registry (`user-registry`) is a web application API that is developed using Flask. This API is used as the backend for user registration and the tasks related to user accounts. The current authentication method is JSON Web Token (JWT). During authentication, the user information is self-managed and received by the API client.

## User data collection

Flask database tables are used to create tables of user registry data that is entered. Review the following database tables created for the user registry:

### User

A table list of user data where the following parameter values are stored:

  * `id`: The user ID name. Required
  * `phone_number`: User preferred number. Optional
  * `email`: User email address. Required
  * `password`: Hash pasword for the user. Required
<!--from Ted how is the valid token defined?-->
  * `token_required`: Unique access token generated after a user is created
  * Discoverable fields for the user (`geoID`, `boundaries`, `polygon`, etc.)

### DomainCheck

A table list of allowed and blocked domains where the following parameter values are stored:

  * `id`: The user ID name. Required
  * `belongs_to`: List of domains that are allowed or blocked. When the value is set to `0`, it means that the domain is allowed. When the value is set to `1`, it means that the domain is blocked.
  * `domains`: List of domain services. For example, `gmail.com` or `hotmail.com` are stored in this parameter.
  
## API Endpoints

View the following list of user registry API Endpoints
  
* /signup: Verifies if the JSON data that contains the email, password, and phone number matches with the information in the `DomainChecks` database table. 
    
  If the domain is block, you receive status code 401 with the following message: `You are not allowed to register.`
    
  If you enter an existing email, you a receive status code 202 with the following message: `User already exists. Please log in`

* /update: Use this endpoint to update user account information. Currently, you can only update your phone number. 

* /login: Verifies if users exist by checking the JSON data. 

  If the user account does not exist, you receive the following message: `User does not exist`.
  
  If the user account does exist, the password is verified. If the passwords do not match, you receive the following message: `Wrong password`.
  
* /logout: Log out users.

* /authority-token: Gets the authority token for a domain. 

## Signing up

Create a user account by selecting the **Sign up** link at the end of the _Login_ dialog box. The _Sign up now_ form appears. 
