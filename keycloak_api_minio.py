import requests
import json
from termcolor import colored

class JWTToken:
    def __init__(self, data, adminRealm, hostname) -> None:
        self.mydata = data
        self.myrealm = adminRealm
        self.hostname = hostname
        self.token_endpoint = f"http://{self.hostname}/realms/{self.myrealm}/protocol/openid-connect/token"
    
    # get JWT token
    def get_token(self):
        response = requests.post(self.token_endpoint, self.mydata) # keycloak JWT token
        
        if response.status_code == 200:
            return response.json()
        else:
            print(f"Post Keycloak token endpoint failed with status code {response.status_code}")
            print(response.text)
            return None

        '''
        try:
            response = requests.post(self.token_endpoint, self.mydata) # keycloak JWT token
            response.raise_for_status()
            return response.json()
        except requests.exceptions.RequestException as e:
            print(f"Post Keycloak token endpoint failed with status code: {str(e)}")
            return None
        '''
    
    # check endpoint JSON format
    def get_enpointJSON(self, endpoint):
        # print_colored_json(self.get_token())
        access_token = self.get_token().get("access_token")
        headers = {
            "Authorization": f"Bearer {access_token}",
            "Content-Type": "application/json"
        }

        response = requests.get(endpoint, headers=headers)

        if response.status_code == 200:
            return response.json()
        else:
            print(f"Failed to get endpoint JSON: {response.status_code}")
            print(response.text)

class KeycloakMinio(JWTToken):
    def __init__(self, data, adminRealm, hostname, minioRealm, minioClient, minioUser) -> None:
        super().__init__(data, adminRealm, hostname)
        self.minioRealm = minioRealm
        self.minioClient = minioClient
        self.minioUser = minioUser
        self.jwt_token = super().get_token()
        self.access_token = self.jwt_token.get("access_token")
    
    def get_headers(self):
        return {
            "Authorization": f"Bearer {self.access_token}",
            "Content-Type": "application/json"
        }

    def create_realm(self):
        realm_endpoint = f"http://{self.hostname}/admin/realms"

        realm_data = {
            "realm": self.minioRealm,
            "enabled": True
        }

        response = requests.post(realm_endpoint, headers=self.get_headers(), json=realm_data)

        if response.status_code == 201:
            print(f"Realm '{self.minioRealm}' created successfully.")
        else:
            print(f"Failed to create realm: {response.status_code}")
            print(response.text)
    
    def realm_SSL_setting(self):
        realm_endpoint = f"http://{self.hostname}/admin/realms/{self.minioRealm}"

        response = requests.get(realm_endpoint, headers=self.get_headers())

        if response.status_code == 200:
            realm_data = response.json()

            realm_data["sslRequired"] = "NONE"

            update_response = requests.put(realm_endpoint, headers=self.get_headers(), json=realm_data)

            if update_response.status_code == 204:
                print(f"Realm '{self.minioRealm}' SSL configuration updated successfully.")
            else:
                print(f"Failed to update realm SSL configuration: {update_response.status_code}")
                print(update_response.text)
        else:
            print(f"Failed to fetch realm configuration: {response.status_code}")
            print(response.text)

    def create_client(self):
        client_endpoint = f"http://{self.hostname}/admin/realms/{self.minioRealm}/clients"

        client_data = {
            #"id": "12a0a129-9461-442e-b2f1-432218a73968",
            "clientId": self.minioClient,
            "name": "",
            #"description": "",
            "rootUrl": "http://minio.apps.lab-okd.cfhlab.studio/",
            #"adminUrl": "http://minio.apps.lab-okd.cfhlab.studio/",
            "baseUrl": "http://minio.apps.lab-okd.cfhlab.studio/",
            "surrogateAuthRequired": False,
            "enabled": True,
            #"alwaysDisplayInConsole": False,
            "clientAuthenticatorType": "client-secret",
            #"secret": "xGNjdtlmT3EYVhTFIGEnHPEDdvwPnrIL",
            "redirectUris": [
                "http://minio.apps.lab-okd.cfhlab.studio/*"
            ],
            "webOrigins": [
                "http://minio.apps.lab-okd.cfhlab.studio/"
            ],
            "notBefore": 0,
            "bearerOnly": False,
            "consentRequired": False,
            "standardFlowEnabled": True,
            "implicitFlowEnabled": False,
            "directAccessGrantsEnabled": True,
            "serviceAccountsEnabled": True,
            "publicClient": False,
            "frontchannelLogout": True,
            "protocol": "openid-connect",
            "attributes": {
                "oidc.ciba.grant.enabled": "false",
                "client.secret.creation.time": "1725852723",
                "backchannel.logout.session.required": "true",
                "oauth2.device.authorization.grant.enabled": "false",
                "backchannel.logout.revoke.offline.tokens": "false"
            },
            "authenticationFlowBindingOverrides": {},
            "fullScopeAllowed": True,
            "nodeReRegistrationTimeout": -1,
            "protocolMappers": [
                {
                    #"id": "5efd6711-a871-45d5-8ed1-a3a03712417a",
                    "name": "client roles",
                    "protocol": "openid-connect",
                    "protocolMapper": "oidc-usermodel-client-role-mapper",
                    "consentRequired": False,
                    "config": {
                        "introspection.token.claim": "true",
                        "multivalued": "true",
                        "userinfo.token.claim": "false",
                        "user.attribute": "foo",
                        "id.token.claim": "true",
                        "lightweight.claim": "false",
                        "access.token.claim": "true",
                        "claim.name": "any_name_roles",
                        "jsonType.label": "String",
                        #"usermodel.clientRoleMapping.clientId": "12a0a129-9461-442e-b2f1-432218a73968"
                    }
                },
                {
                    #"id": "f278cee6-cb02-4331-9775-33b28f8b4912",
                    "name": "Client Host",
                    "protocol": "openid-connect",
                    "protocolMapper": "oidc-usersessionmodel-note-mapper",
                    "consentRequired": False,
                    "config": {
                        "user.session.note": "clientHost",
                        "id.token.claim": "true",
                        "introspection.token.claim": "true",
                        "access.token.claim": "true",
                        "claim.name": "clientHost",
                        "jsonType.label": "String"
                    }
                },
                {
                    #"id": "5fc1bebf-2368-48c4-ab84-363fcc37c588",
                    "name": "Client IP Address",
                    "protocol": "openid-connect",
                    "protocolMapper": "oidc-usersessionmodel-note-mapper",
                    "consentRequired": False,
                    "config": {
                        "user.session.note": "clientAddress",
                        "id.token.claim": "true",
                        "introspection.token.claim": "true",
                        "access.token.claim": "true",
                        "claim.name": "clientAddress",
                        "jsonType.label": "String"
                    }
                },
                {
                    #"id": "5f5dbb68-09be-4ce3-a74c-02c26b07e03a",
                    "name": "Client ID",
                    "protocol": "openid-connect",
                    "protocolMapper": "oidc-usersessionmodel-note-mapper",
                    "consentRequired": False,
                    "config": {
                        "user.session.note": "client_id",
                        "id.token.claim": "true",
                        "introspection.token.claim": "true",
                        "access.token.claim": "true",
                        "claim.name": "client_id",
                        "jsonType.label": "String"
                    }
                }
            ],
            "defaultClientScopes": [
                "web-origins",
                "acr",
                "profile",
                "roles",
                "basic",
                "email"
            ],
            "optionalClientScopes": [
                "address",
                "phone",
                "offline_access",
                "microprofile-jwt"
            ],
            "access": {
                "view": True,
                "configure": True,
                "manage": True
            }
        }

        response = requests.post(client_endpoint, headers=self.get_headers(), json=client_data)

        if response.status_code == 201:
            print(f"Client '{self.minioClient}' created successfully.")
        else:
            print(f"Failed to create client: {response.status_code}")
            print(response.text)

    def get_client_uuid(self, client_id):
        client_endpoint = f"http://{self.hostname}/admin/realms/{self.minioRealm}/clients"

        response = self.get_enpointJSON(client_endpoint)

        for client in response:
            if client["clientId"] == client_id:
                return client["id"]
            
        return None

    def create_role(self):
        client_uuid = self.get_client_uuid(self.minioClient)
        roles_endpoint = f"http://{self.hostname}/admin/realms/{self.minioRealm}/clients/{client_uuid}/roles"

        roles_data = [
            {
                "name": "readonly",
                "description": "",
                "composite": False,
                "clientRole": True,
                #"containerId": "12a0a129-9461-442e-b2f1-432218a73968" #client id
            },
            {
                "name": "diagnostics",
                "description": "",
                "composite": False,
                "clientRole": True,
                #"containerId": "12a0a129-9461-442e-b2f1-432218a73968"
            },
            {
                "name": "consoleAdmin",
                "description": "",
                "composite": False,
                "clientRole": True,
                #"containerId": "12a0a129-9461-442e-b2f1-432218a73968"
            }
        ]

        for role_data in roles_data:
            try:
                response = requests.post(roles_endpoint, headers=self.get_headers(), json=role_data)
                response.raise_for_status()
                print(f"Role '{role_data['name']}' created successfully.")
            except requests.exceptions.RequestException as e:
                print(f"Failed to create roles: {str(e)}")

    def create_user(self):
        user_endpoint = f"http://{self.hostname}/admin/realms/{self.minioRealm}/users"

        users_data = {
            "username": self.minioUser,
            "enabled": True,
            "credentials": [{
                "type": "password",
                "value": "12345678",
                "temporary": False
            }]
        }

        response = requests.post(user_endpoint, headers=self.get_headers(), json=users_data)

        if response.status_code == 201:
            print(f"User '{self.minioUser}' created successfully.")
        else:
            print(f"Failed to create user: {response.status_code}")
            print(response.text)

    def get_user_uuid(self, username):
        user_endpoint = f"http://{self.hostname}/admin/realms/{self.minioRealm}/users"

        response = self.get_enpointJSON(user_endpoint)

        for user in response:
            if user["username"] == username:
                return user["id"]
            
        return None
    
    def get_client_role(self, client_uuid):
        role_endpoint = f"http://{self.hostname}/admin/realms/{self.minioRealm}/clients/{client_uuid}/roles"

        response = self.get_enpointJSON(role_endpoint)
        '''
        [
            {
                "id": "c5ab8779-8cd4-4f5f-8eca-9ad4ce273e72",
                "name": "readonly",
                "description": "",
                "composite": false,
                "clientRole": true,
                "containerId": "12a0a129-9461-442e-b2f1-432218a73968"
            },
            {
                "id": "0988004f-9299-4b24-9ea9-54b18184c06f",
                "name": "diagnostics",
                "description": "",
                "composite": false,
                "clientRole": true,
                "containerId": "12a0a129-9461-442e-b2f1-432218a73968"
            },
            {
                "id": "89dcde24-177b-49a0-a032-0b9ca7a084ea",
                "name": "consoleAdmin",
                "description": "",
                "composite": false,
                "clientRole": true,
                "containerId": "12a0a129-9461-442e-b2f1-432218a73968"
            },
            {
                "id": "95a72004-a69f-4787-95fc-cd6397700b6e",
                "name": "cafe",
                "description": "",
                "composite": false,
                "clientRole": true,
                "containerId": "12a0a129-9461-442e-b2f1-432218a73968"
            }
        ]
        '''

        return response

    def user_roleMappeing(self):
        user_uuid = self.get_user_uuid(self.minioUser)
        client_uuid = self.get_client_uuid(self.minioClient)

        roleMapping_endpoint = f"http://{self.hostname}/admin/realms/{self.minioRealm}/users/{user_uuid}/role-mappings/clients/{client_uuid}"

        myrole = ["consoleAdmin"] # roles that want to map

        client_role = self.get_client_role(client_uuid)
        
        for role in client_role:
            if role["name"] in myrole:
                response = requests.post(roleMapping_endpoint, headers=self.get_headers(), json=[role])

                if response.status_code == 204:
                    print(f"Role '{role['name']}' mapping successfully.")
                else:
                    print(f"Failed to map the roles: {response.status_code}")
                    print(response.text)

    def create_external_idp(self):
        IDP_endpoint = f"http://{self.hostname}/admin/realms/{self.minioRealm}/identity-provider/instances"

        exIDP_data = {
            "alias": "openshift-v4",
            #"internalId": "b3c6f49a-bb95-441b-a547-72a0328ef09d",
            "providerId": "openshift-v4",
            "enabled": True,
            #"updateProfileFirstLoginMode": "on",
            #"trustEmail": False,
            #"storeToken": False,
            #"addReadTokenRoleOnCreate": False,
            #"authenticateByDefault": False,
            #"linkOnly": False,
            "config": {
                "syncMode": "LEGACY",
                "clientSecret": "KIIlmkVE7IKGrlP6NNMD7x53dWUtlM7u",
                "baseUrl": "https://api.lab-okd.cfhlab.studio:6443",
                "clientId": "test"
            }
        } 

        response = requests.post(IDP_endpoint, headers=self.get_headers(), json=exIDP_data)

        if response.status_code == 201:
            print("External idp created successfully.")
        else:
            print(f"Failed to create external idp: {response.status_code}")
            print(response.text)

    def delete_realm(self):
        realm_endpoint = f"http://{self.hostname}/admin/realms/{self.minioRealm}"

        response = requests.delete(realm_endpoint, headers=self.get_headers())

        if response.status_code == 204:
            print(f"Realm '{self.minioRealm}' deleted successfully.")
        else:
            print(f"Failed to delete realm '{self.minioRealm}'. Status Code: {response.status_code}")
            print(f"Error: {response.text}")

class KeycloakCaFe(JWTToken):
    def __init__(self, data, realm, hostname) -> None:
        super().__init__(data, realm, hostname)
    '''
    KeycloakCaFe needs to create a CaFe admin user via Keycloak admin user,
    after that, assign the "realm-management":"manage-realm" role to CaFe admin user 
    '''

    def create_realm(self):
        endpoint = ""

def print_colored_json(data):
    json_str = json.dumps(data, indent=4)
    for line in json_str.splitlines():
        if ':' in line:
            key, value = line.split(':', 1)
            colored_key = colored(key, 'cyan')
            colored_value = colored(value, 'yellow')
            print(f"{colored_key}:{colored_value}")
        else:
            print(colored(line, 'white'))

def Keycloak_MinIO_init(adminData):
    minio_data = {
        "adminRealm": "master",
        "hostname": "${hostname}",
        "minioRealm": "any_name",
        "minioClient": "any_name_for_minio",
        "minioUser": "any_login_user_for_minio"
    }
    myMinio = KeycloakMinio(adminData, **minio_data)
    myMinio.create_realm()
    myMinio.realm_SSL_setting()
    myMinio.create_client()
    myMinio.create_role()
    myMinio.create_user()
    myMinio.user_roleMappeing()
    myMinio.create_external_idp()
    #myMinio.delete_realm()

def main():
	# admin account
    adminData = {
        "grant_type": "password",
        "client_id": "admin-cli",
        "username": "admin",
        "password": "admin"
    }
    
    Keycloak_MinIO_init(adminData)


if __name__ == '__main__':
    main()

'''
Reference:
https://www.keycloak.org/docs-api/22.0.1/rest-api/index.html
'''
