# OpenvpnAS-script-mapping-ldap-groups

With Lightweight Directory Access Protocol (LDAP), users can connect to your Access Server with their LDAP credentials and access resources. You can configure the access control rules for granting access to apply globally for all users or on a per-user and per-group basis. Typically, the server administrator manually assigns users to groups, but you can automate group assignments.

After successful authentication, the Access Server can run a post-auth (post-authentication) Python3 script to perform additional tasks. We provide a post_auth script that reads an LDAP group membership attribute supplied by the LDAP server and uses that to assign the user to a group in Access Server automatically. Ensure you define these group mappings in the post_auth script and configure the LDAP server to provide the group membership attribute to the Access Server.

To enable LDAP group mapping using a script, follow the steps detailed below:

Configure and enable LDAP authentication.
Configure the LDAP server to provide group membership.
Customize the post_auth script to set up the group mappings.
Install the post_auth script into the Access Server.
Test user login and confirm functionality.

Edit the script to map LDAP groups to Access Server groups

nano ldap.py

scroll to this section:

# determine the access server group based on LDAP group settings
if 'Administrators' in ldap_groups:
group = "admin"
elif 'Sales' in ldap_groups:
group = "sales"
elif 'Finance' in ldap_groups:
group = "finance"
elif 'Engineering' in ldap_groups:
group = "engineering"

Reload the script:

cd /usr/local/openvpn_as/scripts
./sacli -k auth.module.post_auth_script --value_file=/root/ldap.py ConfigPut
./sacli start
