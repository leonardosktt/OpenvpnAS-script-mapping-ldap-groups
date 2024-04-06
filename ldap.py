# OpenVPN Access Server LDAP Mapping post_auth (autologin) script.
#
# Note that it is normal that a first login can result in an error;
# after the first time it saves the information to the database so
# it works fine from then on.
#
# Please adjust the group match definitions near the bottom of this
# script so that it matches the group names you want to map.
#
# Please also review the default group assignment setting. This
# setting actually overrides the 'default group' setting in the
# Group Permissions section in the Admin UI. So if you are using
# that function, and you want this script to adhere to that, please
# set this value to the same setting as the 'default group' setting.
#
# Contributions by:
# David Lam
# Johan Draaisma
# Vadym Teslia
# Bohdan Hamulets
#
# Full documentation at:
# https://openvpn.net/static-links/post-auth-ldap-group-mapping
#
# Script last updated in June 2021

import re

from pyovpn.plugin import *

# regex to parse the first component of an LDAP group DN
re_group = re.compile(r"^CN=([^,]+)", re.IGNORECASE)


def ldap_groups_parse(res):
    ret = set()
    for g in res:
        m = re.match(re_group, g)
        if m:
            ret.add(m.groups()[0])
    return ret

# this function is called by the Access Server after normal authentication
def post_auth(authcred, attributes, authret, info):

    # Default group assignment - update this if you use the default group setting in Access Server.
    group = ""

    # user properties to save
    proplist_save = {}

    if info.get('auth_method') == 'ldap': # this code only operates when the Access Server auth method is set to LDAP
        user_dn = info['user_dn']  # get the user's distinguished name
        # use our given LDAP context to perform queries
        with info['ldap_context'] as l:
            # get the LDAP group settings for this user
            ldap_groups = set()
            if hasattr(l, 'search_ext_s'):
                # we are using old python-ldap package on the Access Server < V2.8
                import ldap
                ldap_groups = l.search_ext_s(user_dn, ldap.SCOPE_SUBTREE, attrlist=["memberOf"])[0][1]['memberOf']
                if ldap_groups:
                    ldap_groups = ldap_groups_parse(ldap_groups)
            else:
                # we are using ldap3 package on the Access Server >= V2.8
                search_base = info['search_base']  # Base DN on the LDAP server to start the search from
                uname_attr = info['ldap_context'].authldap.parms['uname_attr']
                search_filter = '(%s=%s)' % (uname_attr, user_dn)
                attribute = 'memberOf'
                if l.search(search_base, search_filter, attributes=[attribute]):
                    ldap_groups = getattr(l.entries[0], attribute).value
                    if not isinstance(ldap_groups, (list, tuple)):
                        ldap_groups = {ldap_groups}
                    if ldap_groups:
                        ldap_groups = ldap_groups_parse(ldap_groups)
                else:
                    print('POST_AUTH: Ldap groups for the user %r are not found, please check your filters %r' % (user_dn, search_filter))
            if ldap_groups:
                print("********** LDAP_GROUPS %s" % ldap_groups)

                # Adjust these to map the user's LDAP group membership to an Access Server group.
                if 'nome_grupo_AD' in ldap_groups:
                    group = "nome_grupo_openvpn"
                elif 'nome_grupo_AD' in ldap_groups:
                    group = "nome_grupo_openvpn"
        if group:
            print("***** POST_AUTH: User group mapping found for %r, setting OpenVPN connection group to %r ..." % (info['user_dn'], group))
            authret['proplist']['conn_group'] = group
            proplist_save['conn_group'] = group
        else:
            print("***** POST_AUTH: No group mapping matches found for %r ... Using default group settings..." % info['user_dn'])
            authret['proplist']['conn_group'] = group
            proplist_save['conn_group'] = group
    return authret, proplist_save
