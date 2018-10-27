import re

import ldap3
from jupyterhub.auth import Authenticator
from ldap3.utils.conv import escape_filter_chars
from tornado import gen
from traitlets import Unicode, Int, Bool, List


class LDAPAuthenticator(Authenticator):
    server_address = Unicode(
        config=True,
        help="""
        IP address or hostname of the LDAP server to contact.
        """
    )
    server_port = Int(
        config=True,
        help="""
        Port on which to contact the LDAP server.

        Defaults to `636` if `use_ssl` is set, `389` otherwise.
        """
    )

    def _server_port_default(self):
        if self.use_ssl:
            return 636  # default SSL port for LDAP
        else:
            return 389  # default plaintext port for LDAP

    use_ssl = Bool(
        False,
        config=True,
        help="""
        Use SSL to communicate with the LDAP server.

        Deprecated in version 3 of LDAP in favor of Start TLS.
        Your LDAP server must be configured to support this, however.
        """
    )

    whitelist_groups = List(
        config=True,
        allow_none=True,
        default=None,
        help="""
        List of LDAP group DNs that grant access.

        if a user is in any of the listed groups, they are allowed access.
        Membership is currently only tested using the MemberOf overlay.

        Set to an empty list or None to allow all users with a valid account to login.
        """
    )

    blacklist_groups = List(
        config=True,
        allow_none=True,
        default=None,
        help="""
            List of LDAP group DNs that deny access.

            if a user is in any of the listed groups, they are denied access.
            Membership is currently only tested using the MemberOf overlay.

            Set to an empty list or None to allow all users with a valid account to login.
            """
    )

    admin_groups = List(
        config=True,
        default_value=None,
        allow_none=True,
        help="""
        List of groups that grant administrator status. Can be overridden by admin_users.
        """
    )

    build_user_profile = Bool(
        config=True,
        default_value=False,
        allow_none=True,
        help="""
        Build user profile for spawner cooperation. Saves the user's UID, GID, and group memberships
        """
    )

    profile_groups = List(
        config=True,
        default_value=None,
        allow_none=True,
        help="""
        List of groups to check when building the user's auth profile.
        """
    )

    profile_uid_attribute = Unicode(
        config=True,
        default_value='uidNumber',
        allow_none=False,
        help="""
            LDAP attribute corresponding to a uid. Defaults to 'uidNumber'.
            """
    )

    profile_gid_attribute = Unicode(
        config=True,
        default_value='gidNumber',
        allow_none=False,
        help="""
        LDAP attribute corresponding to a gid. Defaults to 'gidNumber'.
        """
    )

    profile_group_name_attribute = Unicode(
        config=True,
        default_value='cn',
        allow_none=False,
        help="""
            LDAP attribute corresponding to a group's name. Defaults to 'cn'.
            """
    )

    # FIXME: Use something other than this? THIS IS LAME, akin to websites restricting things you
    # can use in usernames / passwords to protect from SQL injection!
    valid_username_regex = Unicode(
        r'^[a-z][.a-z0-9_-]*$',
        config=True,
        help="""
        Regex for validating usernames - those that do not match this regex will be rejected.

        This is primarily used as a measure against LDAP injection, which has fatal security
        considerations. The default works for most LDAP installations, but some users might need
        to modify it to fit their custom installs. If you are modifying it, be sure to understand
        the implications of allowing additional characters in usernames and what that means for
        LDAP injection issues. See https://www.owasp.org/index.php/LDAP_injection for an overview
        of LDAP injection.
        """
    )

    user_search_base = Unicode(
        config=True,
        default=None,
        allow_none=True,
        help="""
        Search base for looking up user accounts.

        LDAPAuthenticator will search all objects matching under this base where the `user_attribute`
        matches the given login name.
        """
    )

    username_attribute = Unicode(
        config=True,
        default=None,
        allow_none=True,
        help="""
        LDAP attribute containing the user's username. Most use uid, Active Directory uses sAMAccountname.
        """
    )

    lookup_dn_search_filter = Unicode(
        config=True,
        default_value='({username_attribute}={username})',
        allow_none=True,
        help="""
        Query for user lookup, should at least contain a match between {username_attribute} and {username}.
        """
    )

    search_user_dn = Unicode(
        config=True,
        default_value=None,
        allow_none=True,
        help="""
        Account to perform user lookups through.

        If lookup_dn_search_user and search_user_password are None, an anonymous bind will be used.
        Anonymous binds should be discouraged for security purposes.
        """
    )

    search_user_password = Unicode(
        config=True,
        default_value=None,
        allow_none=True,
        help="""
        Password for the lookup account.
        """
    )

    # TODO memberOf overlay toggle for whiteliisting

    # FIXME: Whoops, this test may run before the data exists
    # def __init__(self):
    #     super().__init__()
    #
    #     try:
    #         # test search filter at least is shaped correctly
    #         self.lookup_dn_search_filter.format(username_attribute=self.username_attribute,
    #                                             username='format_test')
    #     except Exception as err:
    #         self.log.critical("LDAP search filter malformed! Missing 'username_attribute' or 'username': %s", err)
    #         raise
    #
    #     try:
    #         self.build_connection(self.search_user_dn, self.search_user_password).unbind()
    #     except Exception as err:
    #         self.log.critical("Could not complete startup LDAP test bind! %s", err)
    #         raise

    def build_connection(self, bind_dn, bind_password):
        """
        Builds and binds LDAP connection
        :return: Connection object
        """
        try:
            server = ldap3.Server(
                host=self.server_address,
                port=self.server_port,
                use_ssl=self.use_ssl
            )  # allowed_referral_hosts=[("*", True)]

            conn = ldap3.Connection(
                server,
                user=bind_dn,
                password=bind_password,
                auto_bind=ldap3.AUTO_BIND_TLS_BEFORE_BIND if not self.use_ssl else ldap3.AUTO_BIND_NO_TLS,
                client_strategy=ldap3.SYNC,
                raise_exceptions=True
            )
        except Exception as err:
            if isinstance(err, ldap3.core.exceptions.LDAPBindError):
                self.log.warning('"%s" Failed to bind to LDAP server: %s', bind_dn, err)
            else:
                self.log.error("LDAP connection failed: %s", err)
            raise

        return conn

    @staticmethod
    def _read_cached_dn(authentication):
        user_dn = authentication['auth_state']['profile'].get('dn')
        if user_dn is None:
            raise RuntimeError('User missing DN in auth_state profile')
        return user_dn


    def _check_ldap_group_membership(self, authentication, group_list):
        membership_filter = '(|' + ''.join(
            ['(memberOf={})'.format(escape_filter_chars(x)) for x in set(group_list)]
        ) + ')'
        self.log.debug('Checking group membership with filter: %s', membership_filter)

        user_dn = self._read_cached_dn(authentication)

        with self.build_connection(self.search_user_dn, self.search_user_password) as ldap:
            ldap.search(search_base=user_dn, search_filter=membership_filter, search_scope=ldap3.BASE)
            self.log.debug('Membership test says: %s', len(ldap.response) > 0)
            return len(ldap.response) > 0


    def is_admin(self, handler, data, authentication, *args, **kwargs):
        super_admin = super().is_admin(handler, data, authentication, *args, **kwargs)
        if super_admin:
            return True
        elif self.admin_groups:
            return self._check_ldap_group_membership(authentication, self.admin_groups)
        else:
            # Either a False (strip admin) or a None (no change)
            return super_admin

    def build_profile(self, handler, data, username, authentication, *args, **kwargs):
        super_profile = super().build_profile(handler, data, authentication, *args, **kwargs)

        # TODO: set a profile default of {} in get_authenticated_user
        profile = authentication['auth_state']['profile']
        profile.update(super_profile)

        user_dn = self._read_cached_dn(authentication)

        if self.build_user_profile:
            # Ok. We're scraping the UID, GID, groups of interest that intersect the user's groups, and those GIDs
            with self.build_connection(self.search_user_dn, self.search_user_password) as ldap:
                # Load UID/GID/memberOf
                # TODO: When memberOf overlay id optional, it probably needs to N group lookups no matter what to simplify
                self.log.sebug("Loading UID/GID/MemberOf for profile")
                ldap.search(search_base=user_dn, search_filter='(objectClass=*)', search_scope=ldap3.BASE,
                            attributes=[self.profile_uid_attribute, self.profile_gid_attribute, 'memberOf'])

                if len(ldap.response) != 1:
                    raise RuntimeError('Profile build got bad result length %s', len(ldap.response))

                user_entry = ldap.entries[0]

                profile['uid'] = user_entry[self.profile_uid_attribute].value
                profile['gid'] = user_entry[self.profile_gid_attribute].value
                self.log.sebug('Found UID %s and GID %s', profile['uid'], profile['gid'])

                # I don't trust user/server escaping to line up... But I'll go with it for now
                target_groups = set(self.profile_groups)
                intersect_groups = target_groups & set(e['memberOf'].value)
                self.log.debug('Group overlap to enumerate: %s', intersect_groups)

                # FIXME: Better name for dict?
                # FIXME: EXTREME ASSUMPTION - User private group by default. It's not BAD, just want this to be seen
                # I want all groups to have a resolved name. This is "private" in name only by default.
                # If profile_groups pulls in this gid, it will overwrite
                # FIXME: Put normalized username in the authenticated dictionary? authenticated['normalized_name']?
                profile['group_map'] = {profile['gid']: username}
                for group in intersect_groups:
                    ldap.search(search_base=group, search_filter='(objectClass=*)', search_scope=ldap3.BASE,
                                attributes=[self.profile_gid_attribute,self.profile_group_name_attribute])

                    if len(ldap.response) != 1:
                        raise RuntimeError('Profile build group search got bad result length %s for %s',
                                           len(ldap.response), group)

                    group_entry = ldap.entries[0]
                    profile['group_map'][group_entry[self.profile_gid_attribute]] = group_entry[self.profile_group_name_attribute]

            self.log.debug('Profile enumerated: %s', profile)
        return

    def user_dn_lookup(self, connection, username):
        """
        Lookup user dn

        :param connection: server connection
        :param username: username to lookup
        :return: DN string or None
        """

        # Hopefully this will catch a poorly formatted search filter
        search_filter = self.lookup_dn_search_filter.format(username_attribute=self.username_attribute,
                                                            username=username)

        self.log.debug('Attempting to resolve "%s" with base: "%s" and filter: "%s"', username, self.server_address,
                       self.user_search_base, search_filter)

        try:
            with connection as ldap:
                ldap.search(search_base=self.user_search_base,
                            search_scope=ldap3.SUBTREE,
                            search_filter=search_filter,
                            attributes=[self.username_attribute],
                            size_limit=2)
                results = ldap.response

            if len(results) == 0:
                self.log.warning('Lookup for %s returned no results!', username)
                return None
            elif len(results) > 1:
                self.log.warning('Lookup for %s was not distinct!', username)
                return None
            else:
                return results[0]['dn']
        except Exception as err:
            self.log.error('LDAP DN resolution raised while resolving %s: %s', username, err)
            raise

    def check_whitelist(self, username, authentication, *args, **kwargs):
        if super().check_whitelist(username, authentication, *args, **kwargs):
            return True

        if self.whitelist_groups:
            return self._check_ldap_group_membership(authentication, self.whitelist_groups)
        else:
            return True

    def check_blacklist(self, username, authentication, *args, **kwargs):
        if super().check_blacklist(username, authentication, *args, **kwargs):
            return True

        if self.blacklist_groups:
            return self._check_ldap_group_membership(authentication, self.blacklist_groups)
        else:
            return True

    @gen.coroutine
    def authenticate(self, handler, data, *args, **kwargs):
        """Resolve a username to a dn and check password. Adds dn to auth_state"""
        username = data['username']
        password = data['password']

        # Protect against invalid usernames as well as LDAP injection attacks
        if not re.match(self.valid_username_regex, username):
            self.log.warning('Login denied for "%s": username must match regex %s',
                             username, self.valid_username_regex)
            return None

        if password is None or password.strip() == '':
            self.log.warning('Login denied for "%s": blank password', username)
            return None

        self.log.debug('Connecting to server and resolving "%s".', username)

        user_dn = self.user_dn_lookup(self.build_connection(self.search_user_dn, self.search_user_password),
                                      username)

        if user_dn is None:
            return None

        self.log.info('"%s" attempting login, checking password', user_dn)

        # I'd like to just rebind the existing connection, but
        # maybe that user lacks permissions to read data we need
        try:
            self.build_connection(user_dn, password)
        except Exception as err:
            if isinstance(err, ldap3.core.exceptions.LDAPBindError):
                self.log.info('Password rejected for %s', username)
                return None
            raise

        # We've looked up the username and validated the password, they pass this phase

        return {
            'name': username,
            'auth_state': {
                'profile': {
                    'dn': user_dn
                }
            }
        }


if __name__ == "__main__":
    import getpass
    c = LDAPAuthenticator()

    c.server_address = input('server_address: ')
    c.server_port = int(input('server_port: '))
    c.use_ssl = input('use_ssl: ') == 'True'  # less than ideal
    c.search_user_dn = input('search_user_dn: ')
    if c.search_user_dn == '':
        c.search_user_dn = None
    c.search_user_password = getpass.getpass('search_user_password: ')
    if c.search_user_password == '':
        c.search_user_password = None

    c.user_search_base = input('user_search_base: ')
    c.username_attribute = input('username_attribute: ')
    c.lookup_dn_search_filter = input('lookup_dn_search_filter: ')

    auth_result = c.authenticate(None, {
        'username': input('LDAP test login: '),
        'password': getpass.getpass()
    })

    auth_status = auth_result.result()

    print(auth_status)

    # anything else it too complicated for now.
