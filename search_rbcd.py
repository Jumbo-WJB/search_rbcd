from argparse import ArgumentParser
import ldap3
from ldap3.utils.conv import escape_filter_chars
from impacket.ldap.ldaptypes import SR_SECURITY_DESCRIPTOR

class SearchRBCD(object):
    def __init__(self,ldap_server,ldap_session):
        self.ldap_server = ldap_server
        self.ldap_session = ldap_session

    def get_sid_info(self,root,sid):
        self.ldap_session.search(root, '(objectSid=%s)' % escape_filter_chars(sid), attributes=['samaccountname']) # https://github.com/SecureAuthCorp/impacket/blob/ea023b2813ba512cbd556e59415fd020b9fbc423/examples/rbcd.py#L419
        try:
            dn = self.ldap_session.entries[0].entry_dn
            samname = self.ldap_session.entries[0]['samaccountname']
            return dn, samname
        except IndexError as e:
            print(e)
            return False

    def get_computer_AllowedToActOnBehalfOfOtherIdentity(self):

        root = self.ldap_server.info.other['defaultNamingContext'][0]
        print(root)
        self.ldap_session.search(root,"(&(objectCategory=computer)(objectClass=computer))",attributes=['cn','msDS-AllowedToActOnBehalfOfOtherIdentity'])
        searchlength = len(self.ldap_session.entries)
        ldap_entriess.append(self.ldap_session.entries)
        first_ldap_entriess = ldap_entriess[0]
        for i in range(0,searchlength):
            searchresult = first_ldap_entriess[i]
            computer = searchresult['cn']
            if searchresult['msDS-AllowedToActOnBehalfOfOtherIdentity']:
                AllowedToActOnBehalfOfOtherIdentity = searchresult['msDS-AllowedToActOnBehalfOfOtherIdentity'][0]
                # print(AllowedToActOnBehalfOfOtherIdentity)
                sd = SR_SECURITY_DESCRIPTOR(data=AllowedToActOnBehalfOfOtherIdentity) # https://github.com/SecureAuthCorp/impacket/blob/ea023b2813ba512cbd556e59415fd020b9fbc423/examples/rbcd.py#L403
                for ace in sd['Dacl'].aces:
                    AllowedToActOnBehalfOfOtherIdentitySID = ace['Ace']['Sid'].formatCanonical()
                    SamAccountName = self.get_sid_info(root,AllowedToActOnBehalfOfOtherIdentitySID)[1]
                    if SamAccountName:
                        print(f'computer:{computer} \'s msDS-AllowedToActOnBehalfOfOtherIdentity value is {AllowedToActOnBehalfOfOtherIdentitySID} , sidname is {SamAccountName}')



def init_ldap_connection(target, domain, username, password):
    user = '%s\\%s' % (domain, username)
    use_ssl = False
    port = 389
    tls = None
    ldap_server = ldap3.Server(target, get_info=ldap3.ALL, port=port, use_ssl=use_ssl, tls=tls)
    ldap_session = ldap3.Connection(ldap_server, user=user, password=password, authentication=ldap3.NTLM, auto_bind=True)
    return ldap_server, ldap_session


def main():
    parser = ArgumentParser()
    parser.add_argument('-u','--username', help='username for LDAP', required=True)
    parser.add_argument('-p','--password', help='password for LDAP', required=True)
    parser.add_argument('-d','--domain', help='LDAP server/domain', required=True)
    parser.add_argument('-l','--ldapserver', help='LDAP server', required=True)
    args = parser.parse_args()
    try:
        ldap_server, ldap_session = init_ldap_connection(args.ldapserver,args.domain, args.username, args.password)
        searchrbcd = SearchRBCD(ldap_server, ldap_session)
        searchrbcd.get_computer_AllowedToActOnBehalfOfOtherIdentity()
    except Exception as e:
        print(e)

if __name__ == '__main__':
    ldap_entriess = []
    main()


