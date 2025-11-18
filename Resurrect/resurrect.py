# Author: x4c1s
# LICENSE: WTFPL
# Date: 2025-11-17

#!/usr/bin/env python3

import argparse
import sys
from tabulate import tabulate
import os
from impacket.ldap import ldap, ldapasn1
from impacket.ldap.ldapasn1 import ModifyRequest, Control
from pyasn1.type.univ import SequenceOf,Sequence, OctetString, Integer, SetOf

def create_ldap_connection(args):
    dom = args.domain.split('.')[0]
    tld = args.domain.split('.')[1]
    
    if args.target:
        server_host = args.target
        print(f"[*] Connecting to {args.target}")
    elif args.dc_host:
        server_host = args.dc_host
        print(f"[*] Connecting to {args.dc_host}")
    else:
        print("[!] Please specify either a DC or a target (--dc-host/--target)")
        return None


    if args.k:
        if not args.dc_host:
            print("[!] Kerberos Authentication Selected but --dc-host not specified")
            sys.exit()

        print("[*] Attempting Kerberos authentication")
        
        if os.environ.get('KRB5CCNAME'):
            print(f"[*] Using Kerberos ccache from KRB5CCNAME: {os.environ.get('KRB5CCNAME')}")
        else:
            print("[*] Using default Kerberos ccache location")
        
        try:
            if args.ldaps:
                conn = ldap.LDAPConnection(f'ldaps://{args.dc_host}')
                conn.kerberosLogin(f'{args.username}', '', f'{args.domain}', '', '')
            else:
                conn = ldap.LDAPConnection(f'ldap://{args.dc_host}')
                conn.kerberosLogin(f'{args.username}', '', f'{args.domain}', '', '')
            
            print("[*] Kerberos Authentication successful")
            return conn
            
        except Exception as e:
            print(f"[!] Kerberos authentication error: {e}")
            return None
    
    elif args.hash:
        if len(args.hash) == 32:
            try:
                if args.ldaps:
                    conn = ldap.LDAPConnection(f'ldaps://{server_host}')
                else:
                    conn = ldap.LDAPConnection(f'ldap://{server_host}')

                lmhash = 'aad3b435b51404eeaad3b435b51404ee'
                nthash = args.hash

                conn.login(
                    user=args.username,
                    password='',
                    domain=args.domain,
                    lmhash=lmhash,
                    nthash=nthash

                )
                print("[*] Authentication successful")
                return conn
            except Exception as e:
                print(f"[!] Authentication Error: {e}")
        else:
            print("[!] Hash length mismatch - should be 32 characters")
            return None
    
    elif args.password:
        try:
            if args.ldaps:
                conn = ldap.LDAPConnection(f'ldaps://{server_host}')
            else:
                conn = ldap.LDAPConnection(f'ldap://{server_host}')

            conn.login( 
                user=args.username, 
                password=args.password, 
                domain=args.domain, 
            )
            print("[*] Authentication successful")
            return conn
        except Exception as e:
            print(f"[!] Authentication Error: {e}")
    else:
        print("[!] Please specify an authentication method (password, hash, or Kerberos)")
        return None



def find_deleted_objects(args):
    try:
        conn = create_ldap_connection(args)
        if not conn:
            sys.exit(1)

        search_base = f'CN=Deleted Objects,DC={args.domain.split(".")[0]},DC={args.domain.split(".")[1]}'
        search_filter = '(&(|(objectClass=User)(objectCategory=Computer))(isDeleted=TRUE))'
        attributes = ['cn', 'sAMAccountName', 'objectClass', 'lastKnownParent']
        show_deleted_control = ldapasn1.Control()
        show_deleted_control['controlType'] = ldapasn1.LDAPOID('1.2.840.113556.1.4.417')
        show_deleted_control['criticality'] = True

        entry_list = []
        page_size = args.page_size if args.page_size else 10
        cookie = b''

        while True:
            paging_control = ldapasn1.SimplePagedResultsControl(criticality=False, size=page_size, cookie=cookie)
            try:   
                resp = conn.search(
                searchBase = search_base,
                searchFilter = search_filter,
                scope=ldapasn1.Scope('wholeSubtree'),
                attributes=attributes,
                searchControls=[show_deleted_control, paging_control]
            )

            except Exception as e:
                print("[!] Search Error: ", e)
                break

            for item in resp:
                if isinstance(item, ldapasn1.SearchResultEntry):
                    entry_list.append(item)
            if not cookie:
                break
        if not entry_list:
            print("[*] No deleted users found or your current user doesn't have the permissions to view them")
            sys.exit()
        else:
            print("[*] Deleted user(s) found\r\t")
            data = []
            for entry in entry_list:
                attrs = {}
                for attr in entry['attributes']:
                    attr_name  = str(attr['type'])
                    attr_values = [str(val) for val in attr['vals']]
                    attrs[attr_name] = attr_values
                
                if not attrs:
                    continue

                cn = attrs.get('cn', [''])[0]
                guid = cn.split('\n')[1].split(':')[1]
                ou = attrs.get('lastKnownParent', [''])[0]
                sam = attrs.get('sAMAccountName', [''])[0]
                objectclass = attrs.get('objectClass')[3]
                data.append([sam, guid, ou, objectclass])
                
        headers = ['username', 'GUID', 'OU', 'objectClass']
        print(tabulate(data, headers=headers, tablefmt='grid'))
    except Exception as e:
        print("[-] An error has occured", e)


def restore_deleted_objects(args):
    import uuid
    try:
        conn = create_ldap_connection(args)
        if not conn:
            sys.exit(1)

        if args.guid:    

            
            def guid_to_ldap_filter(g):
                u = uuid.UUID(g)
                return ''.join('\\%02X' % b for b in u.bytes_le)
        
            guid_filter = guid_to_ldap_filter(args.guid)

        
            search_base = f'CN=Deleted Objects,DC={args.domain.split(".")[0]},DC={args.domain.split(".")[1]}'
            search_filter = f'(&(objectGuid={guid_filter})(isDeleted=TRUE))'
            attributes = ['distinguishedName']
            show_deleted_control = ldapasn1.Control()
            show_deleted_control['controlType'] = ldapasn1.LDAPOID('1.2.840.113556.1.4.417')
            show_deleted_control['criticality'] = True

            entry_list = []
            page_size =  10
            cookie = b''

            try: 
                resp = conn.search(
                searchBase = search_base,
                searchFilter = search_filter,
                scope=ldapasn1.Scope('wholeSubtree'),
                attributes=attributes,
                searchControls=[show_deleted_control]
                )

            except Exception as e:
                print("[!] Search Error: ", e)

            for item in resp:
                if isinstance(item, ldapasn1.SearchResultEntry):
                    entry_list.append(item)
            if not entry_list:
                print("[!] Could not find any object with the supplied GUID")
                sys.exit()
            else:
                data = []
                for entry in entry_list:
                    attrs = {}
                    for attr in entry['attributes']:
                        attr_name  = str(attr['type'])
                        attr_values = [str(val) for val in attr['vals']]
                        attrs[attr_name] = attr_values
                
                    if not attrs:
                        continue

                    dn= attrs.get('distinguishedName', [''])[0]
                    print(f"[*] Object Found: {dn}")
                    cn = dn.split(':')[0].split('\\')[0] 
            new_dn = f"{cn},{args.ou}"

        

   
   
        changes = SequenceOf()  
        change1 = Sequence() 
        change1.setComponentByPosition(0, Integer(1))
        mod1 = Sequence()
        mod1.setComponentByPosition(0, OctetString("isDeleted"))
        mod1.setComponentByPosition(1, SetOf())
        change1.setComponentByPosition(1, mod1)
        changes.append(change1)
        change2 = Sequence()
        change2.setComponentByPosition(0, Integer(2))
        mod2 = Sequence()
        mod2.setComponentByPosition(0, OctetString("distinguishedName"))
        vals2 = SetOf()
        vals2.append(OctetString(new_dn))
        mod2.setComponentByPosition(1, vals2)
        change2.setComponentByPosition(1, mod2)
        changes.append(change2)
        req = ModifyRequest()
        req.setComponentByName('object', OctetString(dn))
        req.setComponentByName('changes', changes)
        ctrl = Control()
        ctrl['controlType'] = '1.2.840.113556.1.4.417'
        ctrl['criticality'] = True
        ctrl['controlValue'] = b''
        print("[*] Restoring Object with GUID: ", args.guid)

        try:
            resp = conn.send(req, controls=[ctrl])
            print("[+] Restore successful!")
            print(f"[+] New DN = {new_dn}")
        except Exception as e:
            print("[!] Restore failed:", e)

        


    except Exception as e:
            print("[!] Error during restore operation: ", e)


def main():

    parser = argparse.ArgumentParser(
        description='Remotely find and restore TombStoned Users',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=f"""
Examples:
# Find Deleted Users and Computers
python3 {sys.argv[0]} find --domain example.com --username admin --password password123 --target 10.10.11.70 

# Restore Objects to their OUs
python3 {sys.argv[0]} restore --domain example.com --username admin --password password123 --target 10.10.11.70 --guid f80369c8-96a2-4a7f-a56c-9c15edd7d1e3 --ou "OU=Staff,DC=evilcorp,DC=com"

# Pass-The-Hash Support
python3 {sys.argv[0]} find --domain example.com --username admin --ldaps --target 10.10.11.70 --hash 149e0ed1f84c8fd4ecb11a9c2ab7af2

# Kerberos Support
python3 {sys.argv[0]} find --domain example.com --username admin --ldaps --dc-host dc.example.com -k
python3 {sys.argv[0]} restore --domain example.com --username admin -k --dc-host dc.example.com --guid f80369c8-96a2-4a7f-a56c-9c15edd7d1e3 --ou "OU=Staff,DC=evilcorp,DC=com"
            """
) 


    subparsers = parser.add_subparsers(
        title='commands',
        dest='command',
        help='Command to execute',
        metavar='{find,restore}'
    )

    def add_common_args(subparsers):
        subparsers.add_argument("--domain", help="Target Domain", required=True)
        subparsers.add_argument("--username", help="Username", required=True)
        subparsers.add_argument("--password", help="Password", required=False)
        subparsers.add_argument("--dc-host", help="Domain Controller FQDN", required=False)
        subparsers.add_argument("--target", help="Target", required=False)
        subparsers.add_argument("--ldaps", help="Force LDAP to authenticate over SSL", action="store_true", required=False)
        subparsers.add_argument("--hash", help="LM:NTLM hash", required=False)
        subparsers.add_argument("-k", help="Use Kerberos for Authentication",action="store_true",required=False)

    find_parser = subparsers.add_parser(
        'find',
        help='Search for Deleted Users and Computers in Active Directory'
    )

    restore_parser = subparsers.add_parser(
        'restore',
        help='Restore Deleted Objects to their respective OU'
    )
    add_common_args(find_parser)
    find_parser.add_argument('--page-size', required=False, type=int, help='Number of results per page (default 10)')
    find_parser.set_defaults(func=find_deleted_objects)


    add_common_args(restore_parser)
    restore_parser.add_argument('--guid', required=True, help='GUID of the deleted object')
    restore_parser.add_argument('--ou', required=True, help='Target OU to restore to')
    restore_parser.set_defaults(func=restore_deleted_objects)

    args = parser.parse_args()
    if not args.command:
        parser.print_help()
        sys.exit(1)
    args.func(args)

if __name__ == "__main__":
    main()


