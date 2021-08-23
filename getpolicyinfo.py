#!/usr/bin/env python
"""
Prisma SDWAN script to lists the policy sets and its rules
tkamath@paloaltonetworks.com
Note: Version 1 only retrieves Security Policy Details

Version: 1.0.0
"""
import cloudgenix
import pandas as pd
import os
import sys
import argparse
import logging
import datetime


# Global Vars
SDK_VERSION = cloudgenix.version
SCRIPT_NAME = 'Prisma SDWAN: Get Policy Info'


# Policy Types
SECURITY_POL ="security"
NW_STACK = "nwstack"
QOS_STACK = "qosstack"
NAT_STACK = "natstack"
ORIGINAL = "original"
BOUND = "BOUND"
ALL = "ALL"

SECURITY = "SECURITY"
NETWORK = "NETWORK"
QOS = "QOS"
NAT = "NAT"

# Set NON-SYSLOG logging to use function name
logger = logging.getLogger(__name__)

try:
    from cloudgenix_settings import CLOUDGENIX_AUTH_TOKEN

except ImportError:
    # will get caught below.
    # Get AUTH_TOKEN/X_AUTH_TOKEN from env variable, if it exists. X_AUTH_TOKEN takes priority.
    if "X_AUTH_TOKEN" in os.environ:
        CLOUDGENIX_AUTH_TOKEN = os.environ.get('X_AUTH_TOKEN')
    elif "AUTH_TOKEN" in os.environ:
        CLOUDGENIX_AUTH_TOKEN = os.environ.get('AUTH_TOKEN')
    else:
        # not set
        CLOUDGENIX_AUTH_TOKEN = None

try:
    from cloudgenix_settings import CLOUDGENIX_USER, CLOUDGENIX_PASSWORD

except ImportError:
    # will get caught below
    CLOUDGENIX_USER = None
    CLOUDGENIX_PASSWORD = None

#
# Global Translation Dicts
#
siteid_nwstackid = {}
siteid_nwpolid = {}
siteid_qosstackid = {}
siteid_natstackid = {}
siteid_secpolid = {}
siteid_sitename = {}
sitename_siteid = {}
appname_appid = {}
appid_appname = {}
secpolname_secpolid = {}
secpolid_secpolname = {}
secpolid_secruleslist = {}
globalpfid_globalpfname = {}
localpfid_localpfname = {}
sitelocalpfid_sitelocalpfname = {}
zoneid_zonename = {}

def create_dicts(cgx_session):
    print("Getting data..")
    #
    # AppDefs
    #
    print("\tApp Defs")
    resp = cgx_session.get.appdefs()
    if resp.cgx_status:
        applist = resp.cgx_content.get("items",None)
        for app in applist:
            appname_appid[app["display_name"]] = app["id"]
            appid_appname[app["id"]] = app["display_name"]

    else:
        print("ERR: Could not retrieve appdefs")
        cloudgenix.jd_detailed(resp)

    #
    # Sites
    #
    print("\tSites")
    resp = cgx_session.get.sites()
    if resp.cgx_status:
        sitelist = resp.cgx_content.get("items",None)

        for site in sitelist:
            sid = site["id"]
            siteid_sitename[sid] = site["name"]
            sitename_siteid[site["name"]] = sid
            siteid_nwstackid[sid] = site["network_policysetstack_id"]
            siteid_nwpolid[sid] = site["policy_set_id"]
            siteid_qosstackid[sid] = site["priority_policysetstack_id"]
            siteid_natstackid[sid] = site["nat_policysetstack_id"]
            siteid_secpolid[sid] = site["security_policyset_id"]

    else:
        print("ERR: Could not retrieve sites")
        cloudgenix.jd_detailed(resp)


    #
    # Security Pol Sets
    #
    print("\tSecurity Policy Sets & Rules")

    resp = cgx_session.get.securitypolicysets()
    if resp.cgx_status:
        itemlist = resp.cgx_content.get("items", None)
        for item in itemlist:
            secpolname_secpolid[item["name"]] = item["id"]
            secpolid_secpolname[item["id"]] = item["name"]

            resp = cgx_session.get.securitypolicyrules(securitypolicyset_id=item["id"])
            if resp.cgx_status:
                ruleslist = resp.cgx_content.get("items", None)
                secpolid_secruleslist[item["id"]] = ruleslist
            else:
                print("ERR: Could not retrieve Rules for Security Policy Set {}".format(item["name"]))
                cloudgenix.jd_detailed(resp)

    else:
        print("ERR: Could not retrieve Security Policy Sets")
        cloudgenix.jd_detailed(resp)

    #
    # Global Prefix Filter
    #
    print("\tGlobal Prefix Filters")

    resp = cgx_session.get.globalprefixfilters()
    if resp.cgx_status:
        itemlist = resp.cgx_content.get("items", None)
        for item in itemlist:
            globalpfid_globalpfname[item["id"]] = item["name"]
    else:
        print("ERR: Could not retrieve Global Prefix Filters")
        cloudgenix.jd_detailed(resp)

    #
    # Local Prefix Filter
    #
    print("\tLocal Prefix Filters")

    resp = cgx_session.get.localprefixfilters()
    if resp.cgx_status:
        itemlist = resp.cgx_content.get("items", None)
        for item in itemlist:
            localpfid_localpfname[item["id"]] = item["name"]
    else:
        print("ERR: Could not retrieve Local Prefix Filters")
        cloudgenix.jd_detailed(resp)

    # #
    # # Site Local Prefix Filter
    # #
    # for sid in siteid_sitename.keys():
    #
    #     resp = cgx_session.get.prefixfilters(site_id=sid)
    #     if resp.cgx_status:
    #         itemlist = resp.cgx_content.get("items", None)
    #         for item in itemlist:
    #             sitelocalpfid_sitelocalpfname[item["id"]] = item["name"]
    #     else:
    #         print("ERR: Could not retrieve Site Prefix Filters")
    #         cloudgenix.jd_detailed(resp)

    #
    # Zones
    #
    print("\tSecurity Zones")

    resp = cgx_session.get.securityzones()
    if resp.cgx_status:
        itemlist = resp.cgx_content.get("items", None)
        for item in itemlist:
            zoneid_zonename[item["id"]] = item["name"]
    else:
        print("ERR: Could not retrieve Security Zones")
        cloudgenix.jd_detailed(resp)

    return



def getsites(policy_id, policy_type):
    sites = []
    if policy_type == "security":
        for sid in siteid_secpolid.keys():
            if siteid_secpolid[sid] == policy_id:
                sites.append(siteid_sitename[sid])

    elif policy_type == "nwstack":
        for sid in siteid_nwstackid.keys():
            if siteid_nwstackid[sid] == policy_id:
                sites.append(siteid_sitename[sid])

    elif policy_type == "qosstack":
        for sid in siteid_qosstackid.keys():
            if siteid_qosstackid[sid] == policy_id:
                sites.append(siteid_sitename[sid])

    elif policy_type == "natstack":
        for sid in siteid_natstackid.keys():
            if siteid_natstackid[sid] == policy_id:
                sites.append(siteid_sitename[sid])

    elif policy_type == "original":
        for sid in siteid_nwpolid.keys():
            if siteid_nwpolid[sid] == policy_id:
                sites.append(siteid_sitename[sid])

    return sites


def clean_exit(cgx_session):
    cgx_session.get.logout()
    sys.exit()


def go():
    ############################################################################
    # Begin Script, parse arguments.
    ############################################################################

    # Parse arguments
    parser = argparse.ArgumentParser(description="{0}.".format(SCRIPT_NAME))

    # Allow Controller modification and debug level sets.
    controller_group = parser.add_argument_group('API', 'These options change how this program connects to the API.')
    controller_group.add_argument("--controller", "-C",
                                  help="Controller URI, ex. "
                                       "C-Prod: https://api.elcapitan.cloudgenix.com",
                                  default="https://api.elcapitan.cloudgenix.com")

    login_group = parser.add_argument_group('Login', 'These options allow skipping of interactive login')
    login_group.add_argument("--email", "-E", help="Use this email as User Name instead of prompting",
                             default=None)
    login_group.add_argument("--pass", "-P", help="Use this Password instead of prompting",
                             default=None)

    # Commandline for entering Policy info
    #policy_group = parser.add_argument_group('Policy Specific Information','Information shared here will be used to get details about the policy sets & its associated sites')
    #policy_group.add_argument("--policytype", "-PT", help="Select Policy Type. Pick from: SECURITY, NETWORK, QOS, NAT, ALL", default=None)


    args = vars(parser.parse_args())

    ############################################################################
    # Parse Args
    ############################################################################
    #policytype = args["policytype"]

    ############################################################################
    # Instantiate API & Login
    ############################################################################

    cgx_session = cloudgenix.API(controller=args["controller"], ssl_verify=False)
    print("{0} v{1} ({2})\n".format(SCRIPT_NAME, SDK_VERSION, cgx_session.controller))

    # login logic. Use cmdline if set, use AUTH_TOKEN next, finally user/pass from config file, then prompt.
    # figure out user
    if args["email"]:
        user_email = args["email"]
    elif CLOUDGENIX_USER:
        user_email = CLOUDGENIX_USER
    else:
        user_email = None

    # figure out password
    if args["pass"]:
        user_password = args["pass"]
    elif CLOUDGENIX_PASSWORD:
        user_password = CLOUDGENIX_PASSWORD
    else:
        user_password = None

    # check for token
    if CLOUDGENIX_AUTH_TOKEN and not args["email"] and not args["pass"]:
        cgx_session.interactive.use_token(CLOUDGENIX_AUTH_TOKEN)
        if cgx_session.tenant_id is None:
            print("AUTH_TOKEN login failure, please check token.")
            sys.exit()

    else:
        while cgx_session.tenant_id is None:
            cgx_session.interactive.login(user_email, user_password)
            # clear after one failed login, force relogin.
            if not cgx_session.tenant_id:
                user_email = None
                user_password = None

    ############################################################################
    # Create Translation Dicts
    ############################################################################
    create_dicts(cgx_session)

    ############################################################################
    # Get App Usage
    ############################################################################

    policydata = pd.DataFrame()

    for secid in secpolid_secpolname.keys():

        secpolname = secpolid_secpolname[secid]
        print("Processing data for Sec Policy {}".format(secpolname))

        sites = getsites(secid,SECURITY_POL)
        rules = secpolid_secruleslist[secid]



        for rule in rules:
            action = rule.get("action", None)
            appids = rule.get("application_ids", None)
            desc = rule.get("description", None)
            source_filter_ids = rule.get("source_filter_ids", None)
            destination_filter_ids = rule.get("destination_filter_ids", None)
            source_zone_ids = rule.get("source_zone_ids", None)
            destination_zone_ids = rule.get("destination_zone_ids", None)
            disabled_flag = rule.get("disabled_flag",None)
            name = rule.get("name", None)
            id = rule.get("id", None)

            #
            # Apps
            #
            appids_text=""
            if appids is None:
                appids_text = "None"

            elif appids == ["any"]:
                appids_text = "any"


            else:
                for appid in appids:
                    appname = appid_appname[appid]
                    appids_text += "{}; ".format(appname)

            #
            # Source Prefix Filter
            #
            source_filter_ids_text = ""
            if source_filter_ids is None:
                source_filter_ids_text = "None"
            elif source_filter_ids == ["any"]:
                source_filter_ids_text = "any"
            else:
                for pfid in source_filter_ids:
                    if pfid in globalpfid_globalpfname.keys():
                        source_filter_ids_text += "{} (global); ".format(globalpfid_globalpfname[pfid])
                    elif pfid in localpfid_localpfname.keys():
                        source_filter_ids_text += "{} (local); ".format(localpfid_localpfname[pfid])
                    else:
                        source_filter_ids_text += "{}; ".format(pfid)

            #
            # Dest Prefix Filter
            #
            destination_filter_ids_text = ""
            if destination_filter_ids is None:
                destination_filter_ids_text = "None"
            elif destination_filter_ids == ["any"]:
                destination_filter_ids_text = "any"
            else:
                for pfid in destination_filter_ids:
                    if pfid in globalpfid_globalpfname.keys():
                        destination_filter_ids_text += "{} (global); ".format(globalpfid_globalpfname[pfid])
                    elif pfid in localpfid_localpfname.keys():
                        destination_filter_ids_text += "{} (local); ".format(localpfid_localpfname[pfid])
                    else:
                        destination_filter_ids_text += "{}; ".format(pfid)


            #
            # Source Zone
            #
            source_zone_ids_text = ""
            if source_zone_ids is None:
                source_zone_ids_text = "None"
            elif source_zone_ids == ["any"]:
                source_zone_ids_text = "any"
            else:
                for zid in source_zone_ids:
                    if zid in zoneid_zonename.keys():
                        source_zone_ids_text += "{}; ".format(zoneid_zonename[zid])
                    else:
                        source_zone_ids_text += "{}; ".format(zid)

            #
            # Destination Zone
            #
            destination_zone_ids_text = ""
            if destination_zone_ids is None:
                destination_zone_ids_text = "None"
            elif destination_zone_ids == ["any"]:
                destination_zone_ids_text = "any"
            else:
                for zid in destination_zone_ids:
                    if zid in zoneid_zonename.keys():
                        destination_zone_ids_text += "{}; ".format(zoneid_zonename[zid])
                    else:
                        destination_zone_ids_text += "{}; ".format(zid)

            policydata = policydata.append({"policyset": secpolname,
                                            "policyset_id": secid,
                                            "sites": sites,
                                            "ruleid": id,
                                            "rulename": name,
                                            "description": desc,
                                            "action": action,
                                            "applications": appids_text,
                                            "source_filter": source_filter_ids_text,
                                            "destination_filter": destination_filter_ids_text,
                                            "source_zone": source_zone_ids_text,
                                            "destination_zone": destination_zone_ids_text,
                                            "disabled": disabled_flag}, ignore_index=True)
    ############################################################################
    # Save Data to CSV
    ############################################################################
    # get time now.
    curtime_str = datetime.datetime.utcnow().strftime('%Y-%m-%d-%H-%M-%S')

    # create file-system friendly tenant str.
    tenant_str = "".join(x for x in cgx_session.tenant_name if x.isalnum()).lower()

    # Set filename
    csvfile = os.path.join('./', '%s_policydata_%s.csv' % (tenant_str, curtime_str))
    print("Writing data to file {}".format(csvfile))
    policydata.to_csv(csvfile, index=False)

    ############################################################################
    # Logout to clear session.
    ############################################################################
    cgx_session.get.logout()

    print("INFO: Logging Out")
    sys.exit()

if __name__ == "__main__":
    go()
