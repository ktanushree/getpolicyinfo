#!/usr/bin/env python
"""
Prisma SDWAN script to lists the policy sets and its rules
tkamath@paloaltonetworks.com
Note:
    Version 1.0.0 b1 only retrieves Security Policy Details
    Version 1.0.0 b2 retrieves prefix filters and zone mapping in separate CSVs

Version: 1.0.0 b2
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
globalpfid_globalprefixlist = {}
localpfid_localpfname = {}
localpfid_localpfbind = {}
localpfidsid_localpfbind = {}
zoneid_zonename = {}
nwid_nwname = {}
nwid_nwtype = {}
labelid_labelname = {}
labelid_labellabel = {}
swiid_swiname = {}
zid_sitebind = {}
zidsid_sitebind = {}
zid_elembind = {}
zidsideid_elembind = {}
elemid_elemname = {}
elemid_siteid = {}
lannwid_ipconfig = {}
wanoverlayid_wanoverlayname = {}
intfid_intfname = {}



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
    # WAN Labels
    #
    print("\tWAN Interface Labels")
    resp = cgx_session.get.waninterfacelabels()
    if resp.cgx_status:
        itemlist = resp.cgx_content.get("items",None)
        for item in itemlist:
            labelid_labelname[item["id"]] = item["name"]
            labelid_labellabel[item["id"]] = item["label"]
    else:
        print("ERR: Could not retrieve WAN Interface Labels")
        cloudgenix.jd_detailed(resp)

    #
    # WAN Networks
    #
    print("\tWAN Networks")
    resp = cgx_session.get.wannetworks()
    if resp.cgx_status:
        itemlist = resp.cgx_content.get("items", None)
        for item in itemlist:
            nwid_nwname[item["id"]] = item["name"]
            nwid_nwtype[item["id"]] = item["type"]
    else:
        print("ERR: Could not retrieve WAN Networks")
        cloudgenix.jd_detailed(resp)
    #
    # Sites
    #
    print("\tSites & Site WAN Interfaces")
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

            resp = cgx_session.get.waninterfaces(site_id=sid)
            if resp.cgx_status:
                swilist = resp.cgx_content.get("items",None)
                for swi in swilist:
                    swiname = swi.get("name",None)
                    if swiname is not None:
                        swiid_swiname[swi["id"]] = swi["name"]
                    else:
                        swiname = "{} Circuit to {}".format(labelid_labelname[swi["label_id"]],nwid_nwname[swi["network_id"]])
                        swiid_swiname[swi["id"]] = swiname
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
            filters = item.get("filter", None)
            if filters is not None:
                ip_prefixes = filters.get("ip_prefixes", None)
                ip_prefixes_text = ""
                for x in ip_prefixes:
                    ip_prefixes_text = "{}; ".format(x)

                globalpfid_globalprefixlist[item["id"]] = ip_prefixes_text
            else:
                globalpfid_globalprefixlist[item["id"]] = "-"
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

            data = {
                "query_params": {
                    "prefix_filter_id": {
                        "eq": item["id"]
                    }
                },
                "getDeleted": False
            }
            prefix_text = ""
            prefix_text_site = ""
            resp = cgx_session.post.tenant_prefixfilters_query(data=data)
            if resp.cgx_status:
                prefixfilters = resp.cgx_content.get("items", None)
                for pf in prefixfilters:
                    sid = pf.get("site_id", None)
                    sname = siteid_sitename[sid]
                    filters = pf.get("filters", None)
                    for filter in filters:
                        ip_prefixes = filter.get("ip_prefixes", None)

                        prefix_text += "{}; ".format(ip_prefixes)
                        prefix_text_site += "{}; ({})".format(ip_prefixes,sname)

                    localpfidsid_localpfbind[(item["id"],sid)] = prefix_text

            else:
                print("ERR: Could not retrieve Prefix Filters Bindings")
                cloudgenix.jd_detailed(resp)

            localpfid_localpfbind[item["id"]] = prefix_text_site
    else:
        print("ERR: Could not retrieve Local Prefix Filters")
        cloudgenix.jd_detailed(resp)


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

    #
    # Site Security Zones
    #
    print("\tSite Security Zones")
    for sid in siteid_sitename.keys():
        sname = siteid_sitename[sid]
        resp = cgx_session.get.sitesecurityzones(site_id=sid)
        if resp.cgx_status:
            itemlist = resp.cgx_content.get("items", None)
            for item in itemlist:
                zid = item.get("zone_id", None)
                networks = item.get("networks", None)
                nw_text = ""
                for nw in networks:
                    swiid = nw["network_id"]
                    if swiid in swiid_swiname.keys():
                        swiname = swiid_swiname[swiid]
                    else:
                        swiname = swiid

                    nw_text += "{}; ".format(swiname)

                zidsid_sitebind[(zid,sid)] = nw_text
                if zid in zid_sitebind.keys():
                    sitebind = zid_sitebind[zid]
                    sitebind.append({sid: nw_text})
                    zid_sitebind[zid] = sitebind
                else:
                    sitebind = [{sid: nw_text}]
                    zid_sitebind[zid] = sitebind

        else:
            print("ERR: Could not retrieve Site Security Zones for {}".format(sname))
            cloudgenix.jd_detailed(resp)


    print("\tElements")
    resp = cgx_session.get.elements()
    if resp.cgx_status:
        itemlist = resp.cgx_content.get("items",None)
        for item in itemlist:
            elemid_elemname[item["id"]] = item["name"]
            if item["site_id"] == "1":
                continue
            else:
                elemid_siteid[item["id"]] = item["site_id"]
    else:
        print("ERR: Could not retrieve Elements")
        cloudgenix.jd_detailed(resp)


    print("\tInterfaces")
    for eid in elemid_siteid.keys():
        sid = elemid_siteid[eid]
        resp = cgx_session.get.interfaces(site_id=sid, element_id=eid)
        if resp.cgx_status:
            itemlist = resp.cgx_content.get("items", None)
            for item in itemlist:
                intfid_intfname[(sid,eid,item["id"])] = item["name"]
        else:
            print("ERR: Could not retrieve Interfaces")
            cloudgenix.jd_detailed(resp)

    print("\tLAN Networks")
    for sid in siteid_sitename.keys():
        resp = cgx_session.get.lannetworks(site_id=sid)
        if resp.cgx_status:
            itemlist = resp.cgx_content.get("items", None)
            for item in itemlist:
                ipv4_config = item.get("ipv4_config", None)
                default_routers = ipv4_config.get("default_routers", None)
                lannwid_ipconfig[item["id"]] = default_routers
        else:
            print("ERR: Could not retrieve LAN Networks")
            cloudgenix.jd_detailed(resp)

    print("\tWAN Overlay")
    resp = cgx_session.get.wanoverlays()
    if resp.cgx_status:
        itemlist = resp.cgx_content.get("items", None)
        for item in itemlist:
            wanoverlayid_wanoverlayname[item["id"]] = item["name"]
    else:
        print("ERR: Could not retrieve LAN Networks")
        cloudgenix.jd_detailed(resp)

    print("\tElement Security Zones")
    for eid in elemid_siteid.keys():
        sid = elemid_siteid[eid]
        resp = cgx_session.get.elementsecurityzones(site_id=sid, element_id=eid)
        if resp.cgx_status:
            itemlist = resp.cgx_content.get("items", None)
            for item in itemlist:
                zid = item.get("zone_id", None)

                # Extract Interfaces
                interface_ids = item.get("interface_ids", None)
                interface_ids_text = ""
                if interface_ids is not None:
                    for intfid in interface_ids:
                        interface_ids_text += "{}; ".format(intfid_intfname[(sid,eid,intfid)])

                # Extract LAN Networks
                lannetwork_ids = item.get("lannetwork_ids", None)
                lannetwork_ids_text = ""
                if lannetwork_ids is not None:
                    for lannwid in lannetwork_ids:
                        lannetwork_ids_text += "{}; ".format(lannwid_ipconfig[lannwid])

                # Extract WAN Interfaces
                waninterface_ids = item.get("waninterface_ids", None)
                waninterface_ids_text = ""
                if waninterface_ids is not None:
                    for swi in waninterface_ids:
                        waninterface_ids_text += "{}; ".format(swiid_swiname[swi])

                # Extract WAN Overlay
                wanoverlay_ids = item.get("wanoverlay_ids", None)
                wanoverlay_ids_text = ""
                if wanoverlay_ids is not None:
                    for wid in wanoverlay_ids:
                        wanoverlay_ids_text += "{}; ".format(wanoverlayid_wanoverlayname[wid])

                zidsideid_elembind[(zid,sid,eid)] = {
                    "interface_ids":interface_ids_text,
                    "lannetwork_ids":lannetwork_ids_text,
                    "waninterface_ids": waninterface_ids_text,
                    "wanoverlay_ids": wanoverlay_ids_text
                }

                if zid in zid_elembind.keys():
                    elembind = zid_elembind[zid]
                    elembind.append({eid:{"interface_ids":interface_ids_text,
                                          "lannetwork_ids":lannetwork_ids_text,
                                          "waninterface_ids": waninterface_ids_text,
                                          "wanoverlay_ids": wanoverlay_ids_text}})
                    zid_elembind[zid] = elembind

                else:
                    elembind = {eid: {"interface_ids": interface_ids_text,
                                      "lannetwork_ids": lannetwork_ids_text,
                                      "waninterface_ids": waninterface_ids_text,
                                      "wanoverlay_ids": wanoverlay_ids_text}}

                    zid_elembind[zid] = [elembind]

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
            source_filter_prefix_text = ""
            if source_filter_ids is None:
                source_filter_ids_text = "None"
                source_filter_prefix_text = "None"
            elif source_filter_ids == ["any"]:
                source_filter_ids_text = "any"
                source_filter_prefix_text = "any"
            else:
                for pfid in source_filter_ids:
                    if pfid in globalpfid_globalpfname.keys():
                        source_filter_ids_text += "{} (global); ".format(globalpfid_globalpfname[pfid])
                        source_filter_prefix_text += "{}; ".format(globalpfid_globalprefixlist[pfid])
                    elif pfid in localpfid_localpfname.keys():
                        source_filter_ids_text += "{} (local); ".format(localpfid_localpfname[pfid])
                        source_filter_prefix_text += "{}; ".format(localpfid_localpfbind[pfid])
                    else:
                        source_filter_ids_text += "{}; ".format(pfid)
                        source_filter_prefix_text += "{}; ".format(pfid)

                source_filter_ids_text = source_filter_ids_text[:-2]
                source_filter_prefix_text = source_filter_prefix_text[:-2]

            #
            # Dest Prefix Filter
            #
            destination_filter_ids_text = ""
            destination_filter_prefix_text = ""
            if destination_filter_ids is None:
                destination_filter_ids_text = "None"
                destination_filter_prefix_text = "None"
            elif destination_filter_ids == ["any"]:
                destination_filter_ids_text = "any"
                destination_filter_prefix_text = "any"
            else:
                for pfid in destination_filter_ids:
                    if pfid in globalpfid_globalpfname.keys():
                        destination_filter_ids_text += "{} (global); ".format(globalpfid_globalpfname[pfid])
                        destination_filter_prefix_text += "{}; ".format(globalpfid_globalprefixlist[pfid])
                    elif pfid in localpfid_localpfname.keys():
                        destination_filter_ids_text += "{} (local); ".format(localpfid_localpfname[pfid])
                        destination_filter_prefix_text += "{}; ".format(localpfid_localpfbind[pfid])
                    else:
                        destination_filter_ids_text += "{}; ".format(pfid)
                        destination_filter_prefix_text += "{}; ".format(pfid)

                destination_filter_ids_text = destination_filter_ids_text[:-2]
                destination_filter_prefix_text = destination_filter_prefix_text[:-2]

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

                source_zone_ids_text = source_zone_ids_text[:-2]

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

                destination_zone_ids_text = destination_zone_ids_text[:-2]

            policydata = policydata.append({"policyset": secpolname,
                                            "policyset_id": secid,
                                            "sites": sites,
                                            "ruleid": id,
                                            "rulename": name,
                                            "description": desc,
                                            "action": action,
                                            "applications": appids_text,
                                            "source_filter": source_filter_ids_text,
                                            #"source_prefix": source_filter_prefix_text,
                                            "destination_filter": destination_filter_ids_text,
                                            #"destination_prefix": destination_filter_prefix_text,
                                            "source_zone": source_zone_ids_text,
                                            "destination_zone": destination_zone_ids_text,
                                            "disabled": disabled_flag}, ignore_index=True)

    zonedata = pd.DataFrame()

    for zid in zoneid_zonename.keys():
        zname = zoneid_zonename[zid]

        for eid in elemid_siteid.keys():
            sid = elemid_siteid[eid]
            ename = elemid_elemname[eid]
            sname = siteid_sitename[sid]

            if (zid,sid) in zidsid_sitebind.keys():
                sitebind = zidsid_sitebind[(zid,sid)]
            else:
                sitebind = "-"

            if (zid,sid,eid) in zidsideid_elembind.keys():
                elembind = zidsideid_elembind[(zid,sid,eid)]
            else:
                elembind="-"

            zonedata = zonedata.append({"zone_id": zid,
                                        "zone_name": zname,
                                        "site_id": sid,
                                        "site_name": sname,
                                        "site_binding": sitebind,
                                        "element_id":eid,
                                        "element_name":ename,
                                        "element_binding": elembind}, ignore_index=True)


    prefixdata = pd.DataFrame()
    for pfid  in globalpfid_globalpfname.keys():
        pfname = globalpfid_globalpfname[pfid]
        prefix = globalpfid_globalprefixlist[pfid]

        prefixdata = prefixdata.append({"type": "Global",
                                        "id":pfid,
                                        "name": pfname,
                                        "prefixlist":prefix,
                                        "site": "-"}, ignore_index=True)

    for pfid in localpfid_localpfname.keys():
        pfname = localpfid_localpfname[pfid]
        for sid in siteid_sitename.keys():
            sname = siteid_sitename[sid]

            if (pfid,sid) in localpfidsid_localpfbind.keys():
                binddata = localpfidsid_localpfbind[(pfid,sid)]
                prefixdata = prefixdata.append({"type":"Local",
                                                "id": pfid,
                                                "name":pfname,
                                                "prefixlist": binddata,
                                                "site":sname},ignore_index=True)

    ############################################################################
    # Save Data to CSV
    ############################################################################
    # get time now.
    curtime_str = datetime.datetime.utcnow().strftime('%Y-%m-%d-%H-%M-%S')

    # create file-system friendly tenant str.
    tenant_str = "".join(x for x in cgx_session.tenant_name if x.isalnum()).lower()

    # Set filename
    csvfile_policyinfo = os.path.join('./', '%s_policydata_%s.csv' % (tenant_str, curtime_str))
    csvfile_zonemapping = os.path.join('./', '%s_zonemapping_%s.csv' % (tenant_str, curtime_str))
    csvfile_prefixmapping = os.path.join('./', '%s_prefixmapping_%s.csv' % (tenant_str, curtime_str))

    print("Writing data to files: \n\t{}\n\t{}\n\t{}".format(csvfile_policyinfo,csvfile_zonemapping,csvfile_prefixmapping))
    policydata.to_csv(csvfile_policyinfo, index=False)
    zonedata.to_csv(csvfile_zonemapping, index=False)
    prefixdata.to_csv(csvfile_prefixmapping, index=False)

    ############################################################################
    # Logout to clear session.
    ############################################################################
    cgx_session.get.logout()

    print("INFO: Logging Out")
    sys.exit()

if __name__ == "__main__":
    go()
