import os
import sys
import re
import csv
import json
import sqlite3
import getpass
import requests
import datetime
import argparse
from operator import itemgetter


# Regex match RFC3339 date
def timeRegex( var ):
	var = str(re.compile('^([0-9]{4})-(0[1-9]|1[012])-(0[1-9]|[12][0-9]|3[01])T([01][0-9]|2[0-3]):([0-5][0-9]):([0-5][0-9]|60)(\.[0-9]+)?(Z)').search(var))
	if 'Match' not in var:
		print('Error: Timestamps must follow this pattern exactly: YYYY-MM-DDT00:00:00Z\n')
		quit()

# Input arguments
parser = argparse.ArgumentParser()
parser.add_argument('-output', help='Override output CSV filename. If file exists, data will be appended (default: CloudflareOutline-YYYY-MM-DD.csv)', required=False, metavar='')
parser.add_argument('-dbpersist', help='Keep SQL Database on disk, do not delete it after report is written.', required=False, action='store_true')
parser.add_argument('-noheaders', help='Remove headers (ex: Organization Name) from CSV.', required=False, action='store_true')
parser.add_argument('-since', help='Start of report timeframe (YYYY-MM-DDT00:00:00Z)', required=False, metavar='')
parser.add_argument('-until', help='End of report timeframe (YYYY-MM-DDT00:00:00Z)', required=False, metavar='')
parser.add_argument('-email', help='Email address)', required=False, metavar='')
parser.add_argument('-key', help='API key', required=False, metavar='')
args = parser.parse_args()

# Parse arguments
if args.email:
	email = args.email
else:
    email = raw_input('Email Address: ')
if args.key:
	key = args.key
else:
    key = getpass.getpass('API Key:')
if args.since:
	timeRegex(args.since)
	since = args.since
if args.until:
	timeRegex(args.until)
	until = args.until

# Update standard API session params
apiSession = requests.Session()
apiSession.headers.update({"X-Auth-Email": "%s" % email,
						   "X-Auth-Key": "%s" % key,
						   "Content-Type": "application/json"})
apiSession.params.update({"per_page": "50"})

# Declare variables
cfApi = "https://api.cloudflare.com/client/v4"
now = str(datetime.datetime.now())[:10] + str(datetime.datetime.now())[20:]
dbname = 'cf-%s.db' % (now)
db = sqlite3.connect(dbname)
cursor = db.cursor()
zonesData = []
orgsData = []

# GET all orgs
def allOrgs():
    allOrgs = apiSession.get("%s/user/organizations" % (cfApi))
    orgsJson = json.loads(allOrgs.content)
    return orgsJson

# GET all zones
def allZones():
    allZones = apiSession.get("%s/zones" % (cfApi))
    zonesJson = json.loads(allZones.content)
    return zonesJson

# GET zone analytics
def zoneAnalytics( zone ):
    zoneID = zone[4]
    #Get analytics and parse them
    if args.since and args.until:
        zoneAnalytics = apiSession.get("%s/zones/%s/analytics/dashboard?since=%s&until=%s" % (cfApi, zoneID,since,until))
    else:
        zoneAnalytics = apiSession.get("%s/zones/%s/analytics/dashboard" % (cfApi, zoneID))

    if not zoneAnalytics.ok:
        sys.exit(zoneAnalytics.content)

    analyticsJson = json.loads(zoneAnalytics.content)['result']['totals']
    totalBandwidth = analyticsJson['bandwidth']['all']
    totalThreats = analyticsJson['threats']['all']
    countryThreats = analyticsJson['threats']['country']
    
    # Add all threats, by CC, with org info to table
    for country, value in countryThreats.iteritems():
        threatsByCC = [zone[0],zone[1],zone[2],zone[3],country,value]
        threatsInsert(threatsByCC)

	# Check for top threat country. If none, insert a null value
    if countryThreats and len(str(countryThreats)) > 3:
        topcountryThreat = max(countryThreats.items(), key=lambda k: k[1])
    else:
        topcountryThreat = ['N/A', 0]

    # Add all to list and return
    analyticsResults = [totalBandwidth,totalThreats,topcountryThreat[0]]
    return analyticsResults

# GET zone details
def zoneDetails( zone ):
    zoneID = zone[4]
    #Get WAF status
    wafStatus = apiSession.get("%s/zones/%s/settings/waf" % (cfApi, zoneID))
    wafStatus = json.loads(wafStatus.content)['result']['value']

    # Get Security Level
    securityLevel = apiSession.get("%s/zones/%s/settings/security_level" % (cfApi, zoneID))
    securityLevel = json.loads(securityLevel.content)['result']['value']

    if 'Free' in str(zone):
            owaspSensitivity = 'N/A'
            owaspMode = 'N/A'
    else:
        # Get OWASP status
        owaspStatus = apiSession.get("%s/zones/%s/firewall/waf/packages" % (cfApi, zoneID))
        owaspStatus = json.loads(owaspStatus.content)['result']
        for package in owaspStatus:
            if 'OWASP ModSecurity' in package['name']:
                owaspSensitivity = package['sensitivity']
                owaspMode = package['action_mode']

    # Add all to list and return
    detailsResults = [wafStatus,securityLevel,owaspSensitivity,owaspMode]
    return detailsResults

# SQLite Org Entry
def orgInsert( org ):
    cursor.execute('''CREATE TABLE IF NOT EXISTS orgs(id INTEGER PRIMARY KEY, orgID TEXT, orgName TEXT)''')
    cursor.execute('''INSERT INTO orgs(orgID, orgName)VALUES(?,?)''', (org[0],org[1]))
    db.commit()

# SQL Threats Entry
def threatsInsert( threatsByCC ):
    cursor.execute('''CREATE TABLE IF NOT EXISTS threatsByCC(id INTEGER PRIMARY KEY, orgID TEXT, zoneName TEXT, orgName TEXT, planType TEXT, cc TEXT, value TEXT)''')
    cursor.execute('''INSERT INTO threatsByCC(orgID, zoneName, orgName, planType, cc, value)VALUES(?,?,?,?,?,?)''', (threatsByCC[0],threatsByCC[1],threatsByCC[2],threatsByCC[3],threatsByCC[4],threatsByCC[5]))
    db.commit()

# SQLite Zone Entry
def zoneInsert( zone ):
    cursor.execute('''CREATE TABLE IF NOT EXISTS zones(id INTEGER PRIMARY KEY, orgID TEXT, zoneName TEXT, orgName TEXT,
        planType TEXT, zoneID TEXT, ns1 TEXT, ns2 TEXT, totalBandwidth TEXT, totalThreats TEXT,
        topcountryThreat TEXT, wafStatus TEXT, securityLevel TEXT, owaspSensitivity TEXT, owaspMode TEXT)
    ''')
    cursor.execute('''INSERT INTO zones(orgID, zoneName, orgName, planType, zoneID, ns1, ns2, totalBandwidth,
        totalThreats, topcountryThreat, wafStatus, securityLevel, owaspSensitivity, owaspMode)
        VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)''', (zone[0],zone[1],zone[2],zone[3],zone[4],zone[5],zone[6],zone[7],zone[8],zone[9],zone[10],zone[11],zone[12],zone[13]))
    db.commit()

# Get org data
allOrgsRes = allOrgs()
if 'result_info' in allOrgsRes:
    orgsPages = allOrgsRes['result_info']['total_pages']
    orgsPage = 0
    while orgsPage != orgsPages:
        orgsPage += 1
        apiSession.params.update({"page": str(orgsPage)})
        orgsJson = allOrgs()
        for result in orgsJson['result']:
            results = [
                result['id'],
                result['name']
            ]
                    #TO-DO - add removal of SELF user org
            orgsData.insert(0, results)
            orgsData = sorted(orgsData, key=itemgetter(0))

    # Insert Orgs into DB
    for org in orgsData:
            if org[1] != 'SELF':
                    orgInsert(org)
else:
    sys.exit(allOrgsRes)

# Get zone data
allZonesRes = allZones()
if 'result_info' in allZonesRes:
    zonesPages = allZonesRes['result_info']['total_pages']
    zonesPage = 0
    while zonesPage != zonesPages:
        zonesPage += 1
        apiSession.params.update({"page": str(zonesPage)})

        zonesJson = allZones()
        for result in zonesJson['result']:
            try:
                ns1 = result['name_servers'][0]
                ns2 = result['name_servers'][1]
            except KeyError:
                ns1 = 'CNAME Setup'
                ns2 = ''
            results = [
                result['owner']['id'],
                result['name'],
                result['owner']['name'],
                result['plan']['name'],
                result['id'],
                ns1,
                ns2
            ]
            zonesData.insert(0, results)
            zonesData = sorted(zonesData, key=itemgetter(0))
else:
    sys.exit(allZonesRes)

# Reset page param for future API calls
apiSession.params.update({"page": "1"})

# Get analytics and details per zone, add to DB
for zone in zonesData:
    analyticsResults = zoneAnalytics( zone )
    detailsResults = zoneDetails( zone )
    zoneResults = [
                    zone[0],
                    zone[1],
                    zone[2],
                    zone[3],
                    zone[4],
                    zone[5],
                    zone[6],
                    analyticsResults[0],
                    analyticsResults[1],
                    analyticsResults[2],
                    detailsResults[0],
                    detailsResults[1],
                    detailsResults[2],
                    detailsResults[3]
                ]
    # Insert zones into DB
    zoneInsert(zoneResults)

print('hi')
# Write Data to CSV
orgCursor = db.cursor()
zoneCursor = db.cursor()
zonedetailCursor = db.cursor()
threatCursor = db.cursor()

# Output file check
if args.output:
    if args.output.lower().endswith(('.csv')):
	    outputFile = args.output
    else:
		print('Error: Output file must be CSV format\n')
		quit()
else:
    outputFile = 'CloudflareOutline-' + str(datetime.datetime.now())[:10] + '.csv'

# Size conversion
def size( num ):
    for unit in ['B','KB','MB','GB','TB','PB', 'EB']:
        if abs(num) < 1024.0:
            return "%.1f%s" % (num, unit)
        num /= 1024.0

# Write to CSV
def csvWriter( var ):
    with open(outputFile, 'a') as f:
                writer = csv.writer(f)
                writer.writerow(var)

# Write report header to CSV
if not args.noheaders:
    reportHeader = ['Cloudflare Report']
    csvWriter(reportHeader)
    csvWriter('')

# Organization level information gathering.
orgCursor.execute("SELECT * FROM orgs")  
for org in orgCursor:
    orgID = org[1]
    orgName = org[2]

    # Get NS
    ns1, ns2 = [], []
    zoneCursor.execute("SELECT ns1, ns2 FROM zones WHERE orgID=?", (orgID,))
    for ns in zoneCursor:
        if str(ns1) == '[]':
            ns1.insert(0, ns[0])
        if str(ns2) == '[]':
            ns2.insert(0, ns[1])
    if str(ns1) == '[]':
        ns1 = 'No Domains'
    else:
        ns1 = ns1[0]
    if str(ns2) == '[]':
        ns2 = ''
    else:
        ns2 = ns2[0]

    # Get total number of zones
    zonesTotal = []
    zoneCursor.execute("Select orgID, orgName, count(id) FROM zones WHERE orgID = ? group by orgID", (orgID,))
    for zone in zoneCursor:
        zonesTotal.insert(0, str(zone[2]))
    if str(zonesTotal) == '[]':
        zonesTotal = '0'
    else:
        zonesTotal = zonesTotal[0]

    # Get total threats per org
    threatTotal = []
    zoneCursor.execute("select orgID, sum(value) from threatsByCC where orgID = ?", (orgID,))
    for zone in zoneCursor:
        if zone[1] is not None:
            threatTotal.insert(0, zone[1])
        else:
            threatTotal.insert(0, '0')
    threatTotal = threatTotal[0]

    # Top 5 threat country codes
    threatCCs = []
    threatCursor.execute("SELECT CC, sum(value) FROM threatsByCC WHERE orgID = ? group by cc ORDER BY CAST(sum(value) AS INTEGER) DESC limit 5", (orgID,))
    for threatCC in threatCursor:
        threatCCs.append(threatCC)
    try: threatCC1 = '%s - %s' % (threatCCs[0][0],threatCCs[0][1])
    except: threatCC1 = "N/A"
    try: threatCC2 = '%s - %s' % (threatCCs[1][0],threatCCs[1][1])
    except: threatCC2 = "N/A"
    try: threatCC3 = '%s - %s' % (threatCCs[2][0],threatCCs[2][1])
    except: threatCC3 = "N/A"
    try: threatCC4 = '%s - %s' % (threatCCs[3][0],threatCCs[3][1])
    except: threatCC4 = "N/A"
    try: threatCC5 = '%s - %s' % (threatCCs[4][0],threatCCs[4][1])
    except: threatCC5 = "N/A"

    # Get total bandwidth per org
    bandwidthTotal = []
    zoneCursor.execute("Select orgID, orgName, sum(totalBandwidth) FROM zones WHERE orgID = ?", (orgID,))
    for zone in zoneCursor:
        if zone[2] is not None:
            bandwidthTotal.insert(0, size(zone[2]))
        else:
            bandwidthTotal.insert(0, '0.0B')
    bandwidthTotal = bandwidthTotal[0]

    # Get zone bandwidth by Plan Type
    bandwidthEnt, bandwidthBiz, bandwidthPro, bandwidthFree = [], [], [], []
    zoneCursor.execute("Select orgID, orgName, planType, sum(totalBandwidth) FROM zones WHERE orgID = ? group by planType;", (orgID,))
    for zone in zoneCursor:
        if "Ent" in zone[2]:
            bandwidthEnt.insert(0, size(int(zone[3])))
        if "Bus" in zone[2]:
            bandwidthBiz.insert(0, size(int(zone[3])))
        if "Pro" in zone[2]:
            bandwidthPro.insert(0, size(int(zone[3])))
        if "Free" in zone[2]:
            bandwidthFree.insert(0, size(int(zone[3])))
    if str(bandwidthEnt) == '[]':
        bandwidthEnt.insert(0, '0.0B')
    if str(bandwidthBiz) == '[]':
        bandwidthBiz.insert(0, '0.0B')
    if str(bandwidthPro) == '[]':
        bandwidthPro.insert(0, '0.0B')
    if str(bandwidthFree) == '[]':
        bandwidthFree.insert(0, '0.0B')
    bandwidthEnt, bandwidthBiz, bandwidthPro, bandwidthFree = bandwidthEnt[0], bandwidthBiz[0], bandwidthPro[0], bandwidthFree[0]


    # Get zone counts by plan type
    zonesEnt, zonesBiz, zonesPro, zonesFree = [], [], [], []
    zoneCursor.execute("Select orgID, orgName, planType, count(id) FROM zones WHERE orgID = ? group by planType;", (orgID,))
    for zone in zoneCursor:
        if "Ent" in zone[2]:
            zonesEnt.insert(0, zone[3])
        if "Bus" in zone[2]:
            zonesBiz.insert(0, zone[3])
        if "Pro" in zone[2]:
            zonesPro.insert(0, zone[3])
        if "Free" in zone[2]:
            zonesFree.insert(0, zone[3])
    if str(zonesEnt) == '[]':
        zonesEnt.insert(0, '0')
    if str(zonesBiz) == '[]':
        zonesBiz.insert(0, '0')
    if str(zonesPro) == '[]':
        zonesPro.insert(0, '0')
    if str(zonesFree) == '[]':
        zonesFree.insert(0, '0')
    zonesEnt, zonesBiz, zonesPro, zonesFree = zonesEnt[0], zonesBiz[0], zonesPro[0], zonesFree[0]


    # Get threats by Plan Type
    threatEnt, threatBiz, threatPro, threatFree = [], [], [], []
    zoneCursor.execute("Select orgID, orgName, planType, sum(value) from threatsByCC where orgID = ? group by planType", (orgID,))
    for zone in zoneCursor:
        if "Ent" in zone[2]:
            threatEnt.insert(0, zone[3])
        if "Bus" in zone[2]:
            threatBiz.insert(0, zone[3])
        if "Pro" in zone[2]:
            threatPro.insert(0, zone[3])
        if "Free" in zone[2]:
            threatFree.insert(0, zone[3])
    if str(threatEnt) == '[]':
        threatEnt.insert(0, '0')
    if str(threatBiz) == '[]':
        threatBiz.insert(0, '0')
    if str(threatPro) == '[]':
        threatPro.insert(0, '0')
    if str(threatFree) == '[]':
        threatFree.insert(0, '0')
    threatEnt, threatBiz, threatPro, threatFree = threatEnt[0], threatBiz[0], threatPro[0], threatFree[0]

    
    # Org level stats
    orgHeader = ['Organization Name','','Top Threat Locations','','','','Number of Zones','Bandwidth','Threat Count']
    orgLine1 = [orgName,'','1. ' + threatCC1,'','','Total',zonesTotal,bandwidthTotal,threatTotal]
    orgLine2 = ['','','2. ' + threatCC2,'','','Free',zonesFree,bandwidthFree,threatFree]
    orgLine3 = ['Nameservers','','3. ' + threatCC3,'','','Pro',zonesPro,bandwidthPro,threatPro]
    orgLine4 = [ns1,'','4. ' + threatCC4,'','','Biz',zonesBiz,bandwidthBiz,threatBiz]
    orgLine5 = [ns2,'','5. ' + threatCC5,'','','Ent',zonesEnt,bandwidthEnt,threatEnt]

    # Write organization level data to CSV
    if not args.noheaders:
        csvWriter(orgHeader)
    csvWriter(orgLine1)
    csvWriter(orgLine2) 
    csvWriter(orgLine3)
    csvWriter(orgLine4) 
    csvWriter(orgLine5)
    csvWriter('')

    # Domain level information gathering.
    zonedetailCursor.execute("SELECT * FROM zones WHERE orgID=?", (orgID,))
    if zonesTotal != '0':
        zoneHeader = ['','Domain','Top Threat Location','Plan Type','Bandwidth','Threat Count','WAF Status','OWASP Status','Firewall Status']
        if not args.noheaders:
            csvWriter(zoneHeader)
        for zone in zonedetailCursor:
            orgID = zone[1]
            zoneName = zone[2]
            orgName = zone[3]
            planType = zone[4]
            zoneID = zone[5]
            ns1 = zone[6]
            ns1 = zone[7]
            bandwidth = size(int(zone[8]))
            totalThreats = zone[9]
            topcountryThreat = zone[10]
            wafStatus = zone[11]
            securityLevel = zone[12]
            owaspSensitivity = zone[13]
            owaspMode = zone[14]
            if planType == 'Free Website':
                owaspStatus = 'off'
            else:    
                owaspStatus = '%s - %s' % (owaspSensitivity, owaspMode)


            # Write domain level data to CSV
            domainData = ['',zoneName,topcountryThreat,planType,bandwidth,totalThreats,wafStatus,owaspStatus,securityLevel]
            csvWriter(domainData)
    for x in range(6):
        csvWriter('')

# Destroy database after CSV is written
if not args.dbpersist:
    try:
        os.remove(dbname)
    except OSError:
        print('\n\nUnable to delete database %s.\n Located at: %s' % (dbname,(os.path.abspath(dbname))))
        pass
