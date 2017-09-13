# CloudflareOutline  ![CfLogo](https://www.cloudflare.com/media/images/web-badges/cf-web-badges-f-1.png)

## Get analytics for each of your organizations on Cloudflare, as well as all of the domains belonging to it.


 You can see an example of the output in this [CSV file](CloudflareOutline-YYYY-MM-DD.csv).

---

## Features
Data is gathered and temporarily stored in a SQL database, which is then used to populate a CSV report.

Data included in the report is listed below.
- Organization Level Analytics
  - Org Name
  - Name Servers
  - Top 5 Threat Locations
  - Number of Zones*
  - Bandwidth*
  - Threat Count*
    - ##### *Total, as well as by plan type.
- Domain Level Analytics (Per Organization)
  - Domain Name
  - Top Threat Location
  - Plan Type
  - Bandwidth
  - Threat Count
  - WAF Status
  - OWASP Status
  - Firewall Status

---

## Argument Flags

Flag | Effect
---------|----------
`-email` |  Email address which is invited to all organizations
`-key` |  API key
`-output` |  Override output CSV filename. If file exists, data will be appended.
`-dbpersist` |  Keep SQL Database on disk, do not delete it after report is written.
`-noheaders` |  Remove headers (ex: Organization Name) from CSV file.
`-since` |  Start of report timeframe (YYYY-MM-DDT00:00:00Z)*
`-until` |  End of report timeframe (YYYY-MM-DDT00:00:00Z)*

*The Since and Until flags may alter the resolution at which you recieve your analytics results. More information can be found in the [API documentation](https://api.cloudflare.com/#zone-analytics-dashboard).
If Since and Until flags are not provided, a default timeframe of the last 12 hours will be used.

---

## Usage
After cloning the repository, navigate to its root directory with your command line.

Once there, you can run the file named `CloudflareOultine.py` like this:
```
python CloudflareOutline.py
```
 _Running CloudflareOutline without any flags will prompt you for your credentials and give you a report for any **available** results within the past 7 days._


You can also add flags to the command to better fit your needs:


```
 python CloudflareOutline.py -email email@domain.com -key XXXXXXX -since 2017-07-01T00:00:00Z -until 2017-08-01T00:00:00Z -dbpersist
```

---

## License
BSD 3-Clause licensed. Please see the LICENSE file for details.
