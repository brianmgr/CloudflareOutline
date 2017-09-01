# Future Improvements ⚒

## 1. Add more argument flags
* `-ns` - Only get NS for all orgs. (Still useful?)
* `-overview` - Aggregate all organization data into a few quick lines and write to csv.
* `-countries` - Convert Country Codes to Country Names.
* `-bytes` - Don't convert bytes to KB,MB,GB,TB,PB.
* `-pretty` - Pretty print CSV output.
---

## 2. Condense and optimize code
* Separate functions into modules.
* Optimize overall structure.
* Reduce repetitive lines.
---

## 3. Render database as [temp file](https://docs.python.org/2/library/tempfile.html#tempfile.mkstemp) for improved security.
* Only if `-dbpersist` flag is not present.
* Currently, if the `-dbpersist` flag is **NOT** present, the database **WILL** be destroyed at the end of the job.
  * If the program crashes, is exited prematurely, or the OS does not allow it, the database will not be removed.
---

## 4. Error handling for API rate limiting

* On 429 error, gracefully fail and tell user to try again in 5 minutes.
---

## 5. CSV formatting
* If `-pretty` flag present, format CSV output. This may be by default in future and a reverse flag added.
```
import pretty_csv
...
if pretty.args:
    pretty_csv
```