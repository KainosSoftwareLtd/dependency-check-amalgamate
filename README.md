# dependency-check-amalgamate
The purpose of this project is to amalgamate several dependency-check json files

dependency-check json files can be created using the following syntax in a maven pom

```xml
<plugin>
  <groupId>org.owasp</groupId>
  <artifactId>dependency-check-maven</artifactId>
  <version>4.0.2</version>
  <configuration>
      <format>ALL</format>
  </configuration>
  <executions>
    <execution>
      <goals>
          <goal>check</goal>
      </goals>
    </execution>
  </executions>
</plugin>
```

```bash
mvn org.owasp:dependency-check-maven:4.0.2:check
```

The amalgamate.py script takes three arguments:

- output, The file to output the amalgamated dependency-check data to.  
- inputs, The input json dependency-check files.  

## Example arguments

```bash
python3 amalgamate.py output.txt sample-data/minimal-omero-client.json,sample-data/simplewebframework.json
```

## Sample Output

```text
┌────────────────────────────────────────────────────────────────────────────────────────────────────┐
│Project                       │ High      Medium    Low                                             │
│────────────────────────────────────────────────────────────────────────────────────────────────────│
│minimal-omero-client          │ 10        7         1                                               │
│────────────────────────────────────────────────────────────────────────────────────────────────────│
│simplewebframework            │ 2         4         0                                               │
└────────────────────────────────────────────────────────────────────────────────────────────────────┘
┌────────────────────────────────────────────────────────────────────────────────────────────────────┐
│Dependency          │ bcprov-jdk14-136.jar                                                          │
│────────────────────────────────────────────────────────────────────────────────────────────────────│
│Evidence Count      │ 22                                                                            │
│────────────────────────────────────────────────────────────────────────────────────────────────────│
│Highest Severity    │ High                                                                          │
│────────────────────────────────────────────────────────────────────────────────────────────────────│
│CVE Count           │ 14                                                                            │
│────────────────────────────────────────────────────────────────────────────────────────────────────│
│Project             │ sample-data/minimal-omero-client.json                                         │
└────────────────────────────────────────────────────────────────────────────────────────────────────┘
┌────────────────────────────────────────────────────────────────────────────────────────────────────┐
│Dependency          │ postgresql-9.4-1200-jdbc4.jar                                                 │
│────────────────────────────────────────────────────────────────────────────────────────────────────│
│Evidence Count      │ 32                                                                            │
│────────────────────────────────────────────────────────────────────────────────────────────────────│
│Highest Severity    │ High                                                                          │
│────────────────────────────────────────────────────────────────────────────────────────────────────│
│CVE Count           │ 9                                                                             │
│────────────────────────────────────────────────────────────────────────────────────────────────────│
│Project             │ sample-data/minimal-omero-client.json                                         │
└────────────────────────────────────────────────────────────────────────────────────────────────────┘
┌────────────────────────────────────────────────────────────────────────────────────────────────────┐
│Dependency          │ spring-core-3.0.1.RELEASE.jar                                                 │
│────────────────────────────────────────────────────────────────────────────────────────────────────│
│Evidence Count      │ 18                                                                            │
│────────────────────────────────────────────────────────────────────────────────────────────────────│
│Highest Severity    │ High                                                                          │
│────────────────────────────────────────────────────────────────────────────────────────────────────│
│CVE Count           │ 7                                                                             │
│────────────────────────────────────────────────────────────────────────────────────────────────────│
│Project             │ sample-data/minimal-omero-client.json                                         │
└────────────────────────────────────────────────────────────────────────────────────────────────────┘
┌────────────────────────────────────────────────────────────────────────────────────────────────────┐
│Dependency          │ spring-tx-3.0.1.RELEASE.jar                                                   │
│────────────────────────────────────────────────────────────────────────────────────────────────────│
│Evidence Count      │ 17                                                                            │
│────────────────────────────────────────────────────────────────────────────────────────────────────│
│Highest Severity    │ High                                                                          │
│────────────────────────────────────────────────────────────────────────────────────────────────────│
│CVE Count           │ 6                                                                             │
│────────────────────────────────────────────────────────────────────────────────────────────────────│
│Project             │ sample-data/minimal-omero-client.json                                         │
└────────────────────────────────────────────────────────────────────────────────────────────────────┘
┌────────────────────────────────────────────────────────────────────────────────────────────────────┐
│Dependency          │ jetty-http-8.1.22.v20160922.jar                                               │
│────────────────────────────────────────────────────────────────────────────────────────────────────│
│Evidence Count      │ 29                                                                            │
│────────────────────────────────────────────────────────────────────────────────────────────────────│
│Highest Severity    │ High                                                                          │
│────────────────────────────────────────────────────────────────────────────────────────────────────│
│CVE Count           │ 4                                                                             │
│────────────────────────────────────────────────────────────────────────────────────────────────────│
│Project             │ sample-data/simplewebframework.json                                           │
└────────────────────────────────────────────────────────────────────────────────────────────────────┘
┌────────────────────────────────────────────────────────────────────────────────────────────────────┐
│Dependency          │ geronimo-spec-jta-1.0.1B-rc4.jar                                              │
│────────────────────────────────────────────────────────────────────────────────────────────────────│
│Evidence Count      │ 14                                                                            │
│────────────────────────────────────────────────────────────────────────────────────────────────────│
│Highest Severity    │ High                                                                          │
│────────────────────────────────────────────────────────────────────────────────────────────────────│
│CVE Count           │ 2                                                                             │
│────────────────────────────────────────────────────────────────────────────────────────────────────│
│Project             │ sample-data/minimal-omero-client.json                                         │
└────────────────────────────────────────────────────────────────────────────────────────────────────┘
┌────────────────────────────────────────────────────────────────────────────────────────────────────┐
│Dependency          │ commons-collections-3.2.jar                                                   │
│────────────────────────────────────────────────────────────────────────────────────────────────────│
│Evidence Count      │ 26                                                                            │
│────────────────────────────────────────────────────────────────────────────────────────────────────│
│Highest Severity    │ High                                                                          │
│────────────────────────────────────────────────────────────────────────────────────────────────────│
│CVE Count           │ 2                                                                             │
│────────────────────────────────────────────────────────────────────────────────────────────────────│
│Project             │ sample-data/minimal-omero-client.json                                         │
└────────────────────────────────────────────────────────────────────────────────────────────────────┘
┌────────────────────────────────────────────────────────────────────────────────────────────────────┐
│Dependency          │ commons-beanutils-core-1.7.0.jar                                              │
│────────────────────────────────────────────────────────────────────────────────────────────────────│
│Evidence Count      │ 14                                                                            │
│────────────────────────────────────────────────────────────────────────────────────────────────────│
│Highest Severity    │ High                                                                          │
│────────────────────────────────────────────────────────────────────────────────────────────────────│
│CVE Count           │ 1                                                                             │
│────────────────────────────────────────────────────────────────────────────────────────────────────│
│Project             │ sample-data/minimal-omero-client.json                                         │
└────────────────────────────────────────────────────────────────────────────────────────────────────┘
┌────────────────────────────────────────────────────────────────────────────────────────────────────┐
│Dependency          │ commons-beanutils-1.8.0.jar                                                   │
│────────────────────────────────────────────────────────────────────────────────────────────────────│
│Evidence Count      │ 31                                                                            │
│────────────────────────────────────────────────────────────────────────────────────────────────────│
│Highest Severity    │ High                                                                          │
│────────────────────────────────────────────────────────────────────────────────────────────────────│
│CVE Count           │ 1                                                                             │
│────────────────────────────────────────────────────────────────────────────────────────────────────│
│Project             │ sample-data/minimal-omero-client.json                                         │
└────────────────────────────────────────────────────────────────────────────────────────────────────┘
┌────────────────────────────────────────────────────────────────────────────────────────────────────┐
│Dependency          │ xercesImpl-2.8.1.jar                                                          │
│────────────────────────────────────────────────────────────────────────────────────────────────────│
│Evidence Count      │ 47                                                                            │
│────────────────────────────────────────────────────────────────────────────────────────────────────│
│Highest Severity    │ High                                                                          │
│────────────────────────────────────────────────────────────────────────────────────────────────────│
│CVE Count           │ 1                                                                             │
│────────────────────────────────────────────────────────────────────────────────────────────────────│
│Project             │ sample-data/minimal-omero-client.json                                         │
└────────────────────────────────────────────────────────────────────────────────────────────────────┘
┌────────────────────────────────────────────────────────────────────────────────────────────────────┐
│Dependency          │ logback-core-1.1.1.jar                                                        │
│────────────────────────────────────────────────────────────────────────────────────────────────────│
│Evidence Count      │ 27                                                                            │
│────────────────────────────────────────────────────────────────────────────────────────────────────│
│Highest Severity    │ High                                                                          │
│────────────────────────────────────────────────────────────────────────────────────────────────────│
│CVE Count           │ 1                                                                             │
│────────────────────────────────────────────────────────────────────────────────────────────────────│
│Project             │ sample-data/minimal-omero-client.json                                         │
└────────────────────────────────────────────────────────────────────────────────────────────────────┘
┌────────────────────────────────────────────────────────────────────────────────────────────────────┐
│Dependency          │ log4j-api-2.0-beta4.jar                                                       │
│────────────────────────────────────────────────────────────────────────────────────────────────────│
│Evidence Count      │ 26                                                                            │
│────────────────────────────────────────────────────────────────────────────────────────────────────│
│Highest Severity    │ High                                                                          │
│────────────────────────────────────────────────────────────────────────────────────────────────────│
│CVE Count           │ 1                                                                             │
│────────────────────────────────────────────────────────────────────────────────────────────────────│
│Project             │ sample-data/simplewebframework.json                                           │
└────────────────────────────────────────────────────────────────────────────────────────────────────┘
┌────────────────────────────────────────────────────────────────────────────────────────────────────┐
│Dependency          │ spring-security-core-3.0.2.RELEASE.jar                                        │
│────────────────────────────────────────────────────────────────────────────────────────────────────│
│Evidence Count      │ 21                                                                            │
│────────────────────────────────────────────────────────────────────────────────────────────────────│
│Highest Severity    │ Medium                                                                        │
│────────────────────────────────────────────────────────────────────────────────────────────────────│
│CVE Count           │ 6                                                                             │
│────────────────────────────────────────────────────────────────────────────────────────────────────│
│Project             │ sample-data/minimal-omero-client.json                                         │
└────────────────────────────────────────────────────────────────────────────────────────────────────┘
┌────────────────────────────────────────────────────────────────────────────────────────────────────┐
│Dependency          │ spring-core-3.1.0.RELEASE.jar                                                 │
│────────────────────────────────────────────────────────────────────────────────────────────────────│
│Evidence Count      │ 18                                                                            │
│────────────────────────────────────────────────────────────────────────────────────────────────────│
│Highest Severity    │ Medium                                                                        │
│────────────────────────────────────────────────────────────────────────────────────────────────────│
│CVE Count           │ 4                                                                             │
│────────────────────────────────────────────────────────────────────────────────────────────────────│
│Project             │ sample-data/simplewebframework.json                                           │
└────────────────────────────────────────────────────────────────────────────────────────────────────┘
┌────────────────────────────────────────────────────────────────────────────────────────────────────┐
│Dependency          │ spring-aop-3.1.0.RELEASE.jar                                                  │
│────────────────────────────────────────────────────────────────────────────────────────────────────│
│Evidence Count      │ 17                                                                            │
│────────────────────────────────────────────────────────────────────────────────────────────────────│
│Highest Severity    │ Medium                                                                        │
│────────────────────────────────────────────────────────────────────────────────────────────────────│
│CVE Count           │ 4                                                                             │
│────────────────────────────────────────────────────────────────────────────────────────────────────│
│Project             │ sample-data/simplewebframework.json                                           │
└────────────────────────────────────────────────────────────────────────────────────────────────────┘
┌────────────────────────────────────────────────────────────────────────────────────────────────────┐
│Dependency          │ httpclient-4.3.1.jar                                                          │
│────────────────────────────────────────────────────────────────────────────────────────────────────│
│Evidence Count      │ 26                                                                            │
│────────────────────────────────────────────────────────────────────────────────────────────────────│
│Highest Severity    │ Medium                                                                        │
│────────────────────────────────────────────────────────────────────────────────────────────────────│
│CVE Count           │ 2                                                                             │
│────────────────────────────────────────────────────────────────────────────────────────────────────│
│Project             │ sample-data/minimal-omero-client.json                                         │
└────────────────────────────────────────────────────────────────────────────────────────────────────┘
┌────────────────────────────────────────────────────────────────────────────────────────────────────┐
│Dependency          │ httpclient-4.1.jar                                                            │
│────────────────────────────────────────────────────────────────────────────────────────────────────│
│Evidence Count      │ 24                                                                            │
│────────────────────────────────────────────────────────────────────────────────────────────────────│
│Highest Severity    │ Medium                                                                        │
│────────────────────────────────────────────────────────────────────────────────────────────────────│
│CVE Count           │ 2                                                                             │
│────────────────────────────────────────────────────────────────────────────────────────────────────│
│Project             │ sample-data/simplewebframework.json                                           │
└────────────────────────────────────────────────────────────────────────────────────────────────────┘
┌────────────────────────────────────────────────────────────────────────────────────────────────────┐
│Dependency          │ dom4j-1.6.1.jar                                                               │
│────────────────────────────────────────────────────────────────────────────────────────────────────│
│Evidence Count      │ 25                                                                            │
│────────────────────────────────────────────────────────────────────────────────────────────────────│
│Highest Severity    │ Medium                                                                        │
│────────────────────────────────────────────────────────────────────────────────────────────────────│
│CVE Count           │ 1                                                                             │
│────────────────────────────────────────────────────────────────────────────────────────────────────│
│Project             │ sample-data/minimal-omero-client.json                                         │
└────────────────────────────────────────────────────────────────────────────────────────────────────┘
┌────────────────────────────────────────────────────────────────────────────────────────────────────┐
│Dependency          │ spring-security-config-3.0.2.RELEASE.jar                                      │
│────────────────────────────────────────────────────────────────────────────────────────────────────│
│Evidence Count      │ 20                                                                            │
│────────────────────────────────────────────────────────────────────────────────────────────────────│
│Highest Severity    │ Medium                                                                        │
│────────────────────────────────────────────────────────────────────────────────────────────────────│
│CVE Count           │ 1                                                                             │
│────────────────────────────────────────────────────────────────────────────────────────────────────│
│Project             │ sample-data/minimal-omero-client.json                                         │
└────────────────────────────────────────────────────────────────────────────────────────────────────┘
┌────────────────────────────────────────────────────────────────────────────────────────────────────┐
│Dependency          │ spring-security-ldap-3.0.2.RELEASE.jar                                        │
│────────────────────────────────────────────────────────────────────────────────────────────────────│
│Evidence Count      │ 20                                                                            │
│────────────────────────────────────────────────────────────────────────────────────────────────────│
│Highest Severity    │ Medium                                                                        │
│────────────────────────────────────────────────────────────────────────────────────────────────────│
│CVE Count           │ 1                                                                             │
│────────────────────────────────────────────────────────────────────────────────────────────────────│
│Project             │ sample-data/minimal-omero-client.json                                         │
└────────────────────────────────────────────────────────────────────────────────────────────────────┘
┌────────────────────────────────────────────────────────────────────────────────────────────────────┐
│Dependency          │ spring-ldap-core-1.3.0.RELEASE.jar                                            │
│────────────────────────────────────────────────────────────────────────────────────────────────────│
│Evidence Count      │ 17                                                                            │
│────────────────────────────────────────────────────────────────────────────────────────────────────│
│Highest Severity    │ Medium                                                                        │
│────────────────────────────────────────────────────────────────────────────────────────────────────│
│CVE Count           │ 1                                                                             │
│────────────────────────────────────────────────────────────────────────────────────────────────────│
│Project             │ sample-data/minimal-omero-client.json                                         │
└────────────────────────────────────────────────────────────────────────────────────────────────────┘
┌────────────────────────────────────────────────────────────────────────────────────────────────────┐
│Dependency          │ guava-17.0.jar                                                                │
│────────────────────────────────────────────────────────────────────────────────────────────────────│
│Evidence Count      │ 19                                                                            │
│────────────────────────────────────────────────────────────────────────────────────────────────────│
│Highest Severity    │ Medium                                                                        │
│────────────────────────────────────────────────────────────────────────────────────────────────────│
│CVE Count           │ 1                                                                             │
│────────────────────────────────────────────────────────────────────────────────────────────────────│
│Project             │ sample-data/minimal-omero-client.json                                         │
└────────────────────────────────────────────────────────────────────────────────────────────────────┘
┌────────────────────────────────────────────────────────────────────────────────────────────────────┐
│Dependency          │ stax-1.2.0.jar                                                                │
│────────────────────────────────────────────────────────────────────────────────────────────────────│
│Evidence Count      │ 19                                                                            │
│────────────────────────────────────────────────────────────────────────────────────────────────────│
│Highest Severity    │ Medium                                                                        │
│────────────────────────────────────────────────────────────────────────────────────────────────────│
│CVE Count           │ 1                                                                             │
│────────────────────────────────────────────────────────────────────────────────────────────────────│
│Project             │ sample-data/simplewebframework.json                                           │
└────────────────────────────────────────────────────────────────────────────────────────────────────┘
┌────────────────────────────────────────────────────────────────────────────────────────────────────┐
│Dependency          │ filters-2.0.235.jar                                                           │
│────────────────────────────────────────────────────────────────────────────────────────────────────│
│Evidence Count      │ 18                                                                            │
│────────────────────────────────────────────────────────────────────────────────────────────────────│
│Highest Severity    │ Low                                                                           │
│────────────────────────────────────────────────────────────────────────────────────────────────────│
│CVE Count           │ 1                                                                             │
│────────────────────────────────────────────────────────────────────────────────────────────────────│
│Project             │ sample-data/minimal-omero-client.json                                         │
└────────────────────────────────────────────────────────────────────────────────────────────────────┘
```

  


