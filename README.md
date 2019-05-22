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

Example arguments

```bash
python3 amalgamate.py output.txt sample-data/minimal-omero-client.json,sample-data/simplewebframework.json
```

  


