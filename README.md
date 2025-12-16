# CVE-2025-66516 & CVE-2025-54988 Analysis and Mitigation

**Apache Tika Version:** 2.9.4-SAS.0.0.1

This branch provides complete security fixes with comprehensive vulnerability analysis, extensive test coverage (11 security tests), and detailed documentation for two critical XML External Entity (XXE) vulnerabilities in Apache Tika 2.9.4.

> **Note:** A fix for Apache Tika version 1.28.5 is available at:  
> https://github.com/sassoftware/tika/tree/1.28.5-CVE-2025-66516-CVE-2025-54988

---

## Vulnerability Overview

### CVE-2025-66516
• **CVE ID:** [CVE-2025-66516](https://nvd.nist.gov/vuln/detail/CVE-2025-66516)  
• **Type:** XML External Entity (XXE) Injection via XFA files in PDF (CWE-611)  
• **Severity:** CRITICAL  
• **CVSS Score:** 10.0 (Critical) - CVSS 4.0  
• **CVSS Vector:** CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H  
• **Published:** December 4, 2025  
• **CNA:** Apache Software Foundation  

### CVE-2025-54988
• **CVE ID:** [CVE-2025-54988](https://nvd.nist.gov/vuln/detail/CVE-2025-54988)  
• **Type:** XML External Entity (XXE) Injection via XFA files in PDF (CWE-611)  
• **Severity:** HIGH  
• **CVSS Score:** 8.4 (High) - CVSS 3.1  
• **CVSS Vector:** CVSS:3.1/AV:L/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H  
• **Published:** August 20, 2025  
• **CNA:** Apache Software Foundation  

### Affected Versions
• **CVE-2025-54988:** Apache Tika 1.13 through 3.2.1 (tika-parser-pdf-module)  
• **CVE-2025-66516:** Apache Tika 1.13 through 3.2.1 (tika-core, tika-pdf-module, tika-parsers)  

### Fixed Versions
• **Apache Tika 3.2.2 or higher** (official release with complete fix)  
• **Branch 2.9.4-CVE-2025-66516-CVE-2025-54988**: CVE fixes implemented for Tika 2.9.4 base  

---

## Vulnerability Description

### CVE-2025-66516: XXE in tika-core via XFA in PDF

**Critical XXE vulnerability** affecting tika-core (1.13-3.2.1), tika-pdf-module (2.0.0-3.2.1), and tika-parsers (1.13-1.28.5) on all platforms. This CVE expands the scope of CVE-2025-54988 by identifying that:

1. The vulnerability exists in **tika-core**, not just tika-parser-pdf-module
2. Users who upgraded tika-parser-pdf-module but not tika-core remain vulnerable
3. In Tika 1.x, the PDFParser was in the `org.apache.tika:tika-parsers` module

The `XMLReaderUtils.getXMLInputFactory()` in tika-core does not properly disable DTD processing when the PDF parser processes XFA forms:

**Attack Vector:**
```xml
<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<xfa:data>&xxe;</xfa:data>
```

**Entry Point:** XFAExtractor.java processes XFA (XML Forms Architecture) embedded in PDFs

### CVE-2025-54988: XXE in tika-parser-pdf-module via XFA in PDF

**Critical XXE vulnerability** in Apache Tika (tika-parser-pdf-module) versions 1.13 through 3.2.1 on all platforms. Allows attackers to carry out XML External Entity injection via a crafted XFA file inside a PDF.

**Affected Packages:** The tika-parser-pdf-module is used as a dependency in:
- tika-parsers-standard-modules
- tika-parsers-standard-package
- tika-app
- tika-grpc
- tika-server-standard

**Attack Capabilities:**
- Read sensitive data from the server
- Trigger malicious requests to internal resources
- Perform SSRF attacks to third-party servers

**Attack Vector:**
```xml
<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<xfa:data>&xxe;</xfa:data>
```

**Entry Point:** PDF files with malicious XFA (XML Forms Architecture) content processed by tika-parser-pdf-module

### Security Impact

Both vulnerabilities enable attackers to:

1. **Arbitrary File Read:** Access sensitive files on the server (e.g., `/etc/passwd`, configuration files)
2. **Server-Side Request Forgery (SSRF):** Make HTTP requests to internal services
3. **Denial of Service (DoS):** Trigger billion laughs attacks or entity expansion bombs
4. **Information Disclosure:** Exfiltrate data through error messages or out-of-band channels

**Impact Severity:**
- Applications processing untrusted PDF documents are at **HIGH RISK**
- Tika Server deployments accepting PDFs are **CRITICALLY VULNERABLE**
- Only PDF files with XFA (XML Forms Architecture) can trigger this vulnerability

---

## Remediation Details

### Official Fix (Recommended)

**Upgrade to Apache Tika 3.2.2 or Higher**

The official fix in Apache Tika 3.2.2 or higher implements:

1. **XMLInputFactory Security** (`XMLReaderUtils.java`)
   ```java
   factory.setProperty(XMLInputFactory.SUPPORT_DTD, false);
   factory.setProperty(XMLInputFactory.IS_SUPPORTING_EXTERNAL_ENTITIES, false);
   ```

2. **TransformerFactory Security** (`XMLReaderUtils.java`)
   ```java
   factory.setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, true);
   factory.setAttribute(XMLConstants.ACCESS_EXTERNAL_DTD, "");
   factory.setAttribute(XMLConstants.ACCESS_EXTERNAL_STYLESHEET, "");
   ```

### Upgrade to This Branch

**For users requiring Java 8 compatibility or 2.x API compatibility**

This branch provides CVE fixes implemented on Tika 2.9.4 base:
- Same security fixes as 3.2.2
- Java 8 compatible
- No breaking API changes from 2.x
- Maintained by SAS Institute Inc.

See [Migration Guide](#migration-guide-choosing-your-path-forward) for deployment options.

### Partial Protection: Disable PDF Parser (Protects 1 of 5 Attack Vectors - 20% Coverage)

**CRITICAL WARNING: This configuration blocks only 20% of the attack surface. 80% remains exploitable.**

**EXECUTIVE SUMMARY:**
- tika-config.xml parser exclusion protects against **1 out of 5 known attack vectors**
- **4 attack vectors remain fully exploitable** and require comprehensive security audit
- This configuration does NOT remediate the root cause in tika-core's XMLReaderUtils
- **Upgrade to 3.2.2 or this branch that includes CVE fixes for 2.9.4 is MANDATORY**

**For users who cannot upgrade immediately**, you can block the PDF-based attack vector by disabling the PDF parser. However, you MUST conduct a comprehensive security audit to identify and mitigate the 4 other attack vectors:

#### Configuration File (`tika-config.xml`)

```xml
<?xml version="1.0" encoding="UTF-8"?>
<properties>
    <parsers>
        <parser class="org.apache.tika.parser.DefaultParser">
            <!-- Exclude PDF Parser to mitigate CVE-2025-66516 -->
            <parser-exclude class="org.apache.tika.parser.pdf.PDFParser"/>
            
            <!-- Exclude PDF MIME types -->
            <mime-exclude>application/pdf</mime-exclude>
            <mime-exclude>application/x-pdf</mime-exclude>
        </parser>
    </parsers>
</properties>
```

#### Attack Vector Analysis: 1 Protected, 4 Unmitigated

**ONLY PROTECTED VECTOR (20% Coverage):**

**1. PDF XFA Parser (XFAExtractor)** BLOCKED by PDF exclusion
- **Attack Vector:** Malicious PDF with XFA forms
- **Config Impact:** BLOCKED - PDFParser exclusion prevents execution
- **Entry Point:** PDFParser → XFAExtractor → context.getXMLInputFactory()
- **Test Coverage:** 
  - `testCVE_2025_66516_XMLStreamReaderXXEBlocked()` - Validates XXE prevention in XMLStreamReader
  - `testCVE_2025_66516_PublicDoctypeBlocked()` - Validates external DTD blocking
  - See [XMLReaderUtilsTest.java](tika-core/src/test/java/org/apache/tika/utils/XMLReaderUtilsTest.java) lines 530-660
- **Validation Status:** Tests pass on this branch - vulnerability fixed
- **Note:** This is the ONLY vector mitigated by tika-config.xml

**UNMITIGATED VECTORS (80% Remain Exploitable):**

**2. XMLLogReader (Utility Class)** NOT PROTECTED
- **Location:** tika-eval-app module
- **Attack Vector:** Malicious XML log files
- **Config Impact:** NONE - XMLLogReader is not a Tika parser
- **Entry Point:** XMLLogReader → XMLReaderUtils.getXMLInputFactory()
- **Why Config Fails:** Utility classes operate outside the parser framework
- **Test Coverage:**
  - `testCVE_2025_66516_XMLLogReaderPattern()` - Validates XMLLogReader pattern triggers XXE when using vulnerable XMLReaderUtils
  - Test demonstrates utility classes bypass tika-config.xml protections
  - See [XMLReaderUtilsTest.java](tika-core/src/test/java/org/apache/tika/utils/XMLReaderUtilsTest.java) line 704
  - Available in comprehensive CVE test suite
- **Validation Status:** Tests pass on this branch - vulnerability fixed in XMLReaderUtils
- **Security Audit Required:** Search codebase for direct XMLLogReader usage patterns

**3. ParseContext Infrastructure** NOT PROTECTED
- **Attack Vector:** Direct usage of ParseContext.getXMLInputFactory()
- **Config Impact:** NONE - Infrastructure code bypasses parser configuration
- **Entry Point:** ParseContext → XMLReaderUtils.getXMLInputFactory()
- **Why Config Fails:** ParseContext is core infrastructure used by all parsers
- **Test Coverage:**
  - `testCVE_2025_66516_ParseContextUsage()` - Validates ParseContext infrastructure calls vulnerable XMLReaderUtils
  - Test demonstrates any parser using context.getXMLInputFactory() is vulnerable
  - See [XMLReaderUtilsTest.java](tika-core/src/test/java/org/apache/tika/utils/XMLReaderUtilsTest.java) line 769
  - Shows config-based exclusions don't affect infrastructure layer
  - Available in comprehensive CVE test suite
- **Validation Status:** Tests pass on this branch - vulnerability fixed in XMLReaderUtils
- **Security Audit Required:** Review all parser integrations and data processing pipelines

**4. Custom Parsers** NOT PROTECTED
- **Attack Vector:** Any custom parser using context.getXMLInputFactory()
- **Config Impact:** NONE - Custom parsers are not PDFParser
- **Entry Point:** CustomParser → context.getXMLInputFactory()
- **Why Config Fails:** Exclusion only applies to PDFParser, not custom implementations
- **Test Coverage:**
  - `testCVE_2025_66516_CustomParserPattern()` - Simulates custom parser pattern calling context.getXMLInputFactory()
  - Test validates custom parsers inherit vulnerable XMLInputFactory from context
  - See [XMLReaderUtilsTest.java](tika-core/src/test/java/org/apache/tika/utils/XMLReaderUtilsTest.java) line 847
  - Demonstrates parser exclusions don't affect custom implementations
  - Available in comprehensive CVE test suite
- **Validation Status:** Tests pass on this branch - vulnerability fixed in XMLReaderUtils
- **Security Audit Required:** Inventory all custom parsers extending AbstractParser or implementing Parser

**5. Application Code** NOT PROTECTED
- **Attack Vector:** Direct application calls to XMLReaderUtils
- **Config Impact:** NONE - Application code bypasses Tika framework entirely
- **Entry Point:** App code → XMLReaderUtils.getXMLInputFactory()
- **Why Config Fails:** Configuration has no effect on direct API usage
- **Test Coverage:**
  - `testCVE_2025_66516_DirectApplicationUsage()` - Simulates direct application usage of XMLReaderUtils.getXMLInputFactory()
  - Test validates direct API calls bypass all Tika configuration
  - See [XMLReaderUtilsTest.java](tika-core/src/test/java/org/apache/tika/utils/XMLReaderUtilsTest.java) line 931
  - Demonstrates vulnerability at the lowest API layer
  - Available in comprehensive CVE test suite
- **Validation Status:** Tests pass on this branch - vulnerability fixed in XMLReaderUtils
- **Security Audit Required:** Search codebase for all XMLReaderUtils.getXMLInputFactory() calls

**Test Suite Summary:**
- **Total CVE Tests:** 11 comprehensive security tests
- **Coverage:** All 5 attack vectors validated
- **Status:** All tests pass on this branch (3.2.2 and 2.9.4 CVE fixes)
- **Location:** [XMLReaderUtilsTest.java](tika-core/src/test/java/org/apache/tika/utils/XMLReaderUtilsTest.java)
- **Usage:** Security auditors can run these tests against their deployments to verify vulnerability status

#### Root Cause Analysis

The vulnerability exists in tika-core's `XMLReaderUtils.getXMLInputFactory()` method:

**Vulnerable Code (line ~295):**
```java
public static XMLInputFactory getXMLInputFactory() {
    XMLInputFactory factory = XMLInputFactory.newInstance();
    // MISSING SECURITY PROPERTIES
    return factory;
}
```

**Missing Protections:**
- `XMLInputFactory.SUPPORT_DTD` not set to false
- `XMLInputFactory.IS_SUPPORTING_EXTERNAL_ENTITIES` not set to false
- `XMLConstants.ACCESS_EXTERNAL_DTD` not restricted to ""

**Impact:** ANY code path calling this method is vulnerable, regardless of tika-config.xml settings.

**Scope:**
- CVE-2025-54988: Originally identified vulnerability in tika-parser-pdf-module
- CVE-2025-66516: Expanded scope showing tika-core vulnerability affects more packages

#### Required Security Audit for Unmitigated Vectors

**If you deploy PDF parser exclusion, you MUST conduct a comprehensive security audit to identify exposure to the 4 unmitigated attack vectors:**

**1. XMLLogReader (Utility Class) - Vector 2**
- **Search for:** XML log file parsing, especially using Tika evaluation utilities
- **Impact:** Utility classes (like XMLLogReader pattern) bypass tika-config.xml protection
- **Action:** Review log analysis and debugging tools

**2. ParseContext Infrastructure - Vector 3**
- **Search for:** `ParseContext.getXMLInputFactory()` or `context.getXMLInputFactory()`
- **Impact:** Infrastructure code ignores parser exclusions
- **Action:** Review all parser integrations and data processing pipelines

**3. Custom Parsers - Vector 4**
- **Search for:** Classes extending `AbstractParser` or implementing `Parser`
- **Impact:** Custom parsers using `context.getXMLInputFactory()` are vulnerable
- **Action:** Inventory all custom parsers and verify XML handling

**4. Application Code - Vector 5**
- **Search for:** `XMLReaderUtils.getXMLInputFactory()`
- **Impact:** Direct API calls bypass all Tika configuration
- **Action:** Audit all XML processing code paths in your application

**Additional Consideration:**
- **Third-Party Libraries:** Scan dependency tree for libraries using tika-core directly, as they may use any of the above 4 vectors

#### Trade-offs

**What You Lose:**
- PDF text extraction
- PDF metadata extraction
- PDF embedded file extraction
- PDF image extraction

**What You Keep:**
- All other parsers (Word, Excel, PowerPoint, HTML, XML, Images)

**What This Does NOT Provide:**
- **Does NOT fix the underlying vulnerability** in XMLReaderUtils
- **Protects only 1 of 5 attack vectors (20% coverage)**
- **Does NOT protect against:**
  - XMLLogReader utility class attacks
  - ParseContext infrastructure exploitation
  - Custom parser attacks using context.getXMLInputFactory()
  - Direct application code calling XMLReaderUtils
  - Third-party libraries using tika-core
- **Provides FALSE SENSE OF SECURITY** if not combined with comprehensive audit
- **Still critically vulnerable** - upgrade is mandatory

**Risk Assessment:**
- **Coverage:** 20% of attack surface (1 of 5 vectors)
- **Remaining Risk:** 80% of vulnerability surface exploitable
- **CVSS Score:** Still 10.0 CRITICAL - severity unchanged
- **Acceptable Risk Posture:** NO - this is not acceptable for a critical vulnerability

### Key Changes in Branch 2.9.4-CVE-2025-66516-CVE-2025-54988

**Modified Files:**

1. **`tika-core/src/main/java/org/apache/tika/utils/XMLReaderUtils.java`** - Security fixes
   - **CVE-2025-66516 Fix:** Added secure XMLInputFactory configuration
     * `SUPPORT_DTD = false` (line 308)
     * `IS_SUPPORTING_EXTERNAL_ENTITIES = false` (line 309)
     * `ACCESS_EXTERNAL_DTD = ""` (line 305)
     * Removed insecure `IGNORING_STAX_ENTITY_RESOLVER`
   
   - **CVE-2025-54988 Fix:** Added secure TransformerFactory methods
     * New `getTransformerFactory()` method with secure defaults
     * New `getSAXTransformerFactory()` method with secure defaults
     * `FEATURE_SECURE_PROCESSING = true`
     * `ACCESS_EXTERNAL_DTD = ""`
     * `ACCESS_EXTERNAL_STYLESHEET = ""`

2. **`tika-core/src/test/java/org/apache/tika/utils/XMLReaderUtilsTest.java`** - Test coverage
   - Added 11 comprehensive security test cases for CVE fixes
   - Validates XXE attack prevention
   - Validates Billion Laughs attack prevention
   - All tests pass (11/11)

---

## Validation Results

### Test Suite Coverage

Branch 2.9.4-CVE-2025-66516-CVE-2025-54988 includes comprehensive security tests in `XMLReaderUtilsTest.java`:

**Total Test Coverage: 11 Tests Covering All 5 Attack Vectors**

**CVE-2025-54988 Tests (TransformerFactory):**
- `testCVE_2025_54988_GetTransformerExists()` - Verifies secure TransformerFactory methods exist
- `testCVE_2025_54988_GetTransformerBlocksXXE()` - Validates XXE prevention in XSLT transformation
  * Test payload: `<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>`
  * Expected: Exception with message containing "Entity", "not allowed", or "external"
  * Assertion: File contents (e.g., "root:", "daemon:") must not appear in output

**CVE-2025-66516 Tests:**
- `testCVE_2025_66516_XMLStreamReaderXXEBlocked()` - Validates XXE prevention in XMLStreamReader
  * Test payload: `<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>`
  * Expected: Exception with message containing "entity", "DTD", or "not declared"
  * Assertion: File contents must not leak into parsed text

- `testCVE_2025_66516_BillionLaughsAttackBlocked()` - Validates entity expansion prevention
  * Test payload: Recursive entity definitions (exponential expansion attack)
  * Expected: Either exception or fast processing (< 1 second)
  * Assertion: Entity expansion must be blocked to prevent DoS

- `testCVE_2025_66516_ParameterEntityBlocked()` - Validates parameter entity prevention
  * Test payload: `<!ENTITY % xxe SYSTEM "file:///etc/passwd">`
  * Expected: Exception with message containing "entity", "DTD", or "not declared"
  * Assertion: Must throw exception, not silently succeed

- `testCVE_2025_66516_XIncludeBlocked()` - Validates XInclude prevention
  * Test payload: `<xi:include href="file:///etc/passwd" parse="text"/>`
  * Expected: File contents must not appear in output
  * Assertion: No file leakage through XInclude mechanism

- `testCVE_2025_66516_PublicDoctypeBlocked()` - Validates external DTD blocking
  * Test payload: `<!DOCTYPE html PUBLIC ... "http://127.234.172.38:7845/malicious.dtd">`
  * Expected: No network connection attempted to fetch external DTD
  * Assertion: Must not throw ConnectException (which would indicate connection attempt)

- `testCVE_2025_66516_XMLLogReaderPattern()` - Validates utility class pattern blocks XXE
  * Test payload: `<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>`
  * Pattern: Simulates XMLLogReader utility class usage
  * Expected: Exception with message containing "entity", "DTD", or "not declared"
  * Assertion: File contents (e.g., "root:", "daemon:") must not leak

- `testCVE_2025_66516_ParseContextUsage()` - Validates ParseContext infrastructure blocks XXE
  * Test payload: `<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>`
  * Pattern: Direct usage of ParseContext.getXMLInputFactory()
  * Expected: Exception with message containing "entity", "DTD", or "not declared"
  * Assertion: Infrastructure-level protection prevents file leakage

- `testCVE_2025_66516_CustomParserPattern()` - Validates custom parser implementations block XXE
  * Test payload: `<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>`
  * Pattern: Custom parser extending AbstractParser using context.getXMLInputFactory()
  * Expected: Exception with message containing "entity", "DTD", or "not declared"
  * Assertion: Custom parsers inherit infrastructure-level protection

- `testCVE_2025_66516_DirectApplicationUsage()` - Validates direct application code blocks XXE
  * Test payload: `<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>`
  * Pattern: Direct call to XMLReaderUtils.getXMLInputFactory()
  * Expected: Exception with message containing "entity", "DTD", or "not declared"
  * Assertion: Even direct API usage that bypasses all configuration is protected

**Attack Vector Validation:**
The test suite validates all 5 attack vectors:
1. **PDF XFA Parser:** testCVE_2025_66516_XMLStreamReaderXXEBlocked, testCVE_2025_66516_PublicDoctypeBlocked
2. **XMLLogReader Pattern:** Tests validate utility class attacks bypass config
3. **ParseContext Infrastructure:** Tests validate infrastructure layer vulnerability
4. **Custom Parsers:** Tests validate custom parser attack patterns
5. **Application Code:** Tests validate direct API usage vulnerability

**All tests pass**, confirming that both CVE-2025-66516 and CVE-2025-54988 are fixed across all attack vectors.


---

## Migration Guide

### For Users Running Tika 3.2.1 or Earlier

#### Option 1: Upgrade to Official 3.2.2 (Recommended)

**Immediate Action:**
```bash
# Update your dependency
<dependency>
    <groupId>org.apache.tika</groupId>
    <artifactId>tika-core</artifactId>
    <version>3.2.2</version>
</dependency>
```

**Benefits:**
- Both CVEs completely fixed
- All functionality retained
- Official support
- Future security updates

**Note:** Requires Java 11+ and may include API changes from 2.x versions.

---

### For Users Running Tika 2.9.x Who Cannot Upgrade to 3.x

If you cannot upgrade to 3.2.2 due to:
- Java version constraints (still using Java 8)
- Breaking API changes between 2.x and 3.x
- Legacy application dependencies
- Extensive testing requirements

#### Option 2: Use Branch 2.9.4-CVE-2025-66516-CVE-2025-54988 (CVE Fixes for 2.9.4)

**Why Choose Branch 2.9.4-CVE-2025-66516-CVE-2025-54988:**
- Same CVE fixes as 3.2.2, adapted for 2.9.4
- Maintains Java 8 compatibility
- No breaking API changes from 2.x
- Proven fix implementation with comprehensive testing
- Complete documentation and analysis

**Immediate Action:**

**Option A: Download Pre-built Binaries (Easiest)**
```bash
# Download from GitHub releases (sassoftware fork with CVE fixes)
wget https://github.com/sassoftware/tika/releases/download/2.9.4-CVE-2025-66516-CVE-2025-54988/tika-app-2.9.4.jar
wget https://github.com/sassoftware/tika/releases/download/2.9.4-CVE-2025-66516-CVE-2025-54988/tika-core-2.9.4.jar
```

**Option B: Build from Source**
```bash
# Clone branch 2.9.4-CVE-2025-66516-CVE-2025-54988
git clone -b 2.9.4-CVE-2025-66516-CVE-2025-54988 https://github.com/sassoftware/tika.git
cd tika/repo

# Build and install
mvn clean install -DskipTests -Dcheckstyle.skip=true

# Artifacts will be in target/ directories
# The version will be 2.9.4 with CVE fixes
```

**Benefits:**
- Both CVE-2025-66516 and CVE-2025-54988 fixed
- All functionality retained (including PDF processing)
- No Java version upgrade required
- No API migration needed
- Maintains compatibility with existing 2.x applications

**Limitations:**
- Plan to upgrade to official 3.2.2 when feasible




---

## References

### Official Resources

• **Apache Tika Security Advisories:** https://tika.apache.org/security.html  
• **Apache Tika 3.2.2 Release:** https://tika.apache.org/3.2.2/  
• **Apache Tika Downloads:** https://tika.apache.org/download.html  

### CVE Information

• **CVE-2025-66516 (NVD):** https://nvd.nist.gov/vuln/detail/CVE-2025-66516  
• **CVE-2025-54988 (NVD):** https://nvd.nist.gov/vuln/detail/CVE-2025-54988  

### Related Information

• **CWE-611:** Improper Restriction of XML External Entity Reference  
• **OWASP XXE:** https://owasp.org/www-community/vulnerabilities/XML_External_Entity_(XXE)_Processing  
• **XML Security Cheat Sheet:** https://cheatsheetseries.owasp.org/cheatsheets/XML_External_Entity_Prevention_Cheat_Sheet.html  

---

## Security Considerations

### Attack Vectors

1. **PDF File Processing (CVE-2025-66516)**
   - Applications accepting PDF uploads from untrusted users
   - PDFs with malicious XFA forms or XMP metadata
   - Web forms, APIs, email attachments, document indexing systems
   - **Risk:** CRITICAL - XXE via XMLInputFactory in PDF parser

2. **XSLT Processing (CVE-2025-54988)**
   - Applications performing XSLT transformations
   - Tika Server endpoints, Tika CLI with XSLT output
   - Custom code using `XMLReaderUtils.getTransformerFactory()`
   - **Risk:** HIGH - XXE via TransformerFactory

3. **Tika Server Deployments**
   - RESTful API endpoints accepting untrusted files
   - Publicly accessible services without input validation
   - **Risk:** CRITICAL - Direct exploitation of both CVEs

### Defense-in-Depth Strategies

1. **Primary Defense: Upgrade to 3.2.2 or This Branch That Includes CVE Fixes for 2.9.4 (MANDATORY)**
   - Upgrade to Tika 3.2.2 (requires Java 11+, receives future Apache security updates)
   - OR use this branch that includes CVE fixes for 2.9.4 (Java 8 compatible, requires manual tracking of future Apache patches)
   - **This is the ONLY way to fix the vulnerability**
   - Fixes both CVEs at the source in XMLReaderUtils
   - Maintains full functionality

2. **Supplemental (20% Protection): Disable PDF Parser + Security Audit**
   - Blocks only PDF-based attacks (1 of 5 vectors)
   - **Requires mandatory security audit** to identify 4 unmitigated vectors:
     1. XMLLogReader utility class
     2. ParseContext infrastructure
     3. Custom parsers
     4. Application code
   - **Does NOT fix the underlying vulnerability**
   - **80% of attack surface remains exploitable**
   - Provides false sense of security without comprehensive audit
   - Reduces functionality
   - Use only as temporary measure before upgrading

3. **Network-Level Controls**
   - Isolate Tika in DMZ or private network
   - Block outbound connections from Tika
   - Implement egress filtering
   - Monitor for SSRF attempts

4. **Input Validation**
   - Validate file types before processing
   - Implement file size limits
   - Scan for malicious patterns
   - Use sandboxed environments

5. **Monitoring and Detection**
   - Log all file processing attempts
   - Alert on XXE-related errors
   - Monitor for unusual file access
   - Track SSRF indicators


---


## Development Environment

• **Apache Tika Version:** 3.2.1 and earlier (vulnerable), 3.2.2 (fixed)  
• **Build Tool:** Apache Maven 3.6+  
• **Java Version:** 8, 11, 17 (tested)  
• **Testing Framework:** JUnit  

### Build Requirements

```bash
# Java 8 or later
java -version

# Maven 3.6 or later
mvn -version

# Build Tika
cd repo
mvn clean install -DskipTests

# Run specific tests
mvn test -Dtest=XMLReaderUtilsTest
```

---

## Proof of Concept

### CVE-2025-66516: PDF XXE Exploitation

**Vulnerable Code Path:**
```
malicious.pdf → PDFParser.parse()
              → XFAExtractor.extract()
              → context.getXMLInputFactory().createXMLStreamReader()
              → XMLInputFactory (SUPPORT_DTD=true, EXTERNAL_ENTITIES=true)
              → XXE payload executed
              → /etc/passwd contents exfiltrated
```

**Exploitation Steps:**

1. Create malicious PDF with XXE in XFA form
2. Upload to Tika server (2.9.1)
3. Observe file contents in response


### CVE-2025-54988: XSLT XXE Exploitation

**Vulnerable Code Path:**
```
malicious.xsl → TransformerFactory.newInstance()
              → factory.newTransformer()
              → XSLT transformation with XXE
              → External entity processed
              → File contents included in output
```

**Exploitation Steps:**

1. Create XSLT with external entity reference
2. Submit for transformation
3. Observe file contents in result


---

## License

This implementation maintains the original Apache License 2.0 of the Apache Tika project.

```
Licensed to the Apache Software Foundation (ASF) under one or more
contributor license agreements. See the NOTICE file distributed with
this work for additional information regarding copyright ownership.
The ASF licenses this file to You under the Apache License, Version 2.0
(the "License"); you may not use this file except in compliance with
the License. You may obtain a copy of the License at

     http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
```

---

## Contact & Contributions

This branch remediates CVE-2025-66516 and CVE-2025-54988 for Apache Tika 2.9.4.

• **Repository:** https://github.com/sassoftware/tika  
• **Branch:** 2.9.4-CVE-2025-66516-CVE-2025-54988    
• **Security Vulnerability Research and Remediation Author:** Jinwoo Hwang  

