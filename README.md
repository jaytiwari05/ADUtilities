
---

# **ADUtilities**

A growing collection of tools, scripts, and resources designed to support **Active Directory (AD) pentesting**, troubleshooting, and environment assessments.
This repository aims to provide practical, ready-to-use utilities that help streamline common tasks encountered during AD security engagements.

## **Current Tools**

### 🔧 **TimeFix – AD Clock Skew Sync Script**

Two lightweight Bash and Python scripts that fetches the time from a target Windows host (via WinRM HTTP headers) and synchronizes your Linux machine’s clock.
Useful for resolving **Kerberos clock-skew errors (KRB_AP_ERR_SKEW)** during pentesting.


### 🔧 **Resurrect – Remotely Find and Restore TombStoned Objects in AD**

A Python tool for remotely discovering and restoring deleted Active Directory objects through LDAP, supporting multiple authentication methods including Kerberos.
Useful for **AD pentesting and recovery operations** when you need to interact with the Deleted Objects container without direct DC access.


### 🔧 **auto_ntlm_reflection – Automate the process of exploitating CVE-2025-33073 (NTLM Reflection)**

A python script that automates the exploitation of CVE-2025-33073 (NTLM Reflection). It can add the dns record, perform coercion, and relay the authentication seamlessly. 

## **Roadmap**

More tools will be added soon, including:

* AD enumeration helpers
* Credential & ticket utilities
* Automation shortcuts for common AD operations
* Misc. red-team friendly scripts

Stay tuned — this repo will grow into a handy toolkit for anyone working with AD security.

---

