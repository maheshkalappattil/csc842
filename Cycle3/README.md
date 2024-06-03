# GMAIL Scanner

GMAIL Scanner is an inline addon to GMAIL framework that helps in scanning email content for known malware signatures.


# DESCRIPTION
GMAIL Scanner is an add on plugin in the Gmail, that allows users to scan the email for malicious URLs and payloads. This tool introduces
the Google workspace add on extension feature. The tool when opened in Gmail, parses the email in context to look for URL and attachment.
It then verifies with VirusTotal if the URL/file hash is of known malware and displays the result within the plugin.

# Why I'm Interested
I observed that even though Gmail has builtin phishing and spam scanning feature, it is not always filtering the phishing/spam emails. It
made me think to research on intgrating VirusTotal like platform with Gmail and I came up with this tool.

# Three Main Points
* Gmail Extension (aka workspace addon) to parse the email body and attachments
* Ability to extend Gmail functionality in terms of malware detection and analysis
* Integration of VirusTotal with Gmail messages
  
# Pre-requisistes  

Since this is an integrated plugin in Gmail, there is no additional tools/software that needs to be installed.

# Further Areas of Improvement
* The Gmail workspace addon is a very extensible framework. The tool can be extended to have a dedicated container/Virtual Machine in Google Cloud that implements REST endpoints. Then, the app script can invokes these endpoints based on the triggers from Gmail such as mail open/compose. This will help in very in depth analysis of malware such as sandboxing the given attachment payload and doing dynamic analysis. Also extensive static analysis can be done using tools similar to OLEDump on microsoft doc/XLS attachments.
  
# Resources
* Gmail Workspace addon - https://developers.google.com/apps-script/add-ons/gmail
* Google App Script Reference - https://developers.google.com/apps-script/reference

