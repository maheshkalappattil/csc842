# Gmail Scanner (End-to-end implementation)

Gmail Scanner now functions end-to-end with Cycle9, with a front end json and Golang based backend service running on a cloud VM.
which does the analysis.

# DESCRIPTION
With Cycle9 the Gmail Scanner is implemented end-to-end. The front end is a plugin in GMAIL that triggers an HTTP REST endpoint when an email is opened in the context of the plugin. The REST endpiont is implemented in a golang server that runs ona cloud VM.

we observed that Gmail Scanner is a handy tool. But it has limited features since it is implemented purely in
app script. Hence with Cycle7 and Cycle9, I re-wrote the frontend/backend to a fully standalone REST based email content scanner that does
1) domain scanning with VirusTotal
2) attachment scanning with VirusTotal

This the second part of two phase project, where I have implemented the front-end(app script triggers).

# Why I'm Interested
I observed that even though Gmail has builtin phishing and spam scanning feature, it is not always filtering the 
phishing/spam emails. It made me think to research on intgrating VirusTotal like platform with Gmail and 
I came up with this tool.

# Three Main Points
* REST API based email scanning backend server that can be run cloud native/Cloud VM
* analyses the email domain and email attachment with VirusTotal
* Ability to add more features such as analysis by sandbox container in same Cloud VM, analayis using ChatGPT prompt etc.

# Pre-requisistes

The front-end requires a google-cloud project with Google Marketplace SDK having alternate deployment(go based) using the deployment json file.
This project is implemented as an internal plugin app, but in production this will be published using a developer account, hence the above mentioend setup is done only by developer account.
The backend of the tool is golang based hence uses go runtime. It can be also compiled as a static executable that won't require any dependencies.

# Further Areas of Improvement
* Add sandbox container based analysis
* Add analysis using ChatGPT prompt

# Running the tool
Backend is run from cloudVM using ./server assuming certs are configured on the VM.
Front-end is setup using a google cloud account with alnternate run time environment in Google Marketplace SDK which uses the deployment json file.

# Resources
* Go wth Gmail Workspace - https://developers.google.com/gmail/api/quickstart/go
* VirusTotal - https://www.virustotal.com/gui/home/upload
* Swagger - https://swagger.io/
