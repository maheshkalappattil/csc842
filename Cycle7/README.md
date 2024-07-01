# Gmail Scanner Backend

A Cloud based backend to scan and analyze Gmail contents. This is an alternative and comprehensive approach to scanning
Gmail(that was implemented using app script in Cycle3) where the app script routes the trigger to Cloud based backend
which does the analysis.

# DESCRIPTION
In Cycle3 we observed that Gmail Scanner is a handy tool. But it has limited features since it is implemented purely in
app script. Hence in Cycle7, I re-wrote the backend to a fully standalone REST based email content scanner that does
1) domain scanning with VirusTotal
2) attachment scanning with VirusTotal

This is a two phase project. In the next phase, I will implement the front-end(app script triggers) and also planning
to add a sandbox container which can use OLE tools to extact macros from attachment(if any) and interpret using ChatGPT
prompt.

# Why I'm Interested
I observed that even though Gmail has builtin phishing and spam scanning feature, it is not always filtering the 
phishing/spam emails. It made me think to research on intgrating VirusTotal like platform with Gmail and 
I came up with this tool.

# Three Main Points
* REST API based email scanning backend server that can be run cloud native/Cloud VM
* analyses the email domain and email attachment with VirusTotal
* Ability to add more features such as analysis by sandbox container in same Cloud VM, analayis using ChatGPT prompt etc.

# Pre-requisistes

This tool is golang based hence uses go runtime. It can be also compiled as a static executable that won't require any dependencies

# Further Areas of Improvement
* Add front end trigger from Gmail using app script
* Add sandbox container based analysis
* Add analysis using ChatGPT prompt

# Running the tool
./server

# Resources
* Go wth Gmail Workspace - https://developers.google.com/gmail/api/quickstart/go
* VirusTotal - https://www.virustotal.com/gui/home/upload
* Swagger - https://swagger.io/
