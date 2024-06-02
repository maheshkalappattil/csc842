function loadAddOn(event) {
  var accessToken = event.gmail.accessToken;
  var messageId = event.gmail.messageId;
  GmailApp.setCurrentMessageAccessToken(accessToken);

  // do regex parsing of email body for URLs
  var mailMessage = GmailApp.getMessageById(messageId);
  const domainR = /(?<=(https?|ftp?|http):\/\/(www\.?))(([a-z\d]([a-z\d-]*[a-z\d])?\.)+[a-z]{2,}|localhost)/g;
  var content= mailMessage.getBody();
  var card;
  var domains = removeDuplicates(content.match(domainR));
  var results = "";

  // check domains against VirusTotal
  if (Array.isArray(domains) && domains.length > 0 ) {
    for (i in domains) {
      var response = checkDomainInVT(domains[i]);
      result = "\ndomain: " + domains[i] + " => " + JSON.stringify(response) + "\n"
      results += result;
    }
  }

  // download attachments and check hash against VirusTotal
  var attA=GmailApp.getMessageById(messageId).getAttachments();
    attA.forEach(function(a){
      hash = a.getHash().replace(/_/g, '');
      var response = checkHashInVT(hash);
      result = "\nattachment: " + hash + " => " + JSON.stringify(response) + "\n"
      results += result;
    });
  

  card = CardService.newCardBuilder()
    .setHeader(CardService.newCardHeader().setTitle("Gmail URL Scanner"))
    .addSection(CardService.newCardSection()
        .addWidget(CardService.newTextParagraph().
        setText(results)))
    .build();
  return [card];
}

function removeDuplicates(arr) {
  if (Array.isArray(arr)) {
    return arr.filter((item,
            index) => arr.indexOf(item) === index);
  }
  return arr;
}

function checkDomainInVT(domain) {
  var options = {
    'headers':  {
      'x-apikey': 'bb03b75a86b0c35e9ac54cf6b4c91dc589b2916e08d1ee2dd5fe104d78abc697'
    }
  }
  resp =  UrlFetchApp.fetch('https://www.virustotal.com/api/v3/domains/'+domain, options).getContentText();
  var j = JSON.parse(resp);
  if (j.data.attributes.total_votes.malicious > j.data.attributes.total_votes.harmless) {
    return "malicious"
  }
  return "harmless"
}

function checkHashInVT(hash) {
  var options = {
    'headers':  {
      'x-apikey': 'bb03b75a86b0c35e9ac54cf6b4c91dc589b2916e08d1ee2dd5fe104d78abc697'
    }
  }
  resp =  UrlFetchApp.fetch('https://www.virustotal.com/api/v3/files/'+hash, options).getContentText();
  var j = JSON.parse(resp);
  if (j.data.attributes.total_votes.malicious > j.data.attributes.total_votes.harmless) {
    return "malicious"
  }
  return "harmless"
}


