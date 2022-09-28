var result = {};
//---------------------- 1.  IP Address  ----------------------
var url = window.location.href;
var urlDomain = window.location.hostname;
var patt = /(25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[0-9]?[0-9])(\.|$){4}/;
var patt2 = /(0x([0-9][0-9]|[A-F][A-F]|[A-F][0-9]|[0-9][A-F]))(\.|$){4}/;
var ip = /\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/;

if(ip.test(urlDomain)||patt.test(urlDomain)||patt2.test(urlDomain)){ 
    result["IP address"]="1";
}else{
    result["IP address"]="-1";
}

//---------------------- 2.  URL Length  ----------------------
if(url.length<54){
    result["URL length"]="-1";
}else if(url.length>=54&&url.length<=100){
    result["URL length"]="0";
}else{
    result["URL length"]="1";
}

//---------------------- 3.  Tiny URL  ----------------------
var onlyDomain = urlDomain.replace('www.','');

if(onlyDomain.length<7){
    result["shortener"]="1";
}else{
    result["shortener"]="-1";
}

//---------------------- 4.  @ Symbol  ----------------------
patt=/@/;
if(patt.test(url)){ 
    result["symbols"]="1";
}else{
    result["symbols"]="-1";
}

//---------------------- 5.  Redirecting using //  ----------------------
if(url.lastIndexOf("//")>7){
    result["redirects"]="1";
}else{
    result["redirects"]="-1";
}

//---------------------- 6. (-) Prefix/Suffix in domain  ----------------------
patt=/-/;
if(patt.test(urlDomain)){ 
    result["prefix/suffix"]="1";
}else{
    result["prefix/suffix"]="-1";
}

//---------------------- 7.  No. of Sub Domains  ----------------------
if((onlyDomain.match(RegExp('\\.','g'))||[]).length==1){ 
    result["subdomains"]="-1";
}else if((onlyDomain.match(RegExp('\\.','g'))||[]).length==2){ 
    result["subdomains"]="0";    
}else{
    result["Nsubdomains"]="1";
}

//---------------------- 8.  HTTPS  ----------------------
patt=/https:\/\//;
if(patt.test(url)){
    result["HTTPS"]="-1";
}else{
    result["HTTPS"]="1";
}

//---------------------- 9.  Domain Registration Length  ----------------------

//---------------------- 10. Favicon  ----------------------
var favicon = undefined;
var nodeList = document.getElementsByTagName("link");
for (var i = 0; i < nodeList.length; i++)
{
    if((nodeList[i].getAttribute("rel") == "icon")||(nodeList[i].getAttribute("rel") == "shortcut icon"))
    {
        favicon = nodeList[i].getAttribute("href");
    }
}
if(!favicon) {
    result["favicon"]="-1";
} else if (favicon.length==12){
    result["favicon"]="-1";
} else {
    patt=RegExp(urlDomain,'g');
    if(patt.test(favicon)){
        result["favicon"]="-1";
    } else{
        result["favicon"]="1";
    }
}

//---------------------- 11. Using Non-Standard Port  ----------------------
const port = window.location.port;
if (port){
    result["port"]="-1";
} else{
    result["port"]="-1";
}


//---------------------- 12.  HTTPS in URL's domain part  ----------------------
patt=/https/;
if(patt.test(onlyDomain)){
    result["tokens"]="1";
}else{
    result["tokens"]="-1";
}

//---------------------- 13.  Request URL  ----------------------
var imgTags = document.getElementsByTagName("img");
var phishCount=0;
var legitCount=0;
patt=RegExp(onlyDomain,'g');

for(var i = 0; i < imgTags.length; i++){
    var src = imgTags[i].getAttribute("src");
    if(!src) continue;
    if(patt.test(src)){
        legitCount++;
    }else if(src.charAt(0)=='/'&&src.charAt(1)!='/'){
        legitCount++;
    }else{
        phishCount++;
    }
}
var totalCount=phishCount+legitCount;
var outRequest=(phishCount/totalCount)*100;

if(outRequest<22){
    result["x-requests"]="-1";
}else if(outRequest>=22&&outRequest<61){
    result["x-requests"]="0";
}else{
    result["x-requests"]="1";
}

//---------------------- 14.  URL of Anchor  ----------------------
var aTags = document.getElementsByTagName("a");
phishCount=0;
legitCount=0;
var allhrefs="";

for(var i = 0; i < aTags.length; i++){
    var hrefs = aTags[i].getAttribute("href");
    if(!hrefs) continue;
    allhrefs+=hrefs+"       ";
    if(patt.test(hrefs)){
        legitCount++;
    }else if(hrefs.charAt(0)=='#'||(hrefs.charAt(0)=='/'&&hrefs.charAt(1)!='/')){
        legitCount++;
    }else{
        phishCount++;
    }
}
totalCount=phishCount+legitCount;
outRequest=(phishCount/totalCount)*100;

if(outRequest<31){
    result["anchors"]="-1";
}else if(outRequest>=31&&outRequest<=67){
    result["anchors"]="0";
}else{
    result["anchors"]="1";
}

//---------------------- 15. Links in script and link  ----------------------
var mTags = document.getElementsByTagName("meta");
var sTags = document.getElementsByTagName("script");
var lTags = document.getElementsByTagName("link");
phishCount=0;
legitCount=0;
allhrefs="sTags  ";

for(var i = 0; i < sTags.length; i++){
    var sTag = sTags[i].getAttribute("src");
    if(sTag!=null){
        allhrefs+=sTag+"      ";
        if(patt.test(sTag)){
            legitCount++;
        }else if(sTag.charAt(0)=='/'&&sTag.charAt(1)!='/'){
            legitCount++;
        }else{
            phishCount++;
        }
    }
}

allhrefs+="      lTags   ";
for(var i = 0; i < lTags.length; i++){
    var lTag = lTags[i].getAttribute("href");
    if(!lTag) continue;
    allhrefs+=lTag+"       ";
    if(patt.test(lTag)){
        legitCount++;
    }else if(lTag.charAt(0)=='/'&&lTag.charAt(1)!='/'){
        legitCount++;
    }else{
        phishCount++;
    }
}

totalCount=phishCount+legitCount;
outRequest=(phishCount/totalCount)*100;

if(outRequest<17){
    result["meta"]="-1";
}else if(outRequest>=17&&outRequest<=81){
    result["meta"]="0";
}else{
    result["meta"]="1";
}

//---------------------- 16.Server Form Handler ----------------------
var forms = document.getElementsByTagName("form");
var res = "-1";

for(var i = 0; i < forms.length; i++) {
    var action = forms[i].getAttribute("action");
    if(!action || action == "") {
        res = "1";
        break;
    } else if(!(action.charAt(0)=="/" || patt.test(action))) {
        res = "0";
    }
}
result["forms"] = res;

//---------------------- 17.Submitting to mail ----------------------
var forms = document.getElementsByTagName("form");
var res = "-1";

for(var i = 0; i < forms.length; i++) {
    var action = forms[i].getAttribute("action");
    if(!action) continue;
    if(action.startsWith("mailto")) {
        res = "1";
        break;
    }
}
result["mailto"] = res;

//---------------------- 18.Using iFrame ----------------------
var iframes = document.getElementsByTagName("iframe");

if(iframes.length == 0) {
    result["iframes"] = "-1";
} else {
    result["iframes"] = "1";
}

//---------------------- Sending the result  ----------------------
chrome.runtime.sendMessage(result, function(response) {
    //console.log(result);
});

chrome.runtime.onMessage.addListener(
    function(request, sender, sendResponse) {
   
      if (request.action == "alert_user"){
        const body = document.body;
        const div = document.createElement('div');
        div.style.position = 'absolute';
        div.style.display = 'inline-flex';
        div.style.top = '10px';
        div.style.right = '10px';
        div.style.width = '350px';
        div.style.height = '85px';
        div.style.backgroundColor = 'white';
        div.style.color = 'black';
        div.style.padding = '10px';
        div.style.borderRadius = '10px';
        div.style.zIndex = '100000000000';
        div.style.visibility = 'hidden';
        div.style["boxShadow"] = "5px 5px 10px #999999";

        const p = document.createElement('p');
        p.style.paddingLeft = '9px';
        p.style.paddingTop = '8px';
        p.style.fontFamily = 'Calibri';
        p.style.fontSize = '18px';
        p.style.fontStyle = 'normal';
        p.style.fontWeight = 'normal';
        p.textContent = 'This website looks suspicious! \n Proceede with caution!';

        let svg = `
        <svg id="Layer_1" style="enable-background:new 0 0 40 40;" version="1.1" viewBox="0 0 40 40" xml:space="preserve" xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink"><style type="text/css">
        .st0{fill:#00BBFF;}
        .st1{fill:none;stroke:#000000;stroke-width:2;stroke-linecap:round;stroke-linejoin:round;stroke-miterlimit:10;}
        .st2{fill:none;stroke:#000000;stroke-width:2;stroke-linecap:round;stroke-miterlimit:10;}
        .st3{stroke:#000000;stroke-miterlimit:10;}
        .st4{fill:none;stroke:#000000;stroke-width:2.1024;stroke-linecap:round;stroke-linejoin:round;stroke-miterlimit:10;}
        .st5{fill:none;stroke:#000000;stroke-width:2.138;stroke-linecap:round;stroke-linejoin:round;stroke-miterlimit:10;}
        .st6{fill:none;stroke:#000000;stroke-width:1.8257;stroke-linecap:round;stroke-linejoin:round;stroke-miterlimit:10;}
        .st7{fill:none;stroke:#000000;stroke-width:2.3094;stroke-linecap:round;stroke-linejoin:round;stroke-miterlimit:10;}
        .st8{fill:none;stroke:#000000;stroke-width:1.9272;stroke-linecap:round;stroke-linejoin:round;stroke-miterlimit:10;}
        </style><path class="st0" d="M30,10.8c0.2,0.6,0.2,1.3,0,2l-5.1,15.8c-0.3,1.1-1.1,1.9-2.1,2.2L22,30l-4-12l11-7L30,10.8z"/>
        <path class="st4" d="M22.7,30.8c-0.6,0.2-1.2,0.2-1.8,0L5.7,26c-1.6-0.5-2.4-2.3-1.8-4.1L9,6c0.6-1.7,2.3-2.7,3.9-2.2l15.2,4.9  c1,0.3,1.6,1.1,1.9,2.1c0.2,0.6,0.2,1.3,0,2l-5.1,15.8C24.5,29.7,23.7,30.5,22.7,30.8z"/>
        <polyline class="st5" points="22,30 18,18 29,11 "/><path class="st1" d="M12,11v1c0,1.7,1.3,3,3,3h0c1.7,0,3-1.3,3-3V9l-1.4,1.1"/>
        <line class="st1" x1="12" x2="12" y1="1" y2="3"/></svg>
        `;

        let blob = new Blob([svg], {type: 'image/svg+xml'});
        let url = URL.createObjectURL(blob);
        let image = document.createElement('img');
        image.src = url;
        image.addEventListener('load', () => URL.revokeObjectURL(url), {once: true});
        image.width = 60;
        image.style.paddingLeft = '10px';
        image.style.paddingTop = '7px';

        div.appendChild(image);
        div.appendChild(p);
        body.appendChild(div);

        div.style.visibility = 'visible';
        $(div).fadeIn();

        setTimeout(function() {
           $(div).fadeOut();
        }, 4000);
    }
    return true;
});